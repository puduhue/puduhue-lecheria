/*
  Puduhue Lechería · servidor (Cloudflare Worker)
  ------------------------------------------------
  Recibe los check lists de sala de ordeña desde los teléfonos (sin cuenta Microsoft),
  valida la clave de la sala que viene en el QR y guarda registros y fotos en OneDrive.

  Además atiende el panel de administración (/api/admin/*): ahí la persona entra con su cuenta
  Microsoft de Puduhue, el servidor verifica con Microsoft quién es y revisa la lista de autorizados
  (_datos/acceso.json) antes de entregar cualquier dato.

  Seguridad:
  - El servidor se identifica ante Microsoft con un certificado (la directiva del tenant bloquea secretos).
  - Solo escribe dentro de BASE_PATH (carpeta "Check list ordeña"). Todas las rutas se arman aquí,
    nunca a partir de texto libre enviado por el teléfono.
  - Cada clave de sala solo permite leer y escribir los registros de esa sala.

  Configuración en Cloudflare (Settings → Variables and Secrets):
    PRIVATE_KEY   (Secret)  contenido completo del archivo servidor_privada.pem
  Todo lo demás tiene valores por defecto abajo y no es secreto.
*/

const DEF = {
  TENANT_ID: "8812d491-c151-4cf4-ad03-7671f57a4a23",
  CLIENT_ID: "95876a8d-3c6c-41ae-963f-1388d2bce484",
  CERT_X5T: "PdFIc6TwVH8_pkko2Bx7YDLt2OE",
  DRIVE_USER: "achavez@puduhue.cl",
  BASE_PATH: "Documentos/Puduhue/PUDUHUE OFICIAL/Adm y Finanzas/08 - IT/Apps de terreno/Check list ordeña",
  ALLOWED_ORIGINS: "https://puduhue.github.io",
};

const ITEMS = { A: 12, B: 8 };
const ALL_KEYS = Object.entries(ITEMS).flatMap(([s, n]) => Array.from({ length: n }, (_, i) => s + (i + 1)));
const MAX_FOTO = 1_500_000;
const MAX_JSON = 60_000;

let tokenCache = null;
let salasCache = null;
let accesoCache = null;
const usuariosCache = new Map();

const cfg = (env, k) => (env && env[k]) || DEF[k];

/* ---------- utilidades ---------- */
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlStr = s => b64url(new TextEncoder().encode(s));
const encPath = p => p.split("/").map(encodeURIComponent).join("/");
const limpiar = (s, n) => String(s ?? "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n);
const nombreCarpeta = s => limpiar(s, 60).replace(/[\\/:*?"<>|#%]/g, "-") || "Sala";

function hoyChile() {
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Santiago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  return p; // YYYY-MM-DD
}
function difDias(a, b) { return Math.round((Date.parse(a + "T12:00:00Z") - Date.parse(b + "T12:00:00Z")) / 86400000); }

function cors(req, env) {
  const origin = req.headers.get("Origin") || "";
  const ok = cfg(env, "ALLOWED_ORIGINS").split(",").map(s => s.trim()).includes(origin);
  return {
    "Access-Control-Allow-Origin": ok ? origin : "null",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
const json = (obj, status, h) => new Response(JSON.stringify(obj), { status, headers: { ...h, "Content-Type": "application/json; charset=utf-8" } });

/* ---------- Microsoft Graph ---------- */
async function importKey(pem) {
  const b = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b), c => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
async function getToken(env) {
  if (tokenCache && tokenCache.exp > Date.now() + 120000) return tokenCache.t;
  const tenant = cfg(env, "TENANT_ID"), client = cfg(env, "CLIENT_ID");
  const aud = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const now = Math.floor(Date.now() / 1000);
  const head = b64urlStr(JSON.stringify({ alg: "RS256", typ: "JWT", x5t: cfg(env, "CERT_X5T") }));
  const body = b64urlStr(JSON.stringify({ aud, iss: client, sub: client, jti: crypto.randomUUID(), nbf: now, exp: now + 600 }));
  const key = await importKey(env.PRIVATE_KEY);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + body));
  const form = new URLSearchParams({
    client_id: client, scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: head + "." + body + "." + b64url(sig),
  });
  const r = await fetch(aud, { method: "POST", body: form });
  if (!r.ok) throw new Error("token " + r.status + " " + (await r.text()).slice(0, 200));
  const j = await r.json();
  tokenCache = { t: j.access_token, exp: Date.now() + j.expires_in * 1000 };
  return tokenCache.t;
}
function itemUrl(env, rel) {
  return `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(cfg(env, "DRIVE_USER"))}/drive/root:/${encPath(cfg(env, "BASE_PATH") + "/" + rel)}:`;
}
async function gGet(env, rel) {
  const r = await fetch(itemUrl(env, rel) + "/content", { headers: { Authorization: "Bearer " + (await getToken(env)) } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("get " + r.status);
  return r;
}
async function gPut(env, rel, body, type, etag) {
  const headers = { Authorization: "Bearer " + (await getToken(env)), "Content-Type": type };
  if (etag) headers["If-Match"] = etag;
  const r = await fetch(itemUrl(env, rel) + "/content" + (etag === null ? "?@microsoft.graph.conflictBehavior=fail" : ""), { method: "PUT", body, headers });
  if (r.status === 412 || r.status === 409) { const e = new Error("conflicto"); e.conflicto = true; throw e; }
  if (!r.ok) throw new Error("put " + r.status + " " + (await r.text()).slice(0, 200));
  return r.json();
}
/* Lee un JSON con su eTag, para escribirlo de vuelta sin pisar cambios de otro envío simultáneo. */
async function gGetJson(env, rel) {
  const tk = "Bearer " + (await getToken(env));
  const m = await fetch(itemUrl(env, rel) + "?$select=eTag,size", { headers: { Authorization: tk } });
  if (m.status === 404) return { data: null, etag: null };
  if (!m.ok) throw new Error("meta " + m.status);
  const { eTag } = await m.json();
  const r = await fetch(itemUrl(env, rel) + "/content", { headers: { Authorization: tk } });
  if (r.status === 404) return { data: null, etag: null };
  if (!r.ok) throw new Error("get " + r.status);
  return { data: await r.json(), etag: eTag };
}
/* Lee, modifica y guarda; si otro envío escribió entre medio, reintenta. */
async function actualizarJson(env, rel, fn) {
  for (let i = 0; i < 4; i++) {
    const { data, etag } = await gGetJson(env, rel);
    const nuevo = await fn(data);
    try { await gPut(env, rel, JSON.stringify(nuevo, null, 1), "application/json", etag); return nuevo; }
    catch (e) { if (!e.conflicto) throw e; await new Promise(r => setTimeout(r, 150 + Math.random() * 400)); }
  }
  throw new Error("No se pudo guardar por cambios simultáneos. Intenta de nuevo.");
}

/* ---------- salas ---------- */
async function todasSalas(env) {
  if (!salasCache || salasCache.exp < Date.now()) {
    const r = await gGet(env, "_datos/salas.json");
    const j = r ? await r.json() : { salas: [] };
    salasCache = { salas: j.salas || [], exp: Date.now() + 60000 };
  }
  return salasCache.salas;
}
async function salaPorClave(env, k) {
  if (!k || k.length < 10 || k.length > 64) return null;
  return (await todasSalas(env)).find(s => s.activa !== false && s.clave === k) || null;
}
/* Un archivo por sala y mes con todos sus check lists: { registros: { "AAAA-MM-DD_AM": {...} } } */
const rutaMes = (salaId, mes) => `_datos/registros/${salaId}/${mes}.json`;
const carpetaFotos = (sala, fecha) => `${nombreCarpeta(sala.nombre)}/${fecha.slice(0, 7)}/Fotos`;

function validarFechaTurno(fecha, turno) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha || "")) return "Fecha inválida.";
  if (!["AM", "PM"].includes(turno)) return "Turno inválido.";
  const d = difDias(fecha, hoyChile());
  if (d > 1 || d < -7) return "La fecha debe estar entre los últimos 7 días y hoy.";
  return null;
}

/* ---------- reglas de edición ----------
   Una parte enviada solo la puede modificar el mismo teléfono y solo el mismo día.
   Fuera de eso queda cerrada, salvo que un administrador la habilite para corregir (24 horas). */
const desbloqueada = (r, S) => { const d = r?.desbloqueo?.[S]; return !!d && Date.parse(d.hasta) > Date.now(); };
function motivoBloqueo(r, S, dispositivo, fecha) {
  const p = r?.partes?.[S];
  if (!p || desbloqueada(r, S)) return null;
  if (!dispositivo || p.dispositivo !== dispositivo) return { error: "bloqueado", mensaje: `Esta parte ya la envió ${p.completadoPor || "otra persona"}${p.horaRegistro ? " a las " + p.horaRegistro : ""} desde otro teléfono. Solo esa persona puede modificarla.` };
  if (fecha !== hoyChile()) return { error: "cerrado", mensaje: "Este check list es de un día anterior y ya está cerrado. Si hay que corregir algo, pídelo a la administración." };
  return null;
}
function vistaOrdenador(r, dispositivo) {
  if (!r) return null;
  const partes = {};
  for (const [S, p] of Object.entries(r.partes || {})) partes[S] = { completadoPor: p.completadoPor, horaRegistro: p.horaRegistro, actualizadoEn: p.actualizadoEn, ediciones: p.ediciones || 0, esTuyo: !!dispositivo && p.dispositivo === dispositivo, desbloqueada: desbloqueada(r, S) };
  return { id: r.id, fecha: r.fecha, turno: r.turno, administrador: r.administrador, partes, items: r.items, estado: r.estado, estadoPartes: r.estadoPartes };
}

/* ---------- panel de administración ---------- */
const ROLES = ["admin", "sup", "enc"];
const mesesEntre = (desde, hasta) => { const out = []; let [y, m] = desde.split("-").map(Number); const [yh, mh] = hasta.split("-").map(Number);
  while (y < yh || (y === yh && m <= mh)) { out.push(`${y}-${String(m).padStart(2, "0")}`); m++; if (m > 12) { m = 1; y++; } if (out.length > 24) break; } return out; };
async function acceso(env) {
  if (!accesoCache || accesoCache.exp < Date.now()) {
    const r = await gGet(env, "_datos/acceso.json");
    const j = r ? await r.json() : { personas: [] };
    accesoCache = { personas: j.personas || [], exp: Date.now() + 30000 };
  }
  return accesoCache.personas;
}
/* Quién está entrando: Microsoft confirma la identidad del token y luego se revisa la lista de autorizados. */
async function usuarioPanel(req, env) {
  const auth = req.headers.get("Authorization") || "";
  const tok = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (env.SOLO_PRUEBAS_USUARIO && tok === "prueba") return { correo: env.SOLO_PRUEBAS_USUARIO };
  if (!tok || tok.length < 100) return null;
  const hit = usuariosCache.get(tok);
  if (hit && hit.exp > Date.now()) return hit.u;
  const r = await fetch("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,userPrincipalName", { headers: { Authorization: "Bearer " + tok } });
  if (!r.ok) return null;
  const me = await r.json();
  const u = { correo: String(me.mail || me.userPrincipalName || "").toLowerCase(), nombre: me.displayName || "" };
  if (usuariosCache.size > 200) usuariosCache.clear();
  usuariosCache.set(tok, { u, exp: Date.now() + 5 * 60000 });
  return u;
}
async function handleAdmin(req, env, h, url, path) {
  const quien = await usuarioPanel(req, env);
  if (!quien) return json({ error: "sesion", mensaje: "Tu sesión no es válida o venció. Vuelve a iniciar sesión." }, 401, h);
  const p = quien.correo.endsWith("@puduhue.cl") ? (await acceso(env)).find(x => x.correo === quien.correo) : null;
  if (!p) return json({ error: "sin_acceso", correo: quien.correo, mensaje: "Esta cuenta no está en la lista de personas autorizadas." }, 403, h);
  const yo = { nombre: p.nombre || quien.nombre, correo: p.correo, rol: p.rol, salas: p.salas || [] };
  const esAdmin = yo.rol === "admin";
  const salas = await todasSalas(env);
  const visibles = salas.filter(s => s.activa !== false && (yo.rol !== "enc" || yo.salas.includes(s.id)));
  const pub = s => ({ id: s.id, nombre: s.nombre, predio: s.predio || "", activa: s.activa !== false, desde: s.desde || "", ...(esAdmin ? { clave: s.clave } : {}) });

  if (req.method === "GET" && path === "/api/admin/yo") return json({ yo, salas: (esAdmin ? salas : visibles).map(pub), hoy: hoyChile() }, 200, h);

  if (req.method === "GET" && path === "/api/admin/registros") {
    const meses = (url.searchParams.get("meses") || "").split(",").filter(m => /^\d{4}-\d{2}$/.test(m)).slice(0, 3);
    if (!meses.length) return json({ error: "datos", mensaje: "Indica los meses." }, 400, h);
    // Se devuelven los archivos tal cual, sin procesarlos, para no gastar tiempo de servidor.
    const partes = await Promise.all(visibles.flatMap(s => meses.map(async m => { const r = await gGet(env, rutaMes(s.id, m)); return r ? await r.text() : null; })));
    const body = `{"meses":${JSON.stringify(meses)},"archivos":[${partes.filter(Boolean).join(",")}]}`;
    return new Response(body, { status: 200, headers: { ...h, "Content-Type": "application/json; charset=utf-8" } });
  }

  if (req.method === "GET" && path === "/api/admin/foto") {
    const ruta = url.searchParams.get("ruta") || "";
    if (ruta.includes("..") || !/\.jpg$/.test(ruta) || !visibles.some(s => ruta.startsWith(nombreCarpeta(s.nombre) + "/"))) return json({ error: "ruta" }, 400, h);
    const r = await gGet(env, ruta);
    if (!r) return json({ error: "no existe" }, 404, h);
    return new Response(r.body, { headers: { ...h, "Content-Type": "image/jpeg", "Cache-Control": "private, max-age=86400" } });
  }

  if (req.method === "POST" && path === "/api/admin/hallazgo") {
    let d; try { d = await req.json(); } catch { return json({ error: "datos" }, 400, h); }
    const sala = visibles.find(s => s.id === d.salaId);
    if (!sala) return json({ error: "permiso", mensaje: "No tienes acceso a esa sala." }, 403, h);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d.fecha || "") || !["AM", "PM"].includes(d.turno) || !ALL_KEYS.includes(d.item)) return json({ error: "datos", mensaje: "Datos inválidos." }, 400, h);
    const nota = limpiar(d.nota, 1000);
    if (!nota) return json({ error: "datos", mensaje: "Escribe qué se hizo para solucionarlo." }, 400, h);
    let seg;
    await actualizarJson(env, rutaMes(sala.id, d.fecha.slice(0, 7)), m => {
      const r = m?.registros?.[`${d.fecha}_${d.turno}`];
      if (!r || r.items?.[d.item]?.estado !== "NC") { const e = new Error("El hallazgo ya no existe."); e.status = 404; throw e; }
      seg = { estado: "cerrado", nota, por: yo.nombre, correo: yo.correo, en: hoyChile(), enHora: new Date().toISOString() };
      r.seguimiento = r.seguimiento || {}; r.seguimiento[d.item] = seg; return m;
    });
    return json({ ok: true, seguimiento: seg }, 200, h);
  }

  if (!esAdmin) return json({ error: "permiso", mensaje: "Solo un administrador puede hacer esto." }, 403, h);

  if (req.method === "POST" && path === "/api/admin/desbloquear") {
    let d; try { d = await req.json(); } catch { return json({ error: "datos" }, 400, h); }
    const sala = salas.find(s => s.id === d.salaId);
    if (!sala || !/^\d{4}-\d{2}-\d{2}$/.test(d.fecha || "") || !["AM", "PM"].includes(d.turno) || !["A", "B"].includes(d.parte)) return json({ error: "datos", mensaje: "Datos inválidos." }, 400, h);
    const motivo = limpiar(d.motivo, 300);
    if (!motivo) return json({ error: "datos", mensaje: "Indica el motivo de la corrección." }, 400, h);
    let des;
    await actualizarJson(env, rutaMes(sala.id, d.fecha.slice(0, 7)), m => {
      const r = m?.registros?.[`${d.fecha}_${d.turno}`];
      if (!r?.partes?.[d.parte]) { const e = new Error("Esa parte no se ha enviado."); e.status = 404; throw e; }
      des = { hasta: new Date(Date.now() + 24 * 3600000).toISOString(), por: yo.nombre, correo: yo.correo, motivo, en: new Date().toISOString() };
      r.desbloqueo = r.desbloqueo || {}; r.desbloqueo[d.parte] = des;
      r.correcciones = (r.correcciones || []).concat([{ parte: d.parte, ...des }]);
      return m;
    });
    return json({ ok: true, desbloqueo: des }, 200, h);
  }

  if (req.method === "POST" && path === "/api/admin/salas") {
    let d; try { d = await req.json(); } catch { return json({ error: "datos" }, 400, h); }
    const clave = () => { const b = crypto.getRandomValues(new Uint8Array(12)); return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
    const nuevo = await actualizarJson(env, "_datos/salas.json", j => {
      j = j || { salas: [] };
      if (d.accion === "agregar") {
        const nombre = limpiar(d.nombre, 40);
        const id = "s-" + nombre.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "");
        if (!nombre || id === "s-") { const e = new Error("Nombre inválido."); e.status = 400; throw e; }
        if (j.salas.some(s => s.id === id)) { const e = new Error("Ya existe una sala con ese nombre."); e.status = 400; throw e; }
        j.salas.push({ id, nombre, predio: "", clave: clave(), desde: hoyChile(), activa: true });
      } else if (d.accion === "reemplazar") {
        const s = j.salas.find(x => x.id === d.salaId); if (!s) { const e = new Error("Sala no encontrada."); e.status = 404; throw e; }
        s.clave = clave(); s.desde = hoyChile();
      } else { const e = new Error("Acción inválida."); e.status = 400; throw e; }
      j.actualizado = new Date().toISOString(); return j;
    });
    salasCache = null;
    return json({ ok: true, salas: nuevo.salas.map(pub) }, 200, h);
  }

  if (req.method === "GET" && path === "/api/admin/personas") return json({ personas: await acceso(env) }, 200, h);

  if (req.method === "PUT" && path === "/api/admin/personas") {
    let d; try { d = await req.json(); } catch { return json({ error: "datos" }, 400, h); }
    const lista = [];
    for (const x of Array.isArray(d.personas) ? d.personas : []) {
      const correo = limpiar(x.correo, 120).toLowerCase(), nombre = limpiar(x.nombre, 80);
      if (!/^[^@\s]+@puduhue\.cl$/.test(correo) || !nombre || !ROLES.includes(x.rol)) return json({ error: "datos", mensaje: "Revisa los datos de " + (nombre || correo || "una persona") + "." }, 400, h);
      if (lista.some(y => y.correo === correo)) return json({ error: "datos", mensaje: correo + " está repetido." }, 400, h);
      lista.push({ nombre, correo, rol: x.rol, ...(x.rol === "enc" ? { salas: (x.salas || []).filter(id => salas.some(s => s.id === id)) } : {}) });
    }
    if (!lista.some(y => y.correo === yo.correo && y.rol === "admin")) return json({ error: "datos", mensaje: "No puedes quitarte a ti mismo el acceso de administrador." }, 400, h);
    await actualizarJson(env, "_datos/acceso.json", () => ({ personas: lista, actualizado: new Date().toISOString(), por: yo.correo }));
    accesoCache = null;
    return json({ ok: true, personas: lista }, 200, h);
  }

  return json({ error: "ruta" }, 404, h);
}

/* ---------- rutas ---------- */
async function handle(req, env, h) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  if (path.startsWith("/api/admin/")) return handleAdmin(req, env, h, url, path);
  const sala = await salaPorClave(env, url.searchParams.get("k"));
  if (path === "/api/ping") return json({ ok: true, hoy: hoyChile() }, 200, h);
  if (!sala) return json({ error: "clave", mensaje: "El código QR de la sala no es válido o fue reemplazado. Pide uno nuevo a la administración." }, 403, h);
  const publica = { id: sala.id, nombre: sala.nombre, predio: sala.predio || "" };

  if (req.method === "GET" && path === "/api/sala") return json({ sala: publica, hoy: hoyChile() }, 200, h);

  if (req.method === "GET" && path === "/api/registro") {
    const fecha = url.searchParams.get("fecha"), turno = url.searchParams.get("turno");
    const e = validarFechaTurno(fecha, turno); if (e) return json({ error: "datos", mensaje: e }, 400, h);
    const r = await gGet(env, rutaMes(sala.id, fecha.slice(0, 7)));
    const m = r ? await r.json() : null;
    return json({ registro: vistaOrdenador(m?.registros?.[`${fecha}_${turno}`], url.searchParams.get("dispositivo")), hoy: hoyChile() }, 200, h);
  }

  if (req.method === "GET" && path === "/api/foto") {
    const ruta = url.searchParams.get("ruta") || "";
    const pre = nombreCarpeta(sala.nombre) + "/";
    if (!ruta.startsWith(pre) || ruta.includes("..") || !/\.jpg$/.test(ruta)) return json({ error: "ruta" }, 400, h);
    const r = await gGet(env, ruta);
    if (!r) return json({ error: "no existe" }, 404, h);
    return new Response(r.body, { headers: { ...h, "Content-Type": "image/jpeg", "Cache-Control": "private, max-age=86400" } });
  }

  if (req.method === "POST" && path === "/api/foto") {
    const fecha = url.searchParams.get("fecha"), turno = url.searchParams.get("turno");
    const item = url.searchParams.get("item"), id = url.searchParams.get("id") || "";
    const e = validarFechaTurno(fecha, turno); if (e) return json({ error: "datos", mensaje: e }, 400, h);
    if (!ALL_KEYS.includes(item) || !/^[a-z0-9]{6,24}$/.test(id)) return json({ error: "datos", mensaje: "Foto inválida." }, 400, h);
    const buf = await req.arrayBuffer();
    const u8 = new Uint8Array(buf.slice(0, 3));
    if (buf.byteLength > MAX_FOTO || buf.byteLength < 1000 || u8[0] !== 0xFF || u8[1] !== 0xD8) return json({ error: "datos", mensaje: "La foto no es válida o es muy grande." }, 400, h);
    const ruta = `${carpetaFotos(sala, fecha)}/${fecha}_${turno}_${item}_${id}.jpg`;
    await gPut(env, ruta, buf, "image/jpeg");
    return json({ ok: true, ruta }, 200, h);
  }

  if (req.method === "POST" && path === "/api/registro") {
    const txt = await req.text();
    if (txt.length > MAX_JSON) return json({ error: "datos", mensaje: "Registro demasiado grande." }, 400, h);
    let d; try { d = JSON.parse(txt); } catch { return json({ error: "datos", mensaje: "Formato inválido." }, 400, h); }
    const e = validarFechaTurno(d.fecha, d.turno); if (e) return json({ error: "datos", mensaje: e }, 400, h);
    const parte = d.parte;
    if (!["A", "B"].includes(parte)) return json({ error: "datos", mensaje: "Parte inválida." }, 400, h);
    const nuevos = {};
    const fotoPre = carpetaFotos(sala, d.fecha) + "/";
    for (const k of ALL_KEYS.filter(k => k[0] === parte)) {
      const it = d.items?.[k]; if (!it) continue;
      if (!["C", "NC", "NA"].includes(it.estado)) return json({ error: "datos", mensaje: "Estado inválido en " + k }, 400, h);
      const o = { estado: it.estado, obs: limpiar(it.obs, 1000) };
      if (it.foto) {
        if (typeof it.foto !== "string" || !it.foto.startsWith(fotoPre) || it.foto.includes("..")) return json({ error: "datos", mensaje: "Foto inválida en " + k }, 400, h);
        o.foto = it.foto;
      }
      nuevos[k] = o;
    }
    let doc;
    await actualizarJson(env, rutaMes(sala.id, d.fecha.slice(0, 7)), mesDoc => {
    mesDoc = mesDoc || { salaId: sala.id, mes: d.fecha.slice(0, 7), registros: {} };
    const prev = mesDoc.registros[`${d.fecha}_${d.turno}`] || null;
    const bl = motivoBloqueo(prev, parte, limpiar(d.dispositivo, 40), d.fecha);
    if (bl) { const e = new Error(bl.mensaje); e.status = 409; e.code = bl.error; throw e; }
    const ahora = new Date().toISOString();
    // Cada parte (A = antes, B = después) se guarda por separado: se conserva la otra parte tal como estaba.
    const items = {};
    for (const [k, it] of Object.entries(prev?.items || {})) if (k[0] !== parte && ALL_KEYS.includes(k)) items[k] = it;
    Object.assign(items, nuevos);
    const partes = { ...(prev?.partes || {}) };
    // Historial: antes de reemplazar una parte se guarda la versión anterior, para que nada se pierda.
    const historial = (prev?.historial || []).slice(-30);
    if (prev?.partes?.[parte]) {
      const pp = prev.partes[parte];
      historial.push({ parte, guardadoEn: pp.actualizadoEn, completadoPor: pp.completadoPor, horaRegistro: pp.horaRegistro, dispositivo: pp.dispositivo,
        items: Object.fromEntries(Object.entries(prev.items || {}).filter(([k]) => k[0] === parte)) });
    }
    partes[parte] = {
      completadoPor: limpiar(d.completadoPor, 80),
      horaRegistro: /^\d{2}:\d{2}$/.test(d.horaRegistro || "") ? d.horaRegistro : "",
      actualizadoEn: ahora, dispositivo: limpiar(d.dispositivo, 40),
      ediciones: (prev?.partes?.[parte]?.ediciones ?? -1) + 1,
    };
    doc = {
      id: `${sala.id}_${d.fecha}_${d.turno}`,
      salaId: sala.id, sala: sala.nombre, predio: sala.predio || "",
      fecha: d.fecha, turno: d.turno,
      area: limpiar(d.area, 60) || prev?.area || "",
      administrador: limpiar(d.administrador, 80) || prev?.administrador || "",
      responsable: limpiar(d.responsable, 80) || prev?.responsable || "",
      partes, items, historial,
      seguimiento: prev?.seguimiento || {},
      ...(prev?.desbloqueo ? { desbloqueo: prev.desbloqueo } : {}),
      creadoEn: prev?.creadoEn || ahora, actualizadoEn: ahora,
      version: "CL-LEC-01 v02",
    };
    const n = ALL_KEYS.filter(k => items[k]).length;
    doc.estado = n === ALL_KEYS.length ? "completo" : n ? "parcial" : "vacío";
    doc.estadoPartes = Object.fromEntries(Object.entries(ITEMS).map(([S, tot]) => {
      const c = Object.keys(items).filter(k => k[0] === S).length;
      return [S, c === tot ? "completa" : c ? "parcial" : "pendiente"];
    }));
    mesDoc.registros[`${d.fecha}_${d.turno}`] = doc;
    return mesDoc;
    });
    return json({ ok: true, estado: doc.estado, estadoPartes: doc.estadoPartes, actualizadoEn: doc.actualizadoEn }, 200, h);
  }

  return json({ error: "ruta" }, 404, h);
}

export default {
  async fetch(req, env) {
    const h = cors(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    try { return await handle(req, env, h); }
    catch (e) {
      if (e.status) return json({ error: e.code || "datos", mensaje: e.message }, e.status, h);
      return json({ error: "servidor", mensaje: "Error del servidor. Intenta de nuevo en unos minutos.", detalle: String(e.message || e).slice(0, 200) }, 502, h);
    }
  },
};
