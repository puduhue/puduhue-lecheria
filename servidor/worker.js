/*
  Puduhue Lechería · servidor (Cloudflare Worker)
  ------------------------------------------------
  Recibe los check lists de sala de ordeña desde los teléfonos (sin cuenta Microsoft),
  valida la clave de la sala que viene en el QR y guarda registros y fotos en OneDrive.

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
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
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
async function gPut(env, rel, body, type) {
  const r = await fetch(itemUrl(env, rel) + "/content", {
    method: "PUT", body, headers: { Authorization: "Bearer " + (await getToken(env)), "Content-Type": type },
  });
  if (!r.ok) throw new Error("put " + r.status + " " + (await r.text()).slice(0, 200));
  return r.json();
}

/* ---------- salas ---------- */
async function salaPorClave(env, k) {
  if (!k || k.length < 10 || k.length > 64) return null;
  if (!salasCache || salasCache.exp < Date.now()) {
    const r = await gGet(env, "_datos/salas.json");
    const j = r ? await r.json() : { salas: [] };
    salasCache = { salas: j.salas || [], exp: Date.now() + 60000 };
  }
  return salasCache.salas.find(s => s.activa !== false && s.clave === k) || null;
}
const rutaRegistro = (sala, fecha, turno) => `_datos/registros/${sala.id}/${fecha}_${turno}.json`;
const carpetaFotos = (sala, fecha) => `${nombreCarpeta(sala.nombre)}/${fecha.slice(0, 7)}/Fotos`;

function validarFechaTurno(fecha, turno) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha || "")) return "Fecha inválida.";
  if (!["AM", "PM"].includes(turno)) return "Turno inválido.";
  const d = difDias(fecha, hoyChile());
  if (d > 1 || d < -7) return "La fecha debe estar entre los últimos 7 días y hoy.";
  return null;
}

/* ---------- rutas ---------- */
async function handle(req, env, h) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const sala = await salaPorClave(env, url.searchParams.get("k"));
  if (path === "/api/ping") return json({ ok: true, hoy: hoyChile() }, 200, h);
  if (!sala) return json({ error: "clave", mensaje: "El código QR de la sala no es válido o fue reemplazado. Pide uno nuevo a la administración." }, 403, h);
  const publica = { id: sala.id, nombre: sala.nombre, predio: sala.predio || "" };

  if (req.method === "GET" && path === "/api/sala") return json({ sala: publica, hoy: hoyChile() }, 200, h);

  if (req.method === "GET" && path === "/api/registro") {
    const fecha = url.searchParams.get("fecha"), turno = url.searchParams.get("turno");
    const e = validarFechaTurno(fecha, turno); if (e) return json({ error: "datos", mensaje: e }, 400, h);
    const r = await gGet(env, rutaRegistro(sala, fecha, turno));
    return json({ registro: r ? await r.json() : null }, 200, h);
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
    const ruta = rutaRegistro(sala, d.fecha, d.turno);
    const prevR = await gGet(env, ruta);
    const prev = prevR ? await prevR.json() : null;
    const ahora = new Date().toISOString();
    // Cada parte (A = antes, B = después) se guarda por separado: se conserva la otra parte tal como estaba.
    const items = {};
    for (const [k, it] of Object.entries(prev?.items || {})) if (k[0] !== parte && ALL_KEYS.includes(k)) items[k] = it;
    Object.assign(items, nuevos);
    const partes = { ...(prev?.partes || {}) };
    partes[parte] = {
      completadoPor: limpiar(d.completadoPor, 80),
      horaRegistro: /^\d{2}:\d{2}$/.test(d.horaRegistro || "") ? d.horaRegistro : "",
      actualizadoEn: ahora, dispositivo: limpiar(d.dispositivo, 40),
      ediciones: (prev?.partes?.[parte]?.ediciones ?? -1) + 1,
    };
    const doc = {
      id: `${sala.id}_${d.fecha}_${d.turno}`,
      salaId: sala.id, sala: sala.nombre, predio: sala.predio || "",
      fecha: d.fecha, turno: d.turno,
      area: limpiar(d.area, 60) || prev?.area || "",
      administrador: limpiar(d.administrador, 80) || prev?.administrador || "",
      responsable: limpiar(d.responsable, 80) || prev?.responsable || "",
      partes, items,
      seguimiento: prev?.seguimiento || {},
      creadoEn: prev?.creadoEn || ahora, actualizadoEn: ahora,
      version: "CL-LEC-01 v02",
    };
    const n = ALL_KEYS.filter(k => items[k]).length;
    doc.estado = n === ALL_KEYS.length ? "completo" : n ? "parcial" : "vacío";
    doc.estadoPartes = Object.fromEntries(Object.entries(ITEMS).map(([S, tot]) => {
      const c = Object.keys(items).filter(k => k[0] === S).length;
      return [S, c === tot ? "completa" : c ? "parcial" : "pendiente"];
    }));
    await gPut(env, ruta, JSON.stringify(doc, null, 1), "application/json");
    return json({ ok: true, estado: doc.estado, estadoPartes: doc.estadoPartes, actualizadoEn: ahora }, 200, h);
  }

  return json({ error: "ruta" }, 404, h);
}

export default {
  async fetch(req, env) {
    const h = cors(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    try { return await handle(req, env, h); }
    catch (e) { return json({ error: "servidor", mensaje: "Error del servidor. Intenta de nuevo en unos minutos.", detalle: String(e.message || e).slice(0, 200) }, 502, h); }
  },
};
