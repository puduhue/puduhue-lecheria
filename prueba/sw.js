/* Service worker: la app funciona sin señal. Cambiar VERSION en cada publicación. */
const VERSION = "lec-v12";
/* v12: Lechería y Puduhue Terreno comparten la dirección puduhue.github.io y las cachés son comunes a toda la dirección.
   Cada app borra y lee solo sus cachés: aquí, las que empiezan con «lec-» (antes se borraban todas, también las de Terreno).
   La copia de prueba (carpeta prueba/) usa «prueba-lec-…» y no toca las de la app real. */
const PRUEBA = self.registration.scope.includes("/prueba/"), CACHE = (PRUEBA ? "prueba-" : "") + VERSION;
const esMia = k => k.startsWith((PRUEBA ? "prueba-" : "") + "lec-");
const buscar = (req, op) => caches.open(CACHE).then(c => c.match(req, op));
const ASSETS = ["./", "index.html", "config.js", "manifest.webmanifest", "logo.png", "icon-192.png", "icon-512.png", "apple-touch-icon.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => esMia(k) && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET") return;
  if (u.origin === location.origin && u.pathname.includes("/panel/")) return; // el panel no se guarda sin conexión
  if (u.origin === location.origin){
    if (e.request.mode === "navigate" || u.pathname.endsWith("/index.html") || u.pathname.endsWith("/config.js")){
      e.respondWith(fetch(e.request).then(r => { const cp = r.clone(); caches.open(CACHE).then(c => c.put(e.request.mode === "navigate" ? "index.html" : e.request, cp)); return r; })
        .catch(() => buscar(e.request.mode === "navigate" ? "index.html" : e.request, {ignoreSearch: true})));
      return;
    }
    e.respondWith(buscar(e.request, {ignoreSearch: true}).then(r => r || fetch(e.request)));
  } else if (u.hostname === "fonts.googleapis.com" || u.hostname === "fonts.gstatic.com"){
    e.respondWith(buscar(e.request).then(r => r || fetch(e.request).then(res => { const cp = res.clone(); caches.open(CACHE).then(c => c.put(e.request, cp)); return res; })));
  }
});
