# Puduhue Lechería

App de terreno para las salas de ordeña de Puduhue.

- **Check list de ordeña** (`index.html`): lo completan los ordeñadores sin cuenta Microsoft, entrando por el QR de su sala. Funciona sin señal y envía cuando vuelve la conexión.
- **Servidor** (`servidor/worker.js`): Cloudflare Worker que valida la clave de cada sala y guarda registros y fotos en OneDrive (`Apps de terreno / Check list ordeña`). Se autentica ante Microsoft con certificado; la clave privada vive solo como secreto en Cloudflare, nunca en este repositorio.
