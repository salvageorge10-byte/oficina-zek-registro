// Registro de envíos: los mismos datos de la oficina, ordenados como planilla de trabajo.
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nombreCorto = L => { const n = (L.n || L.u).split(/\s*[|·•–—\/]\s*|\s+-\s+/)[0].trim(); return n.length > 2 ? n : (L.n || L.u); };
const dm = f => f ? f.slice(8, 10) + "/" + f.slice(5, 7) : "";
const diaDe = iso => { const d = new Date(iso); return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"); };
const dias = (a, b) => Math.round((Date.UTC(...b.split("-").map((x, i) => i === 1 ? x - 1 : +x)) - Date.UTC(...a.split("-").map((x, i) => i === 1 ? x - 1 : +x))) / 864e5);
const dominio = u => u.replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "");
const FLECHA = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg>';
const CLASES = { si: "Dijo que sí", precio: "Preguntó el precio", no: "Dijo que no", consulta: "Respondió" };

// Estados del embudo: cada negocio está en uno solo (por eso la barra puede ser proporcional)
const ESTADOS = [
  { k: "esperando", t: "Esperando respuesta", s: "Esperando respuesta", c: "#5f6678" },
  { k: "interesado", t: "Interesados", s: "Interesado", c: "#8fa8e8" },
  { k: "seguimiento", t: "En seguimiento", s: "En seguimiento", c: "#d8b25c" },
  { k: "cerro", t: "Cerraron", s: "Cerró", c: "#7cc4a0" },
  { k: "no", t: "No van", s: "No va", c: "#e58a80" },
];
const POR_K = Object.fromEntries(ESTADOS.map(e => [e.k, e]));
function estadoDe(L) {
  if (["encontrado", "redactado"].includes(L.etapa)) return "pormandar";
  if (L.etapa === "enviado") return "esperando";
  if (["si", "muestras"].includes(L.etapa)) return "interesado";
  if (["seguimiento", "maqueta"].includes(L.etapa)) return "seguimiento";
  if (L.etapa === "cerrado") return "cerro";
  return "no";
}

let E = null, version = 0, filtro = "todos", tramo = null, q = "";
const abiertas = new Set();

function paso(L) {
  const hoy = E.hoy, ins = L.ins || 0;
  if (L.contesto && !["cerrado", "no"].includes(L.etapa)) return { t: "Contestarle", s: "te escribió el " + dm(L.respF), hoy: true };
  switch (L.etapa) {
    case "redactado": return { t: "Mandar el DM", s: "mensaje listo", hoy: true };
    case "encontrado": return { t: "Escribir el mensaje", s: "lo hace Bruno" };
    case "enviado": return { t: "Esperar respuesta", s: L.envio ? hace(L.envio) : "" };
    case "si": return { t: "Preparando ejemplos", s: "lo hace Tomás" };
    case "muestras": return { t: "Mandarle los ejemplos", s: "mensaje listo", hoy: true };
    case "seguimiento":
      if (L.prox && L.prox <= hoy) return { t: "Insistir hoy", s: (ins + 1) + "ª insistencia", hoy: true };
      return { t: "Insistir el " + dm(L.prox), s: (ins + 1) + "ª insistencia" };
    case "maqueta": return { t: "Armar su maqueta", s: "pedíselo a Claude" };
    case "cerrado": return { t: "Cerró el " + dm(L.cierre), s: "" };
    default: return { t: "—", s: "" };
  }
}
const hace = f => { const d = Math.max(0, dias(f, E.hoy)); return d === 0 ? "le escribiste hoy" : d === 1 ? "le escribiste ayer" : "le escribiste hace " + d + " días"; };
const urgente = L => !!paso(L).hoy;
const ultimaActividad = L => (L.hist && L.hist.length ? L.hist[L.hist.length - 1][0] : L.alta || "");
const conEnvio = L => !!(L.web || L.ejemplosF || ["seguimiento", "maqueta", "cerrado"].includes(L.etapa));

const FILTROS = [
  { k: "todos", t: "Todos", f: L => estadoDe(L) !== "pormandar" },
  { k: "hoy", t: "Para hoy", f: urgente, urgente: true },
  { k: "contestaron", t: "Te contestaron", f: L => !!L.resp },
  { k: "web", t: "Con web o ejemplos", f: conEnvio },
  { k: "pormandar", t: "Por mandar", f: L => estadoDe(L) === "pormandar" },
];

// En la compu lee el servidor local. En internet (GitHub Pages) lee el archivo cifrado que sube la compu.
const REMOTO = !/^(localhost|127\.0\.0\.1)$/.test(location.hostname);
const REPO = "salvageorge10-byte/oficina-zek-registro";
const hoyLocal = () => diaDe(new Date().toISOString());
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
let ultimoCifrado = "";

async function descifrar(paquete, clave) {
  const p = JSON.parse(paquete);
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(clave), "PBKDF2", false, ["deriveKey"]);
  const llave = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(p.sal), iterations: 200000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plano = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(p.iv) }, llave, b64(p.datos));
  return JSON.parse(new TextDecoder().decode(plano));
}
const leerClave = () => { try { return localStorage.getItem("zek-clave") || ""; } catch { return ""; } };
const guardarClave = c => { try { localStorage.setItem("zek-clave", c); } catch {} };

function pedirClave(error) {
  $("#bajada").textContent = "Para ver el registro en este teléfono, poné la clave de la oficina. Se pide una sola vez.";
  $("#embudo").innerHTML = ""; $("#filtros").innerHTML = "";
  $("#filas").innerHTML = `<form class="vacio clave" id="form-clave"><h2>Clave de la oficina</h2>
    <p>Está en la compu, en <code>oficina-zek/datos/clave.txt</code>.</p>
    <div class="cargar"><input class="campo" name="clave" autocomplete="off" autocapitalize="off" placeholder="xxxx-xxxx-xxxx" aria-label="Clave" required><button class="bt pri">Entrar</button></div>
    ${error ? `<p class="error">${error}</p>` : ""}</form>`;
  $("#form-clave").onsubmit = e => { e.preventDefault(); guardarClave(new FormData(e.target).get("clave").trim()); ultimoCifrado = ""; sondear(); };
}

async function sondearRemoto() {
  try {
    let r = await fetch(`https://api.github.com/repos/${REPO}/contents/datos.json?ref=main&_=${Date.now()}`, { headers: { accept: "application/vnd.github.raw" }, cache: "no-store" });
    if (!r.ok) r = await fetch("datos.json?_=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error("sin datos");
    const txt = await r.text();
    if (txt === ultimoCifrado && E) return;
    const clave = leerClave();
    if (!clave) return pedirClave();
    let d;
    try { d = await descifrar(txt, clave); } catch { guardarClave(""); return pedirClave("Esa clave no abre el registro. Fijate que esté bien escrita."); }
    ultimoCifrado = txt;
    E = { ...d, hoy: hoyLocal() };
    const min = Math.round((Date.now() - Date.parse(d.t)) / 60000);
    $("#conexion").className = "estado-conexion " + (min < 30 ? "ok" : "");
    $("#conexion span:last-child").textContent = min < 2 ? "actualizado recién" : "actualizado hace " + (min < 60 ? min + " min" : Math.round(min / 60) + " h");
    render();
  } catch {
    $("#conexion").className = "estado-conexion mal";
    $("#conexion span:last-child").textContent = "sin conexión";
  }
}

async function sondear() {
  if (REMOTO) return sondearRemoto();
  try {
    const r = await fetch("/api/estado?v=" + version, { cache: "no-store" });
    const j = await r.json();
    $("#conexion").className = "estado-conexion ok";
    $("#conexion span:last-child").textContent = "al día";
    if (!j.igual) { version = j.v; E = j; render(); }
  } catch {
    $("#conexion").className = "estado-conexion mal";
    $("#conexion span:last-child").textContent = "oficina cerrada: abrí Oficina ZEK.bat";
  }
}

function render() {
  const foco = document.activeElement;
  if (foco && foco.closest(".detalle") && /TEXTAREA|INPUT/.test(foco.tagName)) { pendiente = true; return; }
  pendiente = false;
  const ls = Object.values(E.leads);
  const enEmbudo = ls.filter(L => estadoDe(L) !== "pormandar");
  const n = k => enEmbudo.filter(L => estadoDe(L) === k).length;

  // Bajada: una frase con los números que importan
  const conWeb = ls.filter(conEnvio).length, cont = ls.filter(L => L.resp).length, hoy = ls.filter(urgente).length;
  $("#bajada").innerHTML = enEmbudo.length
    ? `Le escribiste a <b>${enEmbudo.length}</b> ${enEmbudo.length === 1 ? "negocio" : "negocios"}, <b>${cont}</b> ${cont === 1 ? "contestó" : "contestaron"} y <b>${conWeb}</b> ${conWeb === 1 ? "recibió" : "recibieron"} ejemplos o su web.${hoy ? ` Hoy tenés <b>${hoy}</b> ${hoy === 1 ? "cosa" : "cosas"} para hacer.` : ""}`
    : "Todavía no hay nadie. Se va llenando solo mientras usás Instagram en la compu.";

  // Embudo
  const total = enEmbudo.length || 1;
  $("#embudo").className = "embudo" + (tramo ? " filtrado" : "");
  $("#embudo").innerHTML = `<div class="barra" aria-hidden="true">${ESTADOS.map(e => n(e.k) ? `<i style="flex-grow:${n(e.k)};background:${e.c}"></i>` : "").join("")}</div>
    <div class="tramos">${ESTADOS.map(e => `<button class="tramo ${tramo === e.k ? "activo" : ""}" style="--c:${e.c}" data-tramo="${e.k}" aria-pressed="${tramo === e.k}"><b>${n(e.k)}</b><span>${e.t}</span><small>${Math.round(n(e.k) / total * 100)}% del total</small></button>`).join("")}</div>`;

  // Filtros
  $("#filtros").innerHTML = FILTROS.map(f => { const c = ls.filter(f.f).length; return `<button data-filtro="${f.k}" aria-pressed="${filtro === f.k && !tramo}" class="${f.urgente && c ? "urgente" : ""}">${f.t}<em>${c}</em></button>`; }).join("");

  // Filas
  let lista = ls.filter(tramo ? (L => estadoDe(L) === tramo) : FILTROS.find(f => f.k === filtro).f);
  if (q) { const x = q.toLowerCase(); lista = lista.filter(L => [L.u, L.n, L.rubro, L.ciudad, L.resp, L.nota].join(" ").toLowerCase().includes(x)); }
  lista.sort((a, b) => (Number(urgente(b)) - Number(urgente(a))) || (ultimaActividad(a) < ultimaActividad(b) ? 1 : -1));

  if (!lista.length) {
    $("#filas").innerHTML = ls.length
      ? `<div class="vacio"><h2>Nada por acá.</h2><p>Probá con otro filtro o borrá la búsqueda.</p></div>`
      : `<div class="vacio"><h2>El registro se llena solo.</h2>
         <p>Con la Oficina abierta, usá Instagram en Chrome desde la compu: cada vez que le escribís a un negocio por la web, Mora lo anota acá con el link que le mandaste y lo que te contestó.</p>
         <p>Si alguien te respondió desde el celular, abrí ese chat en la compu y aparece.</p></div>`;
    return;
  }
  $("#filas").innerHTML = lista.map(fila).join("");
}

function fila(L) {
  const e = estadoDe(L), est = POR_K[e] || { s: "Por mandar", c: "#6f7382" }, p = paso(L), abierta = abiertas.has(L.u);
  let mando;
  if (L.web) mando = `<span class="tipo">Su web${L.webF ? " · " + dm(L.webF) : ""}</span><a class="link" href="${esc(L.web)}" target="_blank" rel="noopener"><span>${esc(dominio(L.web))}</span>${FLECHA}</a>`;
  else if (L.ejemplosF && L.muestras?.length) mando = `<span class="tipo">Ejemplos · ${dm(L.ejemplosF)}</span><a class="link" href="${esc(L.muestras[0])}" target="_blank" rel="noopener"><span>${esc(dominio(L.muestras[0]))}</span>${FLECHA}</a>${L.muestras.length > 1 ? `<span class="mas-links">y ${L.muestras.length - 1} más</span>` : ""}`;
  else if (L.envio) mando = `<span class="tipo">Primer mensaje · ${dm(L.envio)}</span><span class="nada">Todavía sin link</span>`;
  else mando = `<span class="nada">Nada todavía</span>`;
  const dijo = L.resp
    ? `<span class="chip ${esc(L.clase)}">${esc(CLASES[L.clase] || "Respondió")}${L.respF ? " · " + dm(L.respF) : ""}</span><div class="dijo">${esc(L.resp)}</div>`
    : `<div class="dijo sin">${L.envio ? "Sin respuesta todavía" : "—"}</div>`;
  const sub = L.ins ? L.ins + (L.ins === 1 ? " insistencia" : " insistencias") : "";
  return `<div class="fila reg ${abierta ? "abierta" : ""}" role="row" data-u="${esc(L.u)}" tabindex="0" aria-expanded="${abierta}">
      <div class="neg" role="cell"><b>${esc(nombreCorto(L))}</b><a href="https://instagram.com/${esc(L.u)}" target="_blank" rel="noopener">@${esc(L.u)}</a><span class="meta">${[L.rubro, L.ciudad].filter(Boolean).map(esc).join(" · ")}</span></div>
      <div class="mando" role="cell">${mando}</div>
      <div class="dijo-celda" role="cell">${dijo}</div>
      <div class="estado" role="cell" style="--c:${est.c}"><div>${est.s}${sub ? `<small>${sub}</small>` : ""}</div></div>
      <div class="paso ${p.hoy ? "hoy" : ""}" role="cell">${esc(p.t)}${p.s ? `<small>${esc(p.s)}</small>` : ""}</div>
    </div>${abierta ? detalle(L) : ""}`;
}

function detalle(L) {
  const chat = (L.chat || []).map(m => `<div class="msj ${m.yo ? "mio" : "suyo"}">${esc(m.x)}</div>`).join("");
  const hist = (L.hist || []).slice().reverse().slice(0, 14).map(([t, x]) => `<li><time>${dm(diaDe(t))}</time><span>${esc(x)}</span></li>`).join("");
  const p = paso(L), activo = !["cerrado", "no"].includes(L.etapa);
  const acciones = [
    `<button class="bt pri" data-acc="abrir">${FLECHA}Abrir chat</button>`,
    L.web ? `<button class="bt" data-acc="copiar-link">Copiar link</button>` : "",
    L.contesto && activo ? `<button class="bt" data-acc="respondido">Ya le respondí</button>` : "",
    L.etapa === "seguimiento" && p.hoy && !L.contesto ? `<button class="bt" data-acc="insisti">Ya insistí</button>` : "",
    activo && L.etapa !== "maqueta" ? `<button class="bt" data-acc="pedir-maqueta">Pedir maqueta</button>` : "",
    activo ? `<button class="bt" data-acc="cerro">Cerró</button>` : "",
    activo ? `<button class="bt no" data-acc="no-va">No va</button>` : `<button class="bt" data-acc="volver">Volver a seguimiento</button>`,
  ].join("");
  if (REMOTO) return `<div class="detalle" data-u="${esc(L.u)}">
    <div><h4>Conversación${L.chatVisto ? " · leída el " + dm(diaDe(L.chatVisto)) : ""}</h4>
      ${chat ? `<div class="chat">${chat}</div>` : `<p class="chat-vacio">Mora todavía no leyó este chat.</p>`}
      <div class="acciones"><button class="bt pri" data-acc="abrir">${FLECHA}Abrir chat</button>${L.web ? `<button class="bt" data-acc="copiar-link">Copiar link</button>` : ""}</div>
      <p class="solo-compu">Para marcar que insististe, que cerró o que no va, usá la oficina en la compu.</p></div>
    <div>${L.nota ? `<h4>Nota</h4><p class="nota-leer">${esc(L.nota)}</p>` : ""}
      <h4>Historial</h4><ul class="linea-tiempo">${hist || "<li><span>Sin movimientos</span></li>"}</ul></div>
  </div>`;
  return `<div class="detalle" data-u="${esc(L.u)}">
    <div><h4>Conversación${L.chatVisto ? " · leída el " + dm(diaDe(L.chatVisto)) : ""}</h4>
      ${chat ? `<div class="chat">${chat}</div>` : `<p class="chat-vacio">Mora todavía no leyó este chat. Abrilo en Instagram desde la compu y aparece acá.</p>`}
      <div class="acciones">${acciones}</div></div>
    <div><h4>Link de su web</h4>
      <div class="cargar"><input class="campo" data-campo="web" value="${esc(L.web || "")}" placeholder="https://…vercel.app" aria-label="Link de su web"><button class="bt" data-acc="guardar-web">Guardar</button></div>
      <h4>Nota</h4><textarea class="nota" data-campo="nota" placeholder="Lo que quieras recordar de este negocio" aria-label="Nota">${esc(L.nota || "")}</textarea>
      <h4>Historial</h4><ul class="linea-tiempo">${hist || "<li><span>Sin movimientos</span></li>"}</ul></div>
  </div>`;
}

async function accion(cuerpo, ok) {
  try {
    const r = await fetch("/api/accion", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(cuerpo) });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    if (ok) avisar(ok);
    sondear();
  } catch (e) { avisar(e.message || "No se pudo guardar"); }
}
let tAviso, pendiente = false;
function avisar(t) { const a = $("#aviso"); a.textContent = t; a.classList.add("ver"); clearTimeout(tAviso); tAviso = setTimeout(() => a.classList.remove("ver"), 2400); }

document.addEventListener("click", async e => {
  const tr = e.target.closest("[data-tramo]");
  if (tr) { tramo = tramo === tr.dataset.tramo ? null : tr.dataset.tramo; return render(); }
  const fi = e.target.closest("[data-filtro]");
  if (fi) { filtro = fi.dataset.filtro; tramo = null; return render(); }
  const b = e.target.closest("[data-acc]");
  if (b) {
    const u = b.closest("[data-u]").dataset.u, L = E.leads[u], acc = b.dataset.acc;
    if (acc === "abrir") return window.open("https://ig.me/m/" + encodeURIComponent(u), "_blank", "noopener");
    if (acc === "copiar-link") { try { await navigator.clipboard.writeText(L.web); avisar("Link copiado"); } catch { avisar("No pude copiar"); } return; }
    if (acc === "guardar-web") return accion({ tipo: "set-web", u, web: b.parentElement.querySelector("input").value }, "Link guardado");
    if (acc === "no-va" && !confirm("¿Pasar a «No va»?")) return;
    const textos = { respondido: "Anotado", insisti: "Insistencia anotada", "pedir-maqueta": "Entró a la cola de maquetas", cerro: "¡Cerró!", "no-va": "Pasado a «No va»", volver: "Volvió a seguimiento" };
    return accion(acc === "volver" ? { tipo: "volver", u, etapa: "seguimiento" } : { tipo: acc, u }, textos[acc]);
  }
  if (e.target.closest("a, input, textarea, .detalle")) return;
  const fila = e.target.closest(".reg");
  if (fila) { const u = fila.dataset.u; abiertas.has(u) ? abiertas.delete(u) : abiertas.add(u); render(); }
});
document.addEventListener("keydown", e => {
  if ((e.key === "Enter" || e.key === " ") && e.target.matches(".reg")) { e.preventDefault(); e.target.click(); }
});
document.addEventListener("focusout", e => {
  if (e.target.matches('[data-campo="nota"]')) {
    const u = e.target.closest("[data-u]").dataset.u;
    if ((E.leads[u]?.nota || "") !== e.target.value) accion({ tipo: "nota", u, nota: e.target.value }, "Nota guardada");
  }
  setTimeout(() => { if (pendiente && !document.activeElement?.closest(".detalle")) render(); }, 60);
});
$("#buscar").addEventListener("input", e => { q = e.target.value.trim(); render(); });

sondear();
if (REMOTO) document.querySelector(".volver")?.remove();
setInterval(sondear, REMOTO ? 90000 : 2000);
addEventListener("focus", () => { if (REMOTO) sondear(); });
