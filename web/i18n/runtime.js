/* Traducción de la interfaz (español, inglés, alemán).
   La página está escrita en español; este bloque traduce lo que se pinta
   (textos, placeholder, title y los diálogos) al idioma elegido.  Por
   defecto se usa el del navegador; se puede cambiar con el selector y se
   recuerda en este dispositivo.  ?lang=xx en la dirección también lo fija
   (la app de la consola lo usa para abrir la web en su idioma). */
"use strict";
const I18N_LANGS = {es: "Español", en: "English", de: "Deutsch"};
const I18N_PATS = I18N_DATA.pat.map(p => [new RegExp(p[0]), p[1], p[2]]);
function i18nPick(){
  let q = null;
  try { q = new URLSearchParams(location.search).get("lang"); } catch(e) {}
  if (q && I18N_LANGS[q]) { try { localStorage.setItem("lang", q); } catch(e) {} return q; }
  try { const s = localStorage.getItem("lang"); if (s && I18N_LANGS[s]) return s; } catch(e) {}
  const list = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "en"];
  for (const l of list) { const c = String(l || "").slice(0, 2).toLowerCase(); if (I18N_LANGS[c]) return c; }
  return "en";
}
let LANG = i18nPick();
document.documentElement.lang = LANG;

function T(s){
  if (s == null || LANG === "es") return s;
  s = String(s);
  const m = s.match(/^(\s*)([\s\S]*?)(\s*)$/);
  const core = m[2];
  if (!core) return s;
  let r = I18N_DATA[LANG][core];
  const flat = core.replace(/\s+/g, " ");   /* textos partidos en varias líneas en el HTML */
  if (r == null && flat !== core) r = I18N_DATA[LANG][flat];
  if (r == null) {
    for (const p of I18N_PATS) {
      const mm = flat.match(p[0]);
      if (mm) { r = (LANG === "en" ? p[1] : p[2]).replace(/\$(\d)/g, (_, n) => T(mm[n] || "")); break; }
    }
  }
  return r == null ? s : m[1] + r + m[3];
}

const I18N_ORIG = new WeakMap();   /* nodo de texto -> {es, tr} */
const I18N_ATTR = new WeakMap();   /* elemento -> {atributo: {es, tr}} */
const I18N_ATTRS = ["placeholder", "title", "aria-label"];
function i18nSkip(el){ return !el || (el.closest && el.closest('script,style,textarea,[translate="no"]')); }
function i18nText(n){
  if (i18nSkip(n.parentNode)) return;
  let o = I18N_ORIG.get(n);
  if (!o || n.data !== o.tr) o = {es: n.data};   /* nuevo, o cambiado por la página */
  o.tr = T(o.es);
  I18N_ORIG.set(n, o);
  if (n.data !== o.tr) n.data = o.tr;
}
function i18nAttrs(el){
  if (i18nSkip(el)) return;
  let map = I18N_ATTR.get(el);
  for (const a of I18N_ATTRS) {
    if (!el.hasAttribute(a)) continue;
    if (!map) { map = {}; I18N_ATTR.set(el, map); }
    const cur = el.getAttribute(a);
    let o = map[a];
    if (!o || cur !== o.tr) o = map[a] = {es: cur};
    o.tr = T(o.es);
    if (cur !== o.tr) el.setAttribute(a, o.tr);
  }
}
function i18nTree(root){
  if (root.nodeType === 3) { i18nText(root); return; }
  if (root.nodeType !== 1) return;
  i18nAttrs(root);
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
  for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeType === 3 ? i18nText(n) : i18nAttrs(n);
}
new MutationObserver(recs => {
  for (const r of recs) {
    if (r.type === "childList") r.addedNodes.forEach(i18nTree);
    else if (r.type === "characterData") i18nText(r.target);
    else if (r.type === "attributes") i18nAttrs(r.target);
  }
}).observe(document.documentElement, {childList: true, subtree: true, characterData: true,
                                      attributes: true, attributeFilter: I18N_ATTRS});

/* Diálogos del navegador */
(() => {
  const c = window.confirm.bind(window), a = window.alert.bind(window), p = window.prompt.bind(window);
  window.confirm = m => c(T(m));
  window.alert = m => a(T(m));
  window.prompt = (m, d) => p(T(m), d);
})();

function setLang(l){
  if (!I18N_LANGS[l]) return;
  LANG = l;
  try { localStorage.setItem("lang", l); } catch(e) {}
  document.documentElement.lang = l;
  document.querySelectorAll("select.langsel").forEach(s => s.value = l);
  i18nTree(document.body);
}
function langSelect(){
  const s = document.createElement("select");
  s.className = "langsel";
  s.setAttribute("translate", "no");
  s.setAttribute("aria-label", "Idioma / Language / Sprache");
  for (const [k, v] of Object.entries(I18N_LANGS)) {
    const o = document.createElement("option");
    o.value = k; o.textContent = v; s.append(o);
  }
  s.value = LANG;
  s.onchange = () => setLang(s.value);
  return s;
}
document.addEventListener("DOMContentLoaded", () => {
  i18nTree(document.body);
  const acc = document.getElementById("b-account");
  if (acc) acc.parentNode.insertBefore(langSelect(), acc);
  const f = document.createElement("div");
  f.className = "langfloat";
  f.append(langSelect());
  document.body.append(f);
});
