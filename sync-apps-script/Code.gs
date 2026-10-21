// Sincronizzazione automatica dei movimenti per Bilancio Familiare.
//
// Gira come progetto Google Apps Script sull'account Google che possiede il
// progetto Firebase. Due fonti:
//   - BPER: movimenti del conto via Enable Banking (open banking PSD2);
//   - AMEX: email di avviso acquisto lette da Gmail.
// Tutto finisce nella collezione Firestore "bilancio_familiare_inbox" con
// stato "da_confermare": è l'app a trasformarli in movimenti veri, dopo che
// l'utente li ha confermati. Lo script non scrive MAI nei movimenti dell'app.
//
// Nessun segreto è in questo file: chiave privata, id applicazione e sessione
// stanno nelle Proprietà dello script (Impostazioni progetto → Proprietà).

const EB_API = "https://api.enablebanking.com";
const INBOX = "bilancio_familiare_inbox";
const DOC_STATO = "_stato_sync";
const GIORNI_RILETTURA = 7; // rilegge sempre gli ultimi giorni: la banca può contabilizzare in ritardo

function prop(k, def) {
  const v = PropertiesService.getScriptProperties().getProperty(k);
  if (v === null || v === "") {
    if (def !== undefined) return def;
    throw new Error("Proprietà dello script mancante: " + k);
  }
  return v;
}
function setProp(k, v) { PropertiesService.getScriptProperties().setProperty(k, v); }

// ---------------------------------------------------------------------------
// Enable Banking: autenticazione JWT RS256
// ---------------------------------------------------------------------------

function b64url(bytesOrString) {
  return Utilities.base64EncodeWebSafe(bytesOrString).replace(/=+$/, "");
}

function ebJwt() {
  const now = Math.floor(Date.now() / 1000);
  const header = { typ: "JWT", alg: "RS256", kid: prop("EB_APP_ID") };
  const payload = { iss: "enablebanking.com", aud: "api.enablebanking.com", iat: now, exp: now + 3600 };
  const input = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  // Apps Script vuole la chiave in formato PKCS#8 ("BEGIN PRIVATE KEY"): vedi LEGGIMI.md.
  const firma = Utilities.computeRsaSha256Signature(input, chiavePem());
  return input + "." + b64url(firma);
}

// Le Proprietà dello script si modificano in un campo a riga singola: incollando
// il file .pem gli "a capo" possono sparire. Ricostruiamo il PEM standard.
function chiavePem() {
  const corpo = prop("EB_PRIVATE_KEY").replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  return "-----BEGIN PRIVATE KEY-----\n" + corpo.match(/.{1,64}/g).join("\n") + "\n-----END PRIVATE KEY-----\n";
}

function eb(method, path, body) {
  const opt = {
    method: method,
    headers: { Authorization: "Bearer " + ebJwt() },
    contentType: "application/json",
    muteHttpExceptions: true
  };
  if (body) opt.payload = JSON.stringify(body);
  const r = UrlFetchApp.fetch(EB_API + path, opt);
  const code = r.getResponseCode();
  if (code >= 300) throw new Error("Enable Banking " + method + " " + path + " → " + code + ": " + r.getContentText().slice(0, 300));
  return JSON.parse(r.getContentText() || "{}");
}

// ---------------------------------------------------------------------------
// Consenso BPER: pagina web dello script (Distribuisci → App web)
// ---------------------------------------------------------------------------

function doGet(e) {
  const p = (e && e.parameter) || {};
  if (p.code) return completaConsenso(p);
  // La pagina dello script gira in un iframe: la banca va aperta nella finestra
  // principale (target _top), altrimenti molte banche rifiutano di caricarsi.
  if (p.avvia) return HtmlService.createHtmlOutput(
    '<p style="font-family:system-ui;margin:40px auto;max-width:520px"><a href="' + avviaConsenso() + '" target="_top">Prosegui su BPER per autorizzare</a></p>');
  return paginaStato("");
}

function avviaConsenso() {
  const aspsp = { name: prop("EB_ASPSP_NAME", "BPER Banca"), country: "IT" };
  const info = (eb("get", "/aspsps?country=IT&psu_type=personal").aspsps || []).find(a => a.name === aspsp.name);
  if (!info) throw new Error("Banca non trovata su Enable Banking: " + aspsp.name);
  const secondi = Number(info.maximum_consent_validity || 90 * 86400);
  const validUntil = new Date(Date.now() + (secondi - 3600) * 1000).toISOString();
  const state = Utilities.getUuid();
  setProp("EB_PENDING_STATE", state);
  const r = eb("post", "/auth", {
    access: { valid_until: validUntil },
    aspsp: aspsp,
    state: state,
    redirect_url: ScriptApp.getService().getUrl(),
    psu_type: "personal",
    language: "it"
  });
  return r.url;
}

function completaConsenso(p) {
  if (p.state !== prop("EB_PENDING_STATE", "")) return paginaStato("Richiesta non riconosciuta: riparti da \"Collega BPER\".");
  // Siamo nell'app web pubblicata: questo è l'indirizzo /exec vero. Dall'editor o
  // dagli avvii automatici getUrl() può restituire quello di prova (/dev).
  setProp("WEB_APP_URL", ScriptApp.getService().getUrl());
  const s = eb("post", "/sessions", { code: p.code });
  setProp("EB_SESSION_ID", s.session_id);
  setProp("EB_ACCOUNTS", JSON.stringify((s.accounts || []).map(a => a.uid)));
  setProp("EB_VALID_UNTIL", (s.access && s.access.valid_until) || "");
  PropertiesService.getScriptProperties().deleteProperty("EB_PENDING_STATE");
  scriviStato();
  return paginaStato("Collegamento riuscito: " + (s.accounts || []).length + " conto/i.");
}

function paginaStato(msg) {
  const scad = prop("EB_VALID_UNTIL", "");
  const url = ScriptApp.getService().getUrl();
  return HtmlService.createHtmlOutput(
    '<div style="font-family:system-ui;max-width:520px;margin:40px auto;line-height:1.5">' +
    "<h2>Sincronizzazione BPER</h2>" +
    (msg ? "<p><b>" + msg + "</b></p>" : "") +
    "<p>Consenso valido fino a: <b>" + (scad ? new Date(scad).toLocaleDateString("it-IT") : "non collegato") + "</b></p>" +
    '<p><a href="' + url + '?avvia=1" target="_top">Collega / rinnova BPER</a></p></div>'
  );
}

// ---------------------------------------------------------------------------
// Sincronizzazione BPER
// ---------------------------------------------------------------------------

// Impostazioni scelte nell'app (Admin → Sincronizzazione automatica banca),
// salvate nel documento di stato: on/off, data di partenza, parole da escludere.
function leggiImpostazioni() {
  const r = UrlFetchApp.fetch(fsUrl(INBOX + "/" + DOC_STATO), {
    headers: { Authorization: "Bearer " + ScriptApp.getOAuthToken() },
    muteHttpExceptions: true
  });
  const f = r.getResponseCode() === 200 ? (JSON.parse(r.getContentText()).fields || {}) : {};
  const escludi = f.escludi && f.escludi.arrayValue
    ? (f.escludi.arrayValue.values || []).map(v => String(v.stringValue || "").toLowerCase()).filter(Boolean)
    : ["mutuo", "emolumenti", "stipendio", "retribuzion"];
  return {
    attiva: !!(f.syncAttiva && f.syncAttiva.booleanValue),
    dal: (f.syncDal && f.syncDal.stringValue) || "",
    escludi: escludi
  };
}

function daImportare(imp, data, descr) {
  if (imp.dal && data < imp.dal) return false;
  const d = descr.toLowerCase();
  return !imp.escludi.some(p => d.indexOf(p) >= 0);
}

function sincronizzaBper() {
  const imp = leggiImpostazioni();
  if (!imp.attiva) { console.log("Sincronizzazione disattivata nell'app"); return; }
  const accounts = JSON.parse(prop("EB_ACCOUNTS", "[]"));
  if (!accounts.length) return;
  // Chiediamo sempre l'ultima settimana (la banca contabilizza in ritardo); la data
  // di partenza scelta nell'app si applica alla data d'acquisto, in inboxDaBper.
  // La prima volta si guarda indietro di 45 giorni per trovare l'ultimo addebito
  // AMEX e mutuo (i movimenti vecchi sono comunque scartati dalla data di partenza).
  const giorni = prop("ULTIMO_ADDEBITO_AMEX", "") && prop("ULTIMO_ADDEBITO_MUTUO", "") ? GIORNI_RILETTURA : 45;
  const da = new Date(Date.now() - giorni * 86400000).toISOString().slice(0, 10);
  let nuovi = 0, saldo = null;
  accounts.forEach(acc => {
    // Il saldo serve all'indicatore "Disponibile oggi": se la banca non lo dà,
    // i movimenti si sincronizzano comunque.
    try {
      const s = leggiSaldo(acc);
      if (s) saldo = saldo ? { importo: saldo.importo + s.importo, tipo: s.tipo, data: s.data } : s;
    } catch (e) { console.log("Saldo BPER non disponibile: " + e.message); }
    let cont = null;
    do {
      const q = "?date_from=" + da + "&transaction_status=BOOK" + (cont ? "&continuation_key=" + encodeURIComponent(cont) : "");
      const r = eb("get", "/accounts/" + acc + "/transactions" + q);
      (r.transactions || []).forEach(t => { if (inboxDaBper(acc, t, imp)) nuovi++; });
      cont = r.continuation_key;
    } while (cont);
  });
  setProp("ULTIMA_SYNC_BPER", new Date().toISOString());
  if (saldo) {
    setProp("SALDO_BPER", String(saldo.importo));
    setProp("SALDO_BPER_TIPO", saldo.tipo);
    setProp("SALDO_BPER_DATA", saldo.data);
  }
  scriviStato();
  console.log("BPER: " + nuovi + " nuovi movimenti" + (saldo ? ", saldo " + saldo.importo + " (" + saldo.tipo + ")" : ""));
}

// Saldo contabile (solo movimenti contabilizzati, coerente con l'import); se la
// banca non lo fornisce si ripiega su quello disponibile.
const PREFERENZA_SALDO = ["ITBD", "CLBD", "XPCD", "ITAV", "CLAV"];
function leggiSaldo(acc) {
  const lista = eb("get", "/accounts/" + acc + "/balances").balances || [];
  const scelto = PREFERENZA_SALDO.map(tipo => lista.find(b => b.balance_type === tipo)).find(Boolean) || lista[0];
  if (!scelto) return null;
  return {
    importo: Number(scelto.balance_amount.amount),
    tipo: scelto.balance_type,
    data: scelto.last_change_date_time || scelto.reference_date || new Date().toISOString()
  };
}

// Data dell'ultimo addebito visto sul conto per AMEX e mutuo: l'app la usa per
// sapere se l'addebito di questo mese è già uscito dal saldo.
function ricordaAddebito(chiave, data) {
  if (data && data > prop(chiave, "")) setProp(chiave, data);
}

function inboxDaBper(acc, t, imp) {
  // Solo movimenti contabilizzati: quelli "da contabilizzare" possono cambiare o sparire.
  if (t.status ? t.status !== "BOOK" : !t.booking_date) return false;
  const descr = [].concat(t.remittance_information || []).join(" ").trim()
    || (t.creditor && t.creditor.name) || (t.debtor && t.debtor.name) || "Movimento BPER";
  if (/\bmutuo\b/i.test(descr)) ricordaAddebito("ULTIMO_ADDEBITO_MUTUO", t.booking_date);
  // L'addebito mensile AMEX: le spese le registri tu una per una con la spunta AMEX;
  // come fa l'app nella riconciliazione, lo escludiamo per non contarlo due volte.
  if (/\b(american express|americanexpress|amex)\b/i.test(descr)) { ricordaAddebito("ULTIMO_ADDEBITO_AMEX", t.booking_date); return false; }
  // Per il bilancio conta il giorno dell'acquisto, non quello di contabilizzazione:
  // le spese con carta BPER lo riportano nella causale ("... del 16.10.2026").
  const mDel = descr.match(/\bdel (\d{2})\.(\d{2})\.(\d{4})\b/);
  const data = mDel ? mDel[3] + "-" + mDel[2] + "-" + mDel[1] : (t.transaction_date || t.value_date || t.booking_date);
  if (!daImportare(imp, data, descr)) return false;
  const importo = Math.abs(Number(t.transaction_amount && t.transaction_amount.amount));
  const ref = t.entry_reference || t.transaction_id || [t.booking_date, importo, descr].join("|");
  return creaInbox("bper_" + hashBreve(acc + "|" + ref), {
    fonte: "bper",
    data: data,
    importo: importo,
    entrata: t.credit_debit_indicator === "CRDT",
    descrizione: descr.replace(/\s+/g, " ").slice(0, 200),
    amex: false
  });
}

// ---------------------------------------------------------------------------
// Email di avviso AMEX
// ---------------------------------------------------------------------------

function sincronizzaAmexEmail() {
  const imp = leggiImpostazioni();
  if (!imp.attiva) return;
  const etOk = GmailApp.getUserLabelByName("finanze-importata") || GmailApp.createLabel("finanze-importata");
  const etKo = GmailApp.getUserLabelByName("finanze-da-controllare") || GmailApp.createLabel("finanze-da-controllare");
  const query = prop("AMEX_QUERY", "from:americanexpress newer_than:14d") + " -label:finanze-importata -label:finanze-da-controllare";
  let nuovi = 0;
  GmailApp.search(query, 0, 50).forEach(thread => {
    let ok = true;
    thread.getMessages().forEach(m => {
      const a = parseAvvisoAmex(m.getSubject(), m.getPlainBody());
      if (!a) { ok = false; return; }
      const data = Utilities.formatDate(m.getDate(), "Europe/Rome", "yyyy-MM-dd");
      if (daImportare(imp, data, a.esercente) && creaInbox("amex_" + hashBreve(m.getId()), {
        fonte: "amex", data: data, importo: a.importo, entrata: false,
        descrizione: a.esercente.slice(0, 200), amex: true
      })) nuovi++;
    });
    thread.addLabel(ok ? etOk : etKo);
  });
  setProp("ULTIMA_SYNC_AMEX", new Date().toISOString());
  scriviStato();
  console.log("AMEX: " + nuovi + " nuovi acquisti");
}

// DA ADATTARE al testo reale delle email American Express Italia: queste
// espressioni sono un punto di partenza. Restituisce null se non riconosce
// l'email, che finisce con l'etichetta "finanze-da-controllare".
function parseAvvisoAmex(oggetto, corpo) {
  const testo = (oggetto + "\n" + corpo).replace(/ /g, " ");
  const mImp = testo.match(/(?:€|EUR)\s*([0-9]{1,3}(?:\.[0-9]{3})*,[0-9]{2})/) || testo.match(/([0-9]{1,3}(?:\.[0-9]{3})*,[0-9]{2})\s*(?:€|EUR)/);
  if (!mImp) return null;
  const importo = Number(mImp[1].replace(/\./g, "").replace(",", "."));
  const mEs = testo.match(/(?:presso|esercente|merchant)\s*:?\s*([^\n]{2,80})/i);
  return { importo: importo, esercente: mEs ? mEs[1].trim() : "Acquisto AMEX" };
}

// ---------------------------------------------------------------------------
// Firestore (REST, con le credenziali dell'account che esegue lo script)
// ---------------------------------------------------------------------------

function fsUrl(path) {
  return "https://firestore.googleapis.com/v1/projects/" + prop("FIREBASE_PROJECT_ID") + "/databases/(default)/documents/" + path;
}

function fsValore(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  return { stringValue: String(v) };
}

function fsCampi(obj) {
  const f = {};
  Object.keys(obj).forEach(k => f[k] = fsValore(obj[k]));
  return { fields: f };
}

// Crea il documento solo se non esiste già: così un movimento già confermato o
// ignorato nell'app non ricompare mai, anche se la banca lo rimanda.
function creaInbox(id, v) {
  const [anno, mese, giorno] = v.data.split("-").map(Number);
  const doc = Object.assign({ id: id, stato: "da_confermare", anno: anno, mese: mese, giorno: giorno, createdAt: Date.now() }, v);
  const r = UrlFetchApp.fetch(fsUrl(INBOX + "?documentId=" + encodeURIComponent(id)), {
    method: "post",
    headers: { Authorization: "Bearer " + ScriptApp.getOAuthToken() },
    contentType: "application/json",
    payload: JSON.stringify(fsCampi(doc)),
    muteHttpExceptions: true
  });
  if (r.getResponseCode() === 409) { aggiornaSeInAttesa(id, doc); return false; }
  if (r.getResponseCode() >= 300) throw new Error("Firestore → " + r.getResponseCode() + ": " + r.getContentText().slice(0, 300));
  return true;
}

// Se il movimento esiste già ma non l'hai ancora confermato, ne aggiorniamo data,
// importo e descrizione (la banca può correggerli). Quelli gestiti non si toccano.
function aggiornaSeInAttesa(id, doc) {
  const auth = { Authorization: "Bearer " + ScriptApp.getOAuthToken() };
  const g = UrlFetchApp.fetch(fsUrl(INBOX + "/" + encodeURIComponent(id)), { headers: auth, muteHttpExceptions: true });
  if (g.getResponseCode() !== 200) return;
  const stato = ((JSON.parse(g.getContentText()).fields || {}).stato || {}).stringValue;
  if (stato !== "da_confermare") return;
  const campi = ["data", "anno", "mese", "giorno", "importo", "descrizione"];
  const v = {};
  campi.forEach(k => v[k] = doc[k]);
  UrlFetchApp.fetch(fsUrl(INBOX + "/" + encodeURIComponent(id)) + "?" + campi.map(k => "updateMask.fieldPaths=" + k).join("&"), {
    method: "patch",
    headers: auth,
    contentType: "application/json",
    payload: JSON.stringify(fsCampi(v)),
    muteHttpExceptions: true
  });
}

// Stato letto dall'app per mostrare ultima sincronizzazione e scadenza consenso.
function scriviStato() {
  const stato = {
    ultimaSyncBper: prop("ULTIMA_SYNC_BPER", ""),
    ultimaSyncAmex: prop("ULTIMA_SYNC_AMEX", ""),
    consensoBperFino: prop("EB_VALID_UNTIL", ""),
    paginaConsenso: prop("WEB_APP_URL", ""),
    saldoBper: prop("SALDO_BPER", "") === "" ? null : Number(prop("SALDO_BPER")),
    saldoBperTipo: prop("SALDO_BPER_TIPO", ""),
    saldoBperData: prop("SALDO_BPER_DATA", ""),
    ultimoAddebitoAmex: prop("ULTIMO_ADDEBITO_AMEX", ""),
    ultimoAddebitoMutuo: prop("ULTIMO_ADDEBITO_MUTUO", "")
  };
  // updateMask: aggiorna solo questi campi, senza toccare le impostazioni scelte nell'app.
  const mask = Object.keys(stato).map(k => "updateMask.fieldPaths=" + k).join("&");
  UrlFetchApp.fetch(fsUrl(INBOX + "/" + DOC_STATO) + "?" + mask, {
    method: "patch",
    headers: { Authorization: "Bearer " + ScriptApp.getOAuthToken() },
    contentType: "application/json",
    payload: JSON.stringify(fsCampi(stato)),
    muteHttpExceptions: true
  });
}

function hashBreve(s) {
  const b = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8);
  return b.slice(0, 12).map(x => ((x + 256) % 256).toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Pianificazione e avvisi
// ---------------------------------------------------------------------------

// Da eseguire una volta a mano dall'editor: crea gli avvii automatici.
function installaPianificazione() {
  ScriptApp.getProjectTriggers().forEach(t => ScriptApp.deleteTrigger(t));
  // PSD2: al massimo 4 letture al giorno senza l'utente presente.
  ScriptApp.newTrigger("sincronizzaBper").timeBased().everyHours(6).create();
  // Le email AMEX si attivano solo dopo aver verificato parseAvvisoAmex su email vere.
  if (prop("AMEX_ATTIVO", "") === "si") ScriptApp.newTrigger("sincronizzaAmexEmail").timeBased().everyHours(1).create();
  ScriptApp.newTrigger("controllaScadenzaConsenso").timeBased().everyDays(1).atHour(8).create();
}

function controllaScadenzaConsenso() {
  const scad = prop("EB_VALID_UNTIL", "");
  if (!scad) return;
  const giorni = Math.floor((new Date(scad) - Date.now()) / 86400000);
  if (giorni === 14 || giorni === 3 || giorni === 0) {
    MailApp.sendEmail(Session.getEffectiveUser().getEmail(),
      "Bilancio Familiare: rinnova il collegamento BPER",
      "Il consenso BPER scade tra " + giorni + " giorni. Rinnovalo da: " + prop("WEB_APP_URL", ""));
  }
}
