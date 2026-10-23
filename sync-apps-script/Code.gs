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
const APP_URL = "https://cosimolacava-del.github.io/Finanze/";

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
  if (p.sync) return paginaStato(esitoSincronizzazione(sincronizzaBper()));
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
    '<p><a href="' + url + '?sync=1" target="_top">Aggiorna saldo e movimenti ora</a> · ' +
    '<a href="' + url + '?avvia=1" target="_top">Collega / rinnova BPER</a> · ' +
    '<a href="' + APP_URL + '" target="_top">Torna all\'app</a></p></div>'
  );
}

// Messaggio per la pagina, dal riepilogo di sincronizzaBper.
function esitoSincronizzazione(r) {
  if (r.errore && /\b429\b|RATE_LIMIT/.test(r.errore)) return "BPER ha raggiunto il limite giornaliero di letture (regola PSD2): riprova domani. Saldo e movimenti già scaricati restano nell'app.";
  if (r.errore) return "Sincronizzazione non riuscita: " + r.errore;
  if (r.occupato) return "C'è già una sincronizzazione in corso: riprova tra un minuto.";
  if (!r.attiva) return "La sincronizzazione è disattivata nell'app (Admin → Sincronizzazione automatica banca).";
  return "Fatto: " + r.nuovi + " nuovi movimenti da confermare" +
    (r.saldo ? ", saldo " + r.saldo.importo.toLocaleString("it-IT", { style: "currency", currency: "EUR" }) : ", saldo non disponibile") +
    ". L'app si aggiorna da sola.";
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
  // Documento mancante (404) = impostazioni predefinite; ogni altro errore (es. quota
  // Firestore esaurita) deve emergere, non trasformarsi in "sincronizzazione spenta".
  if (r.getResponseCode() !== 200 && r.getResponseCode() !== 404) throw new Error("Firestore → " + r.getResponseCode() + ": " + r.getContentText().slice(0, 200));
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

// Chiamata dagli avvii automatici e dal pulsante "Aggiorna saldo" dell'app (?sync=1).
// Il lock evita due sincronizzazioni insieme; restituisce un riepilogo per la pagina.
function sincronizzaBper() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) return { occupato: true };
  try {
    return eseguiSincronizzazioneBper();
  } catch (e) {
    console.log("Sincronizzazione BPER non riuscita: " + e.message);
    return { errore: e.message };
  } finally {
    lock.releaseLock();
  }
}

function eseguiSincronizzazioneBper() {
  const imp = leggiImpostazioni();
  if (!imp.attiva) { console.log("Sincronizzazione disattivata nell'app"); return { attiva: false }; }
  const accounts = JSON.parse(prop("EB_ACCOUNTS", "[]"));
  if (!accounts.length) return { errore: "nessun conto collegato" };
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
  return { attiva: true, nuovi: nuovi, saldo: saldo };
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
  const importo = Math.abs(Number(t.transaction_amount && t.transaction_amount.amount));
  const entrata = t.credit_debit_indicator === "CRDT";
  const ref = t.entry_reference || t.transaction_id || [t.booking_date, importo, descr].join("|");
  const id = "bper_" + hashBreve(acc + "|" + ref);
  const base = { fonte: "bper", importo: importo, entrata: entrata, descrizione: descr.replace(/\s+/g, " ").slice(0, 200), amex: false };
  // Addebito trimestrale del mutuo (su BPER "RATA FINANZIAMENTO"): l'app lo divide
  // da sola in tre rate mensili. Vale anche se precede la data di partenza, perché
  // copre i mesi successivi.
  if (!entrata && /\b(mutuo|rata finanziamento)\b/i.test(descr)) {
    ricordaAddebito("ULTIMO_ADDEBITO_MUTUO", t.booking_date);
    return creaInbox(id, Object.assign({}, base, { data: t.booking_date, tipo: "rata_trimestrale" }));
  }
  // L'addebito mensile AMEX non entra nel bilancio (le spese le registri tu una per
  // una con la spunta AMEX): arriva all'app solo per il controllo, che lo confronta
  // con le spese AMEX registrate per quel ciclo.
  if (!entrata && /\b(american express|americanexpress|amex)\b/i.test(descr)) {
    ricordaAddebito("ULTIMO_ADDEBITO_AMEX", t.booking_date);
    return creaInbox(id, Object.assign({}, base, { data: t.booking_date, tipo: "addebito_amex" }));
  }
  // Per il bilancio conta il giorno dell'acquisto, non quello di contabilizzazione:
  // le spese con carta BPER lo riportano nella causale ("... del 16.10.2026").
  const mDel = descr.match(/\bdel (\d{2})\.(\d{2})\.(\d{4})\b/);
  const data = mDel ? mDel[3] + "-" + mDel[2] + "-" + mDel[1] : (t.transaction_date || t.value_date || t.booking_date);
  // Stipendi: l'app li registra da soli con la tredicesima spalmata (prima delle
  // parole escluse, che contengono "emolumenti" e "stipendio").
  // Entrate fisse senza tredicesima (assegno unico): registrate dall'app con l'importo reale.
  const fissa = entrata && REGOLE_ENTRATA_FISSA.find(r => r.re.test(descr));
  if (fissa) {
    if (imp.dal && data < imp.dal) return false;
    return creaInbox(id, Object.assign({}, base, { data: data, tipo: "entrata_fissa", voce: fissa.voce }));
  }
  const stipendio = entrata && REGOLE_STIPENDIO.find(r => r.re.test(descr));
  if (stipendio) {
    if (imp.dal && data < imp.dal) return false;
    return creaInbox(id, Object.assign({}, base, { data: data, tipo: "stipendio", voce: stipendio.voce }));
  }
  // Un accredito che sembra uno stipendio ma non corrisponde a nessuna regola non
  // va perso tra le parole escluse: lo si mostra in "Da confermare".
  if (entrata && SEMBRA_STIPENDIO.test(descr)) {
    if (imp.dal && data < imp.dal) return false;
    return creaInbox(id, Object.assign({}, base, { data: data, tipo: "stipendio_da_assegnare" }));
  }
  if (!daImportare(imp, data, descr)) return false;
  return creaInbox(id, Object.assign({}, base, { data: data }));
}

// Accrediti riconosciuti come stipendio e voce di entrata dell'app a cui vanno.
// L'ordine conta: Chiara (scuola pubblica, pagata dal MEF tramite NoiPA) prima di
// EMOLUMENTI, che potrebbe comparire anche nelle causali NoiPA. I bonifici della
// Scuola Internazionale sono di fine rapporto: non sono uno stipendio.
const REGOLE_STIPENDIO = [
  { re: /noipa|\bmef\b|s\.?i\.?i\.?t\b|tesoreria (provinciale )?(dello )?stato|spesa fissa/i, voce: "Stipendio Chiara" },
  { re: /\bemolumenti\b/i, voce: "Stipendio Cosimo" }
];
// Assegno unico dall'INPS (il bonus nido, anch'esso INPS, resta un'entrata normale).
const REGOLE_ENTRATA_FISSA = [
  { re: /assegno unico|\ba\.?u\.?u\.?\b/i, voce: "Assegno unico" }
];
const SEMBRA_STIPENDIO = /stipendi|emolument|retribuz|salari|cedolino|competenze/i;

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
  // Anche tipo e voce: un movimento arrivato prima di una nuova regola (es. l'assegno
  // unico di ottobre) diventa automatico alla sincronizzazione successiva.
  const campi = ["data", "anno", "mese", "giorno", "importo", "descrizione"].concat(["tipo", "voce"].filter(k => doc[k]));
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
// Cedolini UNIPV (portale Cineca U-Web)
// ---------------------------------------------------------------------------
// Entra con le credenziali d'ateneo (UNIPV_USER / UNIPV_PASSWORD nelle proprietà
// dello script), scarica i cedolini nuovi e li lascia in INBOX_CEDOLINI. Alla prima
// apertura della Cassaforte l'app li cifra, li allega e cancella questa copia.

const UNIPV = "https://unipv.u-web.cineca.it";
const INBOX_CEDOLINI = "bilancio_familiare_cassaforte_inbox";
const MAX_CEDOLINO = 740 * 1024; // in base64 cresce di 4/3 e un documento Firestore non supera 1 MB

function scaricaCedolini() {
  if (!prop("UNIPV_USER", "") || !prop("UNIPV_PASSWORD", "")) return;
  const oggi = new Date();
  // Il cedolino esce verso il 23: prima del 18 basta un controllo a settimana.
  if (oggi.getDate() < 18 && oggi.getDay() !== 1 && prop("CEDOLINI_VISTI", "")) return;
  const visti = JSON.parse(prop("CEDOLINI_VISTI", "[]"));
  const token = loginUnipv();
  const auth = { Authorization: "Bearer " + token };
  const anni = [oggi.getFullYear()];
  if (oggi.getMonth() === 0) anni.push(oggi.getFullYear() - 1); // a gennaio anche dicembre
  let nuovi = 0;
  anni.forEach(anno => {
    const r = UrlFetchApp.fetch(UNIPV + "/appced/api/v4/documenti?anno=" + anno + "&tipoDocumento=", { headers: auth, muteHttpExceptions: true });
    if (r.getResponseCode() !== 200) throw new Error("Elenco cedolini → " + r.getResponseCode());
    JSON.parse(r.getContentText()).filter(d => d.tipoDocumento === "CEDOLINO" && visti.indexOf(d.id) < 0).forEach(d => {
      // Stessa richiesta dell'app del portale (che codifica due volte idAllegato).
      const url = UNIPV + "/appced/api/v4/documenti/" + encodeURIComponent(d.id) + "?format=pdf&type=" + encodeURIComponent(d.provenienzaDoc || "hrsuite") +
        (String(d.provenienzaDoc || "").indexOf("hrsuite") >= 0 ? "&doc=" + encodeURIComponent(encodeURIComponent(d.idAllegato)) : "");
      const pdf = UrlFetchApp.fetch(url, { headers: Object.assign({ Accept: "application/pdf; text/plain" }, auth), muteHttpExceptions: true });
      const byte = pdf.getBlob().getBytes();
      if (pdf.getResponseCode() !== 200 || String.fromCharCode.apply(null, byte.slice(0, 4).map(b => (b + 256) % 256)) !== "%PDF")
        throw new Error("Cedolino " + d.anno + "-" + d.mese + " → " + pdf.getResponseCode() + ", non è un PDF");
      if (byte.length > MAX_CEDOLINO) throw new Error("Cedolino " + d.anno + "-" + d.mese + " troppo grande (" + byte.length + " byte)");
      const mese = Number(d.mese);
      creaCedolinoInbox(hashBreve("cedolino|" + d.id), {
        anno: Number(d.anno), mese: mese, descrizione: d.descrizione || d.descrDocumento || "",
        nome: "Cedolino " + d.anno + "-" + String(mese).padStart(2, "0") + ".pdf",
        pubblicato: d.dataPubblicazione || d.dtPubblicazione || "", dati: Utilities.base64Encode(byte), creato: Date.now()
      });
      visti.push(d.id);
      setProp("CEDOLINI_VISTI", JSON.stringify(visti));
      nuovi++;
    });
  });
  setProp("ULTIMI_CEDOLINI", new Date().toISOString());
  return nuovi;
}

function creaCedolinoInbox(id, v) {
  const r = UrlFetchApp.fetch(fsUrl(INBOX_CEDOLINI + "?documentId=" + encodeURIComponent(id)), {
    method: "post",
    headers: { Authorization: "Bearer " + ScriptApp.getOAuthToken() },
    contentType: "application/json",
    payload: JSON.stringify(fsCampi(v)),
    muteHttpExceptions: true
  });
  if (r.getResponseCode() !== 409 && r.getResponseCode() >= 300) throw new Error("Firestore → " + r.getResponseCode() + ": " + r.getContentText().slice(0, 300));
}

// Login SAML (Shibboleth) come farebbe il browser: segue i reindirizzamenti con i
// cookie, compila il modulo di accesso e rimanda le risposte SAML, finché /loginShib
// restituisce il token dell'app (valido circa 2 ore).
function loginUnipv() {
  const sessione = {};
  let pagina = navigaUnipv(sessione, UNIPV + "/loginShib");
  let credenzialiInviate = false, sceltaFatta = false;
  for (let passo = 0; passo < 15; passo++) {
    const tipo = String(intestazione(pagina.r.getHeaders(), "Content-Type") || "");
    const testo = pagina.r.getContentText();
    if (/json/.test(tipo)) {
      const j = JSON.parse(testo);
      if (j.token) return j.token;
      throw new Error("Login UNIPV: risposta senza token");
    }
    const moduli = estraiModuli(testo, pagina.url);
    let modulo = moduli.find(m => "j_username" in m.campi);
    if (modulo) {
      if (credenzialiInviate) throw new Error("Login UNIPV: credenziali rifiutate (controlla UNIPV_USER e UNIPV_PASSWORD)");
      modulo.campi.j_username = prop("UNIPV_USER");
      modulo.campi.j_password = prop("UNIPV_PASSWORD");
      modulo.campi._eventId_proceed = "";
      credenzialiInviate = true;
    } else if (!sceltaFatta && (modulo = moduli.find(m => "_eventId_routing" in m.campi && "auth_ctx" in m.campi))) {
      // Pagina di scelta UNIPV / SPID / CIE: come il pulsante UNIPV, triggerFlow('Password', '', 'internal').
      modulo.campi.auth_ctx = "authn/Password";
      modulo.campi.selected_flow = "internal";
      modulo.campi.spid_idp = "";
      sceltaFatta = true;
    } else {
      modulo = moduli.find(m => "SAMLResponse" in m.campi)
        || moduli.find(m => Object.keys(m.campi).some(k => k.indexOf("shib_idp_ls") === 0))
        || moduli.find(m => "_eventId_proceed" in m.campi);
    }
    if (!modulo) {
      // Tornati sul portale dopo la risposta SAML: ora la sessione c'è.
      if (pagina.url.indexOf(UNIPV) === 0 && pagina.url.indexOf("/loginShib") < 0) { pagina = navigaUnipv(sessione, UNIPV + "/loginShib"); continue; }
      // Descrive la pagina (titolo, moduli e nomi dei campi) per capire cosa manca, senza valori.
      const titolo = ((testo.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "").trim();
      const dettagli = moduli.map(m => m.metodo + " " + m.action.split("?")[0].replace(/^https?:\/\/[^\/]+/, "") + " [" + Object.keys(m.campi).join(",") + "]").join(" | ");
      throw new Error("Login UNIPV: pagina inattesa " + pagina.url.split("?")[0] + " (" + pagina.r.getResponseCode() + ") «" + titolo + "» moduli: " + (dettagli || "nessuno") +
        " testo: " + testo.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300));
    }
    pagina = navigaUnipv(sessione, modulo.action, { method: modulo.metodo, payload: modulo.campi });
  }
  throw new Error("Login UNIPV: troppi passaggi");
}

function navigaUnipv(sessione, url, opts) {
  opts = opts || {};
  let metodo = opts.method || "get", payload = opts.payload;
  for (let i = 0; i < 12; i++) {
    const host = url.match(/^https?:\/\/([^\/?#]+)/)[1];
    const cookie = Object.keys(sessione).filter(d => host === d || host.endsWith("." + d))
      .map(d => Object.keys(sessione[d]).map(n => n + "=" + sessione[d][n]).join("; ")).filter(Boolean).join("; ");
    const r = UrlFetchApp.fetch(url, {
      method: metodo, payload: metodo === "post" ? payload : undefined, followRedirects: false, muteHttpExceptions: true,
      headers: Object.assign({ "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36" }, cookie ? { Cookie: cookie } : {})
    });
    const h = r.getAllHeaders();
    [].concat(intestazione(h, "Set-Cookie") || []).forEach(c => {
      const [coppia] = c.split(";"), eq = coppia.indexOf("=");
      const dominio = ((c.match(/;\s*domain=\.?([^;]+)/i) || [])[1] || host).toLowerCase();
      (sessione[dominio] = sessione[dominio] || {})[coppia.slice(0, eq).trim()] = coppia.slice(eq + 1).trim();
    });
    const codice = r.getResponseCode();
    if ([301, 302, 303, 307, 308].indexOf(codice) < 0) return { r: r, url: url };
    url = indirizzoAssoluto(intestazione(h, "Location"), url);
    if (codice !== 307 && codice !== 308) { metodo = "get"; payload = undefined; }
  }
  throw new Error("Login UNIPV: troppi reindirizzamenti");
}

// Le intestazioni possono arrivare in minuscolo (HTTP/2).
function intestazione(h, nome) {
  const k = Object.keys(h).find(x => x.toLowerCase() === nome.toLowerCase());
  return k ? h[k] : undefined;
}

function estraiModuli(html, base) {
  const moduli = [];
  const reModulo = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = reModulo.exec(html))) {
    const attr = (s, n) => {
      const x = s.match(new RegExp("\\s" + n + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", "i"));
      return x ? decodificaHtml(x[2] !== undefined ? x[2] : x[3] !== undefined ? x[3] : x[4]) : null;
    };
    const campi = {};
    (m[2].match(/<(input|button)\b[^>]*>/gi) || []).forEach(t => {
      const nome = attr(t, "name");
      if (!nome) return;
      const tipo = (attr(t, "type") || "").toLowerCase();
      if ((tipo === "checkbox" || tipo === "radio") && !/\bchecked\b/i.test(t)) return;
      campi[nome] = attr(t, "value") || "";
    });
    moduli.push({ action: indirizzoAssoluto(attr(m[1], "action") || base, base), metodo: (attr(m[1], "method") || "get").toLowerCase(), campi: campi });
  }
  return moduli;
}

function decodificaHtml(s) {
  return s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function indirizzoAssoluto(u, base) {
  if (/^https?:\/\//i.test(u)) return u;
  const origine = base.match(/^https?:\/\/[^\/?#]+/)[0];
  if (u.charAt(0) === "/") return origine + u;
  return base.replace(/[?#].*$/, "").replace(/[^\/]*$/, "") + u;
}

// ---------------------------------------------------------------------------
// Pianificazione e avvisi
// ---------------------------------------------------------------------------

// Da eseguire una volta a mano dall'editor: crea gli avvii automatici.
function installaPianificazione() {
  ScriptApp.getProjectTriggers().forEach(t => ScriptApp.deleteTrigger(t));
  // PSD2: al massimo 4 letture al giorno senza l'utente presente, e ogni
  // sincronizzazione ne usa 2 (saldo e movimenti). Mattina, pomeriggio e sera,
  // niente di notte: resta spazio per il pulsante "Aggiorna saldo".
  [8, 14, 20].forEach(ora => ScriptApp.newTrigger("sincronizzaBper").timeBased().everyDays(1).atHour(ora).create());
  // Le email AMEX si attivano solo dopo aver verificato parseAvvisoAmex su email vere.
  if (prop("AMEX_ATTIVO", "") === "si") ScriptApp.newTrigger("sincronizzaAmexEmail").timeBased().everyHours(1).create();
  ScriptApp.newTrigger("controllaScadenzaConsenso").timeBased().everyDays(1).atHour(8).create();
  ScriptApp.newTrigger("scaricaCedolini").timeBased().everyDays(1).atHour(9).create();
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
