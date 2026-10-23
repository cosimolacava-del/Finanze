// ============================================================
// CASSAFORTE: password e informazioni di famiglia cifrate nel browser.
//
// Su Firestore arrivano solo dati cifrati (AES-GCM 256). La chiave della
// cassaforte è casuale e viene salvata solo "incartata" da una chiave ricavata
// dalla password di ciascuno (PBKDF2-SHA256, 600.000 iterazioni) e dalla chiave
// di recupero. Né Google né lo script BPER possono leggere il contenuto.
// La chiave sbloccata vive solo in memoria e sparisce al blocco o alla chiusura.
// ============================================================
const Cassaforte = (() => {
  const COL = "bilancio_familiare_cassaforte", DOC_CHIAVI = "_chiavi", COL_ALLEGATI = "bilancio_familiare_cassaforte_allegati";
  // Cedolini scaricati dallo script (sync-apps-script), in chiaro finché la cassaforte non li cifra.
  const COL_INBOX = "bilancio_familiare_cassaforte_inbox";
  const MAX_ALLEGATO = 10 * 1024 * 1024, PARTE_ALLEGATO = 512 * 1024;
  const TIPI_ALLEGATO = /^(application\/pdf|image\/(jpeg|png|webp|heic|heif|gif))$/;
  const ITER_PASSWORD = 600000, ITER_RECUPERO = 100000, MIN_PASSWORD = 12;
  const BLOCCO_INATTIVITA = 5 * 60 * 1000, BLOCCO_NASCOSTA = 60 * 1000, PULIZIA_APPUNTI = 30 * 1000;
  const TIPI = {
    login:     { nome: "Accesso",             icona: "&#128273;", campi: ["utente", "password", "url", "note"] },
    conto:     { nome: "Conto / carta",       icona: "&#127974;", campi: ["numero", "utente", "password", "note"] },
    documento: { nome: "Documento",           icona: "&#129706;", campi: ["numero", "scadenza", "note"] },
    contratto: { nome: "Contratto / polizza", icona: "&#128196;", campi: ["numero", "scadenza", "utente", "url", "note"] },
    nota:      { nome: "Nota",                icona: "&#128221;", campi: ["note"] }
  };
  const ETICHETTE = { utente: "Utente / email", password: "Password", url: "Sito", numero: "Numero", scadenza: "Scadenza", note: "Note" };
  const ETICHETTE_TIPO = {
    conto: { numero: "IBAN o numero carta", utente: "Intestatario", password: "PIN / codice" },
    documento: { numero: "Numero documento" },
    contratto: { numero: "Numero contratto o polizza", utente: "Riferimento / contatto" }
  };
  const segreto = (tipo, campo) => campo === "password" || (tipo === "conto" && campo === "numero");
  const etichetta = (tipo, campo) => (ETICHETTE_TIPO[tipo] || {})[campo] || ETICHETTE[campo];

  let chiavi;              // undefined = in caricamento, null = cassaforte da creare
  let erroreCloud = "";
  let chiave = null;       // CryptoKey non estraibile, solo in memoria
  let chiaveModifiche = null, scadenzaModifiche = 0;
  const FINESTRA_MODIFICHE = 3 * 60 * 1000;
  const haPasskey = () => (chiavi?.slots || []).some(s => s.tipo === "passkey");
  const haPassword = () => (chiavi?.slots || []).some(s => s.tipo === "password");
  const voci = new Map();  // id -> voce decifrata (solo mentre è sbloccata)
  let stopChiavi = null, stopVoci = null, codaDecifra = Promise.resolve();
  let vista = vistaIniziale();
  let ultimoUso = Date.now(), nascostaDa = null;

  function vistaIniziale(){ return { modo: "lista", cerca: "", rivela: new Set(), bozza: null, chiaveRecupero: null, messaggio: "", errore: "", attesa: false }; }

  // ---------- crittografia ----------
  const enc = new TextEncoder(), dec = new TextDecoder();
  const casuali = n => crypto.getRandomValues(new Uint8Array(n));
  const b64 = buf => { const u = new Uint8Array(buf); let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); };
  const daB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function chiaveDaSegreto(segretoTesto, salt, iter){
    const base = await crypto.subtle.importKey("raw", enc.encode(segretoTesto), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  }
  async function creaSlot(chiaveEstraibile, segretoTesto, nome, tipo){
    const id = crypto.randomUUID(), salt = casuali(16), iv = casuali(12), iter = tipo === "recupero" ? ITER_RECUPERO : ITER_PASSWORD;
    const kek = await chiaveDaSegreto(segretoTesto, salt, iter);
    const incartata = await crypto.subtle.wrapKey("raw", chiaveEstraibile, kek, { name: "AES-GCM", iv, additionalData: enc.encode("slot:" + id) });
    return { id, nome, tipo, iter, salt: b64(salt), iv: b64(iv), chiave: b64(incartata), creato: Date.now() };
  }
  function apriSlot(slot, segretoTesto, estraibile){
    return chiaveDaSegreto(segretoTesto, daB64(slot.salt), slot.iter).then(kek =>
      crypto.subtle.unwrapKey("raw", daB64(slot.chiave), kek, { name: "AES-GCM", iv: daB64(slot.iv), additionalData: enc.encode("slot:" + slot.id) },
        { name: "AES-GCM" }, estraibile, ["encrypt", "decrypt"]));
  }
  // Prova la password su tutti gli slot "password": ognuno ha la sua.
  async function apriConPassword(password, estraibile){
    for (const slot of (chiavi?.slots || []).filter(s => s.tipo === "password")) {
      try { return { slot, chiave: await apriSlot(slot, password, estraibile) }; } catch (e) { /* password di un altro slot */ }
    }
    throw new Error("Password errata.");
  }
  // ---------- passkey (telefono, impronta, Face ID) ----------
  // Si usa l'estensione WebAuthn "PRF": la passkey, dopo la verifica biometrica,
  // restituisce un segreto di 32 byte legato a un sale nostro. Da quel segreto si
  // ricava la chiave che "incarta" la chiave della cassaforte, come per le password.
  // Il segreto non lascia mai il dispositivo né arriva a Firestore.
  const b64url = buf => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const passkeyDisponibili = () => !!(window.PublicKeyCredential && navigator.credentials);
  async function chiaveDaPrf(segretoPrf){
    const base = await crypto.subtle.importKey("raw", segretoPrf, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("cassaforte-passkey") },
      base, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  }
  function erroreWebAuthn(err){
    if (err && err.name === "NotAllowedError") return new Error("Operazione annullata o scaduta.");
    return err instanceof Error ? err : new Error(String(err));
  }
  async function segretoDaPasskey(slots){
    const valutazioni = {};
    slots.forEach(s => { valutazioni[b64url(daB64(s.credId))] = { first: daB64(s.prfSalt) }; });
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: {
        challenge: casuali(32), rpId: location.hostname, userVerification: "required", timeout: 120000,
        allowCredentials: slots.map(s => ({ type: "public-key", id: daB64(s.credId) })),
        extensions: { prf: { evalByCredential: valutazioni } } } });
    } catch (err) { throw erroreWebAuthn(err); }
    const slot = slots.find(s => s.credId === b64(cred.rawId));
    const segretoPrf = cred.getClientExtensionResults().prf?.results?.first;
    if (!slot || !segretoPrf) throw new Error("Questa passkey non ha restituito il segreto: il dispositivo o il browser non supportano PRF.");
    return { slot, segretoPrf };
  }
  async function apriConPasskey(estraibile){
    const slots = (chiavi?.slots || []).filter(s => s.tipo === "passkey");
    if (!slots.length) throw new Error("Nessuna passkey registrata.");
    const { slot, segretoPrf } = await segretoDaPasskey(slots);
    const kek = await chiaveDaPrf(segretoPrf);
    try {
      return { slot, chiave: await crypto.subtle.unwrapKey("raw", daB64(slot.chiave), kek, { name: "AES-GCM", iv: daB64(slot.iv), additionalData: enc.encode("slot:" + slot.id) },
        { name: "AES-GCM" }, estraibile, ["encrypt", "decrypt"]) };
    } catch (err) { throw new Error("Passkey non valida per questa cassaforte."); }
  }
  async function creaSlotPasskey(chiaveEstraibile, nome){
    if (!passkeyDisponibili()) throw new Error("Questo browser non supporta le passkey.");
    const prfSalt = casuali(32);
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: {
        challenge: casuali(32), timeout: 120000,
        rp: { name: "Bilancio Familiare – Cassaforte", id: location.hostname },
        user: { id: casuali(16), name: `${nome} – Cassaforte`, displayName: `${nome} – Cassaforte` },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        extensions: { prf: { eval: { first: prfSalt } } } } });
    } catch (err) { throw erroreWebAuthn(err); }
    const ext = cred.getClientExtensionResults().prf;
    if (!ext || ext.enabled === false) throw new Error("Passkey creata, ma questo dispositivo non supporta PRF: non può proteggere la cassaforte. Puoi cancellarla dal gestore delle password.");
    const slotBase = { credId: b64(cred.rawId), prfSalt: b64(prfSalt) };
    // Alcuni dispositivi danno il segreto solo a un accesso successivo: lo chiediamo subito.
    let segretoPrf = ext.results?.first;
    if (!segretoPrf) segretoPrf = (await segretoDaPasskey([slotBase])).segretoPrf;
    const id = crypto.randomUUID(), iv = casuali(12);
    const incartata = await crypto.subtle.wrapKey("raw", chiaveEstraibile, await chiaveDaPrf(segretoPrf), { name: "AES-GCM", iv, additionalData: enc.encode("slot:" + id) });
    return { id, nome, tipo: "passkey", ...slotBase, iv: b64(iv), chiave: b64(incartata), creato: Date.now() };
  }

  async function nonEstraibile(chiaveEstraibile){
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", chiaveEstraibile));
    const k = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    raw.fill(0);
    return k;
  }
  // L'id del documento entra nei dati autenticati: un testo cifrato non può
  // essere spostato su un'altra voce senza che la decifratura fallisca.
  async function cifra(obj, id){
    const iv = casuali(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("voce:" + id) }, chiave, enc.encode(JSON.stringify(obj)));
    return { v: 1, iv: b64(iv), ct: b64(ct), aggiornato: Date.now() };
  }
  async function decifra(d, id){
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: daB64(d.iv), additionalData: enc.encode("voce:" + id) }, chiave, daB64(d.ct));
    return JSON.parse(dec.decode(pt));
  }

  // Chiave di recupero: 32 caratteri (160 bit) senza lettere ambigue.
  const ALFABETO_RECUPERO = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const nuovaChiaveRecupero = () => [...casuali(32)].map(b => ALFABETO_RECUPERO[b & 31]).join("").match(/.{4}/g).join("-");
  const normalizzaRecupero = s => String(s).toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1").replace(/[^0-9A-Z]/g, "").match(/.{1,4}/g)?.join("-") || "";

  function generaPassword(lunghezza = 20){
    const caratteri = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?";
    const limite = 256 - (256 % caratteri.length);
    let out = "";
    while (out.length < lunghezza) for (const b of casuali(lunghezza * 2)) if (b < limite && out.length < lunghezza) out += caratteri[b % caratteri.length];
    return out;
  }

  // ---------- Firestore ----------
  const col = () => db.collection(COL);

  // ---------- allegati ----------
  // Ogni file è cifrato a pezzi da 512 KB, un documento per pezzo, in una
  // collezione a parte: così non si scaricano finché non li apri. L'id del pezzo
  // ("<allegato>_<n>") entra nei dati autenticati, e il numero di pezzi sta
  // nella voce cifrata: pezzi scambiati o mancanti vengono scoperti.
  const colAllegati = () => db.collection(COL_ALLEGATI);
  const dimensioneLeggibile = n => n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1).replace(".0", "").replace(".", ",")} MB`;
  async function caricaAllegato(file, avanzamento){
    if (!TIPI_ALLEGATO.test(file.type)) throw new Error(`“${file.name}”: si possono allegare solo PDF e immagini.`);
    if (file.size > MAX_ALLEGATO) throw new Error(`“${file.name}” supera ${dimensioneLeggibile(MAX_ALLEGATO)}.`);
    return cifraAllegato(file.name, file.type, new Uint8Array(await file.arrayBuffer()), avanzamento);
  }
  async function cifraAllegato(nome, tipo, dati, avanzamento){
    const id = crypto.randomUUID();
    const parti = Math.max(1, Math.ceil(dati.length / PARTE_ALLEGATO));
    for (let i = 0; i < parti; i++) {
      const docId = `${id}_${i}`, iv = casuali(12);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("allegato:" + docId) }, chiave, dati.subarray(i * PARTE_ALLEGATO, (i + 1) * PARTE_ALLEGATO));
      await colAllegati().doc(docId).set({ v: 1, iv: b64(iv), ct: b64(ct), aggiornato: Date.now() });
      avanzamento && avanzamento(i + 1, parti);
    }
    return { id, nome, tipo, dimensione: dati.length, parti };
  }
  async function leggiAllegato(a){
    const pezzi = [];
    for (let i = 0; i < a.parti; i++) {
      const docId = `${a.id}_${i}`, d = await colAllegati().doc(docId).get();
      if (!d.exists) throw new Error(`Allegato “${a.nome}” incompleto.`);
      const { iv, ct } = d.data();
      try { pezzi.push(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: daB64(iv), additionalData: enc.encode("allegato:" + docId) }, chiave, daB64(ct)))); }
      catch (err) { throw new Error(`Allegato “${a.nome}” illeggibile.`); }
    }
    return new Blob(pezzi, { type: a.tipo });
  }
  function eliminaAllegati(elenco){
    return Promise.all((elenco || []).flatMap(a => Array.from({ length: a.parti }, (_, i) => colAllegati().doc(`${a.id}_${i}`).delete())));
  }
  // La finestra si apre subito, al clic: aprirla dopo l'attesa la farebbe bloccare dal browser.
  async function apriAllegato(a){
    const finestra = window.open("", "_blank");
    try {
      const url = URL.createObjectURL(await leggiAllegato(a));
      if (finestra) finestra.location.href = url;
      else { const link = document.createElement("a"); link.href = url; link.download = a.nome; document.body.appendChild(link); link.click(); link.remove(); }
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (err) { if (finestra) finestra.close(); throw err; }
  }

  function avvia(){
    if (stopChiavi || !cloudReady || !db) return;
    stopChiavi = col().doc(DOC_CHIAVI).onSnapshot(d => {
      chiavi = d.exists ? d.data() : null;
      erroreCloud = "";
      ridisegna();
    }, e => {
      erroreCloud = e && e.code === "permission-denied"
        ? "Firestore non permette ancora l'accesso alla cassaforte: vanno aggiornate le regole di sicurezza."
        : "Cassaforte non raggiungibile: " + (e && e.message);
      stopChiavi = null;
      ridisegna();
    });
  }
  // Dal movimento "Stipendio Cosimo" del bilancio: apre il cedolino del mese se la
  // cassaforte è aperta, altrimenti lo propone appena la si sblocca.
  let cedolinoRichiesto = null;
  const nomeCedolino = (anno, mese) => `Cedolino ${anno}-${String(mese).padStart(2, "0")}.pdf`;
  const trovaCedolino = (anno, mese) => {
    const voce = [...voci.values()].find(v => v.raccolta === "cedolini-unipv-" + anno);
    return voce && (voce.allegati || []).find(a => a.nome === nomeCedolino(anno, mese));
  };
  function apriCedolino(anno, mese){
    const a = chiave && trovaCedolino(anno, mese);
    if (a) return apriAllegato(a).catch(err => { alert(err.message); });
    cedolinoRichiesto = { anno, mese };
    state.tab = "cassaforte";
    render();
  }
  function bannerCedolino(){
    if (!cedolinoRichiesto) return "";
    const { anno, mese } = cedolinoRichiesto, etichettaMese = `${MESI[mese - 1].toLowerCase()} ${anno}`;
    if (trovaCedolino(anno, mese)) return `<p class="cf-ok">${pulsante("apriCedolinoRichiesto", `&#128196; Apri il cedolino di ${etichettaMese}`)}</p>`;
    if (importazioneCedolini) return `<p class="sub">Cerco il cedolino di ${etichettaMese}…</p>`;
    return `<p class="cf-errore">Il cedolino di ${etichettaMese} non è ancora in Cassaforte.</p>`;
  }

  // Una voce per anno ("Cedolini UNIPV 2026"), riconosciuta dal campo raccolta.
  let importazioneCedolini = null;
  function importaCedolini(){
    if (importazioneCedolini || !chiave) return importazioneCedolini;
    importazioneCedolini = (async () => {
      const snap = await db.collection(COL_INBOX).get();
      let importati = 0;
      for (const d of snap.docs) {
        if (!chiave) break;
        const c = d.data(), raccolta = "cedolini-unipv-" + c.anno;
        const allegato = await cifraAllegato(c.nome, "application/pdf", daB64(c.dati));
        const voce = [...voci.values()].find(v => v.raccolta === raccolta);
        const vid = voce ? voce.id : crypto.randomUUID();
        const dati = voce ? { ...voce } : { tipo: "nota", titolo: `Cedolini UNIPV ${c.anno}`, raccolta, creato: Date.now(),
          note: "Scaricati in automatico dal portale U-Web dell'Università di Pavia." };
        delete dati.id;
        dati.allegati = (dati.allegati || []).concat(allegato).sort((a, b) => String(a.nome).localeCompare(String(b.nome)));
        dati.modificato = Date.now();
        await col().doc(vid).set(await cifra(dati, vid));
        voci.set(vid, { id: vid, ...dati });
        // Solo ora, con il cedolino cifrato al sicuro, si cancella la copia in chiaro.
        await db.collection(COL_INBOX).doc(d.id).delete();
        importati++;
      }
      if (importati && !vista.bozza) { vista.messaggio = importati === 1 ? "1 cedolino nuovo aggiunto." : `${importati} cedolini nuovi aggiunti.`; ridisegna(); }
    })().catch(err => { console.error("Importazione cedolini", err); }).finally(() => { importazioneCedolini = null; ridisegna(); });
    return importazioneCedolini;
  }
  function ascoltaVoci(){
    if (stopVoci) return;
    let primaLettura = true;
    stopVoci = col().onSnapshot(snap => {
      const cambi = snap.docChanges().filter(c => c.doc.id !== DOC_CHIAVI);
      codaDecifra = codaDecifra.then(async () => {
        for (const c of cambi) {
          if (!chiave) return;
          if (c.type === "removed") { voci.delete(c.doc.id); continue; }
          try { voci.set(c.doc.id, { id: c.doc.id, ...(await decifra(c.doc.data(), c.doc.id)) }); }
          catch (e) { voci.set(c.doc.id, { id: c.doc.id, illeggibile: true, titolo: "Voce illeggibile" }); }
        }
        ridisegna();
        // Le voci servono già decifrate, per aggiungere i cedolini a quella dell'anno.
        if (primaLettura) { primaLettura = false; importaCedolini(); }
      });
    }, e => { erroreCloud = "Lettura delle voci non riuscita: " + (e && e.message); ridisegna(); });
  }
  async function aggiornaSlot(modifica){
    const ref = col().doc(DOC_CHIAVI);
    await db.runTransaction(async tx => {
      const d = await tx.get(ref);
      if (!d.exists) throw new Error("Cassaforte non trovata.");
      tx.update(ref, { slots: modifica(d.data().slots || []), aggiornato: Date.now() });
    });
  }

  // Per qualche minuto dopo lo sblocco le modifiche agli accessi (nuova persona,
  // passkey, chiave di recupero) non chiedono di riconfermare l'identità.
  async function sblocca(kEstraibile){
    chiave = await nonEstraibile(kEstraibile); vista = vistaIniziale(); ultimoUso = Date.now();
    chiaveModifiche = kEstraibile; scadenzaModifiche = Date.now() + FINESTRA_MODIFICHE;
    ascoltaVoci();
  }
  async function confermaIdentita(password){
    if (chiaveModifiche && Date.now() < scadenzaModifiche) return chiaveModifiche;
    if (password) return (await apriConPassword(password, true)).chiave;
    if (haPasskey()) return (await apriConPasskey(true)).chiave;
    throw new Error("Scrivi la tua password attuale per confermare.");
  }
  function blocca(){
    // Allegati caricati in una modifica mai salvata: non servono più.
    if (vista.nuoviAllegati && vista.nuoviAllegati.length) eliminaAllegati(vista.nuoviAllegati).catch(() => {});
    chiave = null; chiaveModifiche = null;
    if (stopVoci) { stopVoci(); stopVoci = null; }
    voci.clear();
    vista = vistaIniziale();
    ridisegna(true);
  }

  // Si ridisegna solo se la scheda è aperta e non c'è un modulo a metà.
  function ridisegna(forza){
    if (typeof state === "undefined" || state.tab !== "cassaforte") return;
    if (!forza && vista.bozza && vista.modo === "modifica") return;
    render();
  }

  // ---------- blocco automatico ----------
  ["pointerdown", "keydown", "wheel", "touchstart"].forEach(ev => document.addEventListener(ev, () => { ultimoUso = Date.now(); }, { passive: true }));
  document.addEventListener("visibilitychange", () => { nascostaDa = document.hidden ? Date.now() : null; });
  setInterval(() => {
    if (!chiave) return;
    const ora = Date.now();
    if (ora - ultimoUso > BLOCCO_INATTIVITA || (nascostaDa && ora - nascostaDa > BLOCCO_NASCOSTA)) blocca();
  }, 10000);

  // ---------- interfaccia ----------
  const e = s => escapeHtml(s ?? "");
  const pulsante = (azione, testo, extra = "") => `<button class="range-btn" data-cf="${azione}" ${extra}>${testo}</button>`;
  const campoPassword = (nome, etichettaTesto, auto = "off") =>
    `<label class="cf-campo"><span>${etichettaTesto}</span><input type="password" data-cf-input="${nome}" autocomplete="${auto}" autocapitalize="off" spellcheck="false"></label>`;
  const avviso = () => (vista.errore ? `<p class="cf-errore">${e(vista.errore)}</p>` : "") + (vista.messaggio ? `<p class="cf-ok">${e(vista.messaggio)}</p>` : "");
  const intestazione = (destra = "") => `<div class="card-title-row"><h3 style="margin-bottom:0">&#128274; Cassaforte</h3><div style="display:flex;gap:6px;flex-wrap:wrap">${destra}</div></div>`;

  function renderVista(){
    avvia();
    if (!cloudReady) return `<div class="card">${intestazione()}<p class="sub">Accedi all'app per usare la cassaforte.</p></div>`;
    if (erroreCloud) return `<div class="card">${intestazione()}<p class="cf-errore">${e(erroreCloud)}</p></div>`;
    if (chiavi === undefined) return `<div class="card">${intestazione()}<p class="sub">Caricamento…</p></div>`;
    if (vista.chiaveRecupero) return renderChiaveRecupero();
    if (chiavi === null) return renderCreazione();
    if (!chiave) return renderSblocco();
    if (vista.modo === "modifica") return renderModifica();
    if (vista.modo === "impostazioni") return renderImpostazioni();
    return renderLista();
  }

  function renderCreazione(){
    return `<div class="card cf">${intestazione()}
      <p class="sub">Qui puoi tenere password, codici e dati importanti della famiglia. Tutto viene cifrato su questo dispositivo prima di essere salvato: senza il tuo accesso nessuno può leggerlo, neanche Google.</p>
      <div class="cf-form">
        <label class="cf-campo"><span>Il tuo nome</span><input type="text" data-cf-input="nome" value="Cosimo" autocomplete="off"></label>
      </div>
      ${passkeyDisponibili() ? `
      <p class="sub"><b>Consigliato: con impronta o Face ID.</b> Il telefono crea una passkey, salvata nel gestore delle password di Google o iCloud. Sul PC la usi inquadrando il QR code col telefono. Niente password da ricordare.</p>
      ${avviso()}
      <button class="add-btn" data-cf="creaPasskey" ${vista.attesa ? "disabled" : ""}>${vista.attesa ? "Creazione…" : "&#128241; Crea con impronta / Face ID"}</button>
      <h4 style="margin:22px 0 6px">Oppure con una password</h4>` : avviso()}
      <p class="sub">Almeno ${MIN_PASSWORD} caratteri; va bene una frase di 4-5 parole. Non salvarla nel browser e non usarla altrove.</p>
      <div class="cf-form">
        ${campoPassword("password", "Password della cassaforte", "new-password")}
        ${campoPassword("conferma", "Ripeti la password", "new-password")}
      </div>
      <button class="${passkeyDisponibili() ? "range-btn" : "add-btn"}" data-cf="crea" ${vista.attesa ? "disabled" : ""}>Crea con password</button>
      <p class="sub" style="margin-top:14px">In entrambi i casi ricevi subito una chiave di recupero da scrivere su carta: serve se perdi il telefono o dimentichi la password.</p>
    </div>`;
  }

  function renderChiaveRecupero(){
    return `<div class="card cf">${intestazione()}
      <h4 style="margin:6px 0">Chiave di recupero</h4>
      <p class="sub">Scrivila su carta e conservala in un posto sicuro in casa. Serve se perdi il telefono o dimentichi la password: senza un accesso e senza questa chiave i dati sono persi per sempre. Non verrà più mostrata.</p>
      <div class="cf-recupero">${e(vista.chiaveRecupero)}</div>
      <label style="display:flex;gap:8px;align-items:center;margin:12px 0"><input type="checkbox" data-cf-input="presaNota"> L'ho scritta e conservata</label>
      ${avviso()}
      <button class="add-btn" data-cf="chiudiRecupero">Continua</button>
    </div>`;
  }

  function renderSblocco(){
    const recupero = vista.modo === "recupero";
    const nomi = [...new Set((chiavi.slots || []).filter(s => s.tipo !== "recupero").map(s => s.nome))];
    const conPasskey = passkeyDisponibili() && haPasskey();
    const attesa = vista.attesa ? "disabled" : "";
    if (recupero) return `<div class="card cf">${intestazione()}
        <p class="sub">Per riavere l'accesso: scrivi chi sei e la chiave di recupero, poi crea una nuova passkey${passkeyDisponibili() ? " oppure una nuova password" : ""}.</p>
        <div class="cf-form">
          <label class="cf-campo"><span>Il tuo nome</span><input type="text" data-cf-input="nome" list="cfNomiRec" value="${e(nomi[0] || "")}" autocomplete="off"><datalist id="cfNomiRec">${nomi.map(n => `<option value="${e(n)}">`).join("")}</datalist></label>
          <label class="cf-campo"><span>Chiave di recupero</span><input type="text" data-cf-input="recupero" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
        </div>
        ${avviso()}
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${passkeyDisponibili() ? `<button class="add-btn" data-cf="recuperaNuovaPasskey" ${attesa}>&#128241; Recupera e crea una nuova passkey</button>` : ""}
          ${pulsante("annullaRecupero", "Annulla")}</div>
        <h4 style="margin:22px 0 6px">Oppure imposta una nuova password</h4>
        <div class="cf-form">
          ${campoPassword("password", "Nuova password", "new-password")}
          ${campoPassword("conferma", "Ripeti la nuova password", "new-password")}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${pulsante("recupera", "Recupera con la chiave e imposta la password", attesa)}
          ${conPasskey && haPassword() ? pulsante("recuperaPasskey", "&#128241; Conferma con la passkey invece della chiave", attesa) : ""}</div>
      </div>`;
    return `<div class="card cf">${intestazione()}
        <p class="sub">La cassaforte è bloccata. Si blocca da sola dopo 5 minuti di inattività.</p>
        ${avviso()}
        ${conPasskey ? `<button class="add-btn" data-cf="sbloccaPasskey" ${attesa} style="margin-bottom:12px">${vista.attesa ? "Sblocco…" : "&#128241; Apri con impronta / Face ID"}</button>` : ""}
        ${haPassword() ? `<div class="cf-form">${campoPassword("password", conPasskey ? "Oppure con la password" : "Password", "current-password")}</div>
        <button class="${conPasskey ? "range-btn" : "add-btn"}" data-cf="sblocca" ${attesa}>${vista.attesa && !conPasskey ? "Sblocco…" : "Sblocca con password"}</button>` : ""}
        ${!conPasskey && !haPassword() ? `<p class="cf-errore">Questo browser non supporta le passkey: usa un altro dispositivo o la chiave di recupero.</p>` : ""}
        <p style="margin:14px 0 0"><a href="#" data-cf="mostraRecupero" class="sub">Non riesco ad accedere</a></p>
    </div>`;
  }

  function giorniA(data){ return Math.round((new Date(data + "T00:00:00") - new Date(new Date().toDateString())) / 86400000); }
  function badgeScadenza(v){
    if (!v.scadenza) return "";
    const g = giorniA(v.scadenza), data = new Date(v.scadenza + "T00:00:00").toLocaleDateString("it-IT");
    if (g < 0) return `<span class="cf-badge rust">scaduto il ${data}</span>`;
    if (g <= 60) return `<span class="cf-badge gold">scade il ${data}</span>`;
    return `<span class="cf-badge">scade il ${data}</span>`;
  }

  function renderLista(){
    const q = vista.cerca.trim().toLowerCase();
    const elenco = [...voci.values()]
      .filter(v => !q || [v.titolo, v.utente, v.url, v.note, TIPI[v.tipo]?.nome, ...(v.allegati || []).map(a => a.nome)].some(x => String(x || "").toLowerCase().includes(q)))
      .sort((a, b) => String(a.titolo || "").localeCompare(String(b.titolo || ""), "it"));
    const righe = elenco.map(v => {
      const t = TIPI[v.tipo] || TIPI.nota;
      const campi = t.campi.filter(c => c !== "note" && c !== "scadenza" && v[c]).map(c => {
        const visibile = !segreto(v.tipo, c) || vista.rivela.has(v.id + ":" + c);
        const valore = c === "url" && /^https?:\/\//i.test(v.url)
          ? `<a href="${e(v.url)}" target="_blank" rel="noopener noreferrer">${e(v.url)}</a>`
          : `<span class="cf-valore">${visibile ? e(v[c]) : "••••••••"}</span>`;
        return `<div class="cf-riga"><span class="cf-etichetta">${e(etichetta(v.tipo, c))}</span>${valore}
          ${segreto(v.tipo, c) ? pulsante("rivela", visibile ? "Nascondi" : "Mostra", `data-id="${e(v.id)}" data-campo="${c}"`) : ""}
          ${c !== "url" ? pulsante("copia", "Copia", `data-id="${e(v.id)}" data-campo="${c}"`) : ""}</div>`;
      }).join("");
      return `<div class="cf-voce">
        <div class="cf-voce-testa"><div><b>${t.icona} ${e(v.titolo)}</b> <span class="sub">${e(t.nome)}</span> ${badgeScadenza(v)}</div>
          ${v.illeggibile ? "" : pulsante("modifica", "&#9998; Modifica", `data-id="${e(v.id)}"`)}</div>
        ${campi}
        ${(v.allegati || []).length ? `<div class="cf-riga"><span class="cf-etichetta">&#128206; Allegati</span><span style="display:flex;gap:6px;flex-wrap:wrap;flex:1 1 140px;min-width:0">
          ${v.allegati.map(a => pulsante("apriAllegato", `${e(a.nome)} <span class="sub">${dimensioneLeggibile(a.dimensione)}</span>`, `data-id="${e(v.id)}" data-allegato="${e(a.id)}" style="max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"`)).join("")}</span></div>` : ""}
        ${v.note ? `<div class="cf-note">${e(v.note)}</div>` : ""}
      </div>`;
    }).join("");
    return `<div class="card cf">${intestazione(pulsante("nuova", "+ Nuova voce") + pulsante("impostazioni", "&#9881; Impostazioni") + pulsante("blocca", "&#128274; Blocca"))}
      ${avviso()}
      ${bannerCedolino()}
      <input class="cf-cerca" data-cf-input="cerca" placeholder="Cerca…" value="${e(vista.cerca)}" autocomplete="off">
      ${righe || `<p class="sub">${voci.size ? "Nessuna voce corrisponde alla ricerca." : "Ancora nessuna voce. Aggiungi la prima con “+ Nuova voce”."}</p>`}
    </div>`;
  }

  function renderModifica(){
    const b = vista.bozza, t = TIPI[b.tipo] || TIPI.nota;
    const campo = c => {
      if (c === "note") return `<label class="cf-campo cf-largo"><span>${e(etichetta(b.tipo, c))}</span><textarea data-cf-campo="note" rows="4">${e(b.note)}</textarea></label>`;
      if (c === "scadenza") return `<label class="cf-campo"><span>${e(etichetta(b.tipo, c))}</span><input type="date" data-cf-campo="scadenza" value="${e(b.scadenza)}"></label>`;
      const nascosto = segreto(b.tipo, c) && !vista.rivela.has("bozza:" + c);
      return `<label class="cf-campo"><span>${e(etichetta(b.tipo, c))}</span><span style="display:flex;gap:6px">
        <input type="${nascosto ? "password" : "text"}" data-cf-campo="${c}" value="${e(b[c])}" autocomplete="off" autocapitalize="off" spellcheck="false" style="flex:1;min-width:0">
        ${segreto(b.tipo, c) ? pulsante("rivelaBozza", nascosto ? "Mostra" : "Nascondi", `data-campo="${c}"`) : ""}
        ${c === "password" ? pulsante("genera", "Genera") : ""}</span></label>`;
    };
    return `<div class="card cf">${intestazione(pulsante("blocca", "&#128274; Blocca"))}
      <h4 style="margin:6px 0">${b.id ? "Modifica voce" : "Nuova voce"}</h4>
      <div class="cf-form">
        <label class="cf-campo"><span>Tipo</span><select data-cf-campo="tipo">${Object.entries(TIPI).map(([k, x]) => `<option value="${k}" ${k === b.tipo ? "selected" : ""}>${x.nome}</option>`).join("")}</select></label>
        <label class="cf-campo"><span>Titolo</span><input type="text" data-cf-campo="titolo" value="${e(b.titolo)}" autocomplete="off" placeholder="es. Home banking BPER"></label>
        ${t.campi.map(campo).join("")}
      </div>
      <h4 style="margin:6px 0">&#128206; Allegati</h4>
      ${(b.allegati || []).map(a => `<div class="cf-riga"><span class="cf-valore" style="font-family:inherit">${e(a.nome)} <span class="sub">${dimensioneLeggibile(a.dimensione)}</span></span>
        ${pulsante("apriAllegato", "Apri", `data-allegato="${e(a.id)}"`)}${pulsante("rimuoviAllegato", "Rimuovi", `data-allegato="${e(a.id)}"`)}</div>`).join("")}
      <label class="range-btn" style="display:inline-block;margin:6px 0 12px;cursor:pointer">+ Aggiungi PDF o foto
        <input type="file" data-cf-file accept="application/pdf,image/*" multiple style="display:none" ${vista.attesa ? "disabled" : ""}></label>
      <span class="sub">fino a ${dimensioneLeggibile(MAX_ALLEGATO)} ciascuno, cifrati come il resto</span>
      <p class="sub" id="cfAvanzamento" style="margin:4px 0"></p>
      ${avviso()}
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:space-between">
        <div style="display:flex;gap:8px"><button class="add-btn" data-cf="salva" ${vista.attesa ? "disabled" : ""}>Salva</button>${pulsante("annulla", "Annulla")}</div>
        ${b.id ? `<button class="range-btn" data-cf="elimina" style="color:var(--rust)">Elimina</button>` : ""}
      </div>
    </div>`;
  }

  function renderImpostazioni(){
    const slots = chiavi.slots || [];
    const accessi = slots.filter(s => s.tipo !== "recupero");
    const nomi = [...new Set(accessi.map(s => s.nome))];
    const descrizione = s => s.tipo === "recupero" ? "Chiave di recupero" : (s.tipo === "passkey" ? "Passkey di " : "Password di ") + e(s.nome);
    const elenco = slots.map(s => `<div class="cf-riga"><span class="cf-etichetta">${descrizione(s)}</span>
      <span class="sub">creata il ${new Date(s.creato).toLocaleDateString("it-IT")}</span>
      ${s.tipo !== "recupero" && accessi.length > 1 ? pulsante("rimuoviSlot", "Rimuovi", `data-id="${e(s.id)}"`) : ""}</div>`).join("");
    // Subito dopo lo sblocco non serve riconfermare; poi si conferma con password o passkey.
    const confermaRecente = chiaveModifiche && Date.now() < scadenzaModifiche;
    const campoConferma = nome => confermaRecente || !haPassword() ? ""
      : campoPassword(nome, haPasskey() ? "La tua password attuale (o lascia vuoto e conferma con la passkey)" : "La tua password attuale", "current-password");
    const notaConferma = confermaRecente ? "Hai appena aperto la cassaforte: non serve riconfermare."
      : haPassword() ? "Per confermare serve la password di chi fa la modifica" + (haPasskey() ? ", oppure la sua passkey." : ".") : "Per confermare ti verrà chiesta la tua passkey.";
    return `<div class="card cf">${intestazione(pulsante("lista", "&larr; Torna alle voci") + pulsante("blocca", "&#128274; Blocca"))}
      ${avviso()}
      <h4 style="margin:6px 0">Chi può aprire la cassaforte</h4>
      ${elenco}
      <datalist id="cfNomi">${nomi.map(n => `<option value="${e(n)}">`).join("")}</datalist>
      <h4 style="margin:18px 0 6px">&#128241; Passkey (impronta / Face ID)</h4>
      <p class="sub">Ognuno può avere la sua. La passkey resta sul dispositivo dove la crei (e nel suo gestore delle password Google o iCloud): <b>per Chiara, falla sul suo telefono</b>. Apri lì la cassaforte con la tua passkey inquadrando il QR code col tuo telefono, poi aggiungi la sua. ${notaConferma}</p>
      ${passkeyDisponibili() ? `<div class="cf-form">
        <label class="cf-campo"><span>Di chi è la passkey</span><input type="text" data-cf-input="nomePasskey" list="cfNomi" autocomplete="off" placeholder="es. Chiara"></label>
        ${campoConferma("attualePasskey")}
      </div>
      ${pulsante("aggiungiPasskey", "Aggiungi passkey su questo dispositivo", vista.attesa ? "disabled" : "")}` : `<p class="cf-errore">Questo browser non supporta le passkey.</p>`}
      <h4 style="margin:18px 0 6px">Password (facoltativa)</h4>
      <p class="sub">Utile su un dispositivo che non supporta le passkey. Scrivi un nome esistente per cambiarne la password. ${notaConferma}</p>
      <div class="cf-form">
        <label class="cf-campo"><span>Nome</span><input type="text" data-cf-input="nome" list="cfNomi" autocomplete="off" placeholder="es. Chiara"></label>
        ${campoConferma("attuale")}
        ${campoPassword("password", "Nuova password", "new-password")}
        ${campoPassword("conferma", "Ripeti la nuova password", "new-password")}
      </div>
      <button class="range-btn" data-cf="salvaSlot" ${vista.attesa ? "disabled" : ""}>Salva password</button>
      <h4 style="margin:18px 0 6px">Chiave di recupero</h4>
      <p class="sub">Se l'hai persa o pensi che qualcuno l'abbia vista, generane una nuova: quella vecchia smette di funzionare.</p>
      <div class="cf-form">${campoConferma("attualeRecupero")}</div>
      ${pulsante("nuovoRecupero", "Genera nuova chiave di recupero")}
      <h4 style="margin:18px 0 6px">Copia di sicurezza</h4>
      <p class="sub">Scarica un file con tutte le voci, ancora cifrate: senza password o chiave di recupero è illeggibile.</p>
      ${pulsante("esporta", "Scarica copia cifrata")}
    </div>`;
  }

  // ---------- azioni ----------
  const valoreInput = nome => (document.querySelector(`[data-cf-input="${nome}"]`) || {}).value || "";
  function passwordValida(p, c){
    if (p.length < MIN_PASSWORD) return `La password deve avere almeno ${MIN_PASSWORD} caratteri.`;
    if (p !== c) return "Le due password non coincidono.";
    return "";
  }
  async function conAttesa(fn){
    vista.errore = ""; vista.messaggio = ""; vista.attesa = true; render();
    try { await fn(); }
    catch (err) { vista.errore = err.message || String(err); }
    finally { vista.attesa = false; render(); }
  }

  async function crea(conPasskey){
    const nome = valoreInput("nome").trim() || "Cosimo", password = valoreInput("password");
    const errore = conPasskey ? "" : passwordValida(password, valoreInput("conferma"));
    if (errore) { vista.errore = errore; return render(); }
    await conAttesa(async () => {
      const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const recupero = nuovaChiaveRecupero();
      const accesso = conPasskey ? await creaSlotPasskey(k, nome) : await creaSlot(k, password, nome, "password");
      const slots = [accesso, await creaSlot(k, recupero, "Chiave di recupero", "recupero")];
      const ref = col().doc(DOC_CHIAVI);
      // In transazione: non sovrascrive una cassaforte creata nel frattempo da un altro dispositivo.
      await db.runTransaction(async tx => {
        if ((await tx.get(ref)).exists) throw new Error("La cassaforte esiste già: ricarica la pagina.");
        tx.set(ref, { versione: 1, slots, creato: Date.now(), aggiornato: Date.now() });
      });
      await sblocca(k);
      vista.chiaveRecupero = recupero;
    });
  }
  async function chiaveDaRecupero(codice){
    const slotRec = (chiavi.slots || []).find(s => s.tipo === "recupero");
    try { return await apriSlot(slotRec, normalizzaRecupero(codice), true); }
    catch (err) { throw new Error("Chiave di recupero errata."); }
  }

  async function azione(nome, el){
    ultimoUso = Date.now();
    if (nome === "crea") return crea(false);
    if (nome === "creaPasskey") return crea(true);
    if (nome === "chiudiRecupero") {
      if (!(document.querySelector('[data-cf-input="presaNota"]') || {}).checked) { vista.errore = "Conferma di averla scritta prima di continuare."; return render(); }
      vista.chiaveRecupero = null; vista.errore = ""; return render();
    }
    if (nome === "sblocca") {
      const password = valoreInput("password");
      return conAttesa(async () => { await sblocca((await apriConPassword(password, true)).chiave); });
    }
    if (nome === "sbloccaPasskey") return conAttesa(async () => { await sblocca((await apriConPasskey(true)).chiave); });
    if (nome === "mostraRecupero") { vista.modo = "recupero"; vista.errore = ""; return render(); }
    if (nome === "annullaRecupero") { vista = vistaIniziale(); return render(); }
    if (nome === "recupera" || nome === "recuperaPasskey" || nome === "recuperaNuovaPasskey") {
      // I campi si leggono prima di conAttesa, che ridisegna il modulo.
      const persona = valoreInput("nome").trim(), password = valoreInput("password"), codice = valoreInput("recupero");
      if (!persona) { vista.errore = "Scrivi il tuo nome."; return render(); }
      const errore = nome === "recuperaNuovaPasskey" ? "" : passwordValida(password, valoreInput("conferma"));
      if (errore) { vista.errore = errore; return render(); }
      return conAttesa(async () => {
        const k = nome === "recuperaPasskey" ? (await apriConPasskey(true)).chiave : await chiaveDaRecupero(codice);
        const nuovaPasskey = nome === "recuperaNuovaPasskey";
        const nuovo = nuovaPasskey ? await creaSlotPasskey(k, persona) : await creaSlot(k, password, persona, "password");
        // Una nuova password sostituisce quella vecchia della stessa persona; una passkey si aggiunge.
        await aggiornaSlot(slots => (nuovaPasskey ? slots : slots.filter(s => !(s.tipo === "password" && s.nome.toLowerCase() === persona.toLowerCase()))).concat(nuovo));
        await sblocca(k);
        vista.messaggio = nuovaPasskey ? `Nuova passkey di ${persona} creata. Se hai perso il vecchio telefono, rimuovi la sua passkey da Impostazioni.` : `Password di ${persona} impostata.`;
      });
    }
    if (!chiave) return;
    const id = el && el.dataset.id, campo = el && el.dataset.campo;
    if (nome === "blocca") return blocca();
    if (nome === "apriCedolinoRichiesto") {
      const a = cedolinoRichiesto && trovaCedolino(cedolinoRichiesto.anno, cedolinoRichiesto.mese);
      cedolinoRichiesto = null;
      if (a) apriAllegato(a).catch(err => { vista.errore = err.message; render(); });
      return render();
    }
    if (nome === "lista" || nome === "annulla") {
      if (vista.nuoviAllegati && vista.nuoviAllegati.length) eliminaAllegati(vista.nuoviAllegati).catch(() => {});
      const cerca = vista.cerca; vista = vistaIniziale(); vista.cerca = cerca; return render();
    }
    if (nome === "apriAllegato") {
      const elenco = id ? (voci.get(id) || {}).allegati : (vista.bozza || {}).allegati;
      const a = (elenco || []).find(x => x.id === el.dataset.allegato);
      if (!a) return;
      return apriAllegato(a).catch(err => { vista.errore = err.message; render(); });
    }
    if (nome === "caricaAllegati") {
      const file = [...(el.files || [])];
      if (!file.length || !vista.bozza) return;
      return conAttesa(async () => {
        for (const [n, f] of file.entries()) {
          const a = await caricaAllegato(f, (fatti, totale) => {
            const riga = document.getElementById("cfAvanzamento");
            if (riga) riga.textContent = `Cifratura e caricamento di “${f.name}” (${n + 1}/${file.length}): ${Math.round(fatti / totale * 100)}%`;
          });
          vista.bozza.allegati = (vista.bozza.allegati || []).concat(a);
          (vista.nuoviAllegati = vista.nuoviAllegati || []).push(a);
        }
        vista.messaggio = file.length === 1 ? "Allegato caricato: salva la voce per tenerlo." : "Allegati caricati: salva la voce per tenerli.";
      });
    }
    if (nome === "rimuoviAllegato") {
      const b = vista.bozza, a = (b.allegati || []).find(x => x.id === el.dataset.allegato);
      if (!a) return;
      b.allegati = b.allegati.filter(x => x !== a);
      // Gli allegati già salvati si cancellano davvero solo al salvataggio della voce.
      if ((vista.nuoviAllegati || []).includes(a)) { vista.nuoviAllegati = vista.nuoviAllegati.filter(x => x !== a); eliminaAllegati([a]).catch(() => {}); }
      else (vista.allegatiRimossi = vista.allegatiRimossi || []).push(a);
      return render();
    }
    if (nome === "impostazioni") { vista.modo = "impostazioni"; vista.errore = vista.messaggio = ""; return render(); }
    if (nome === "rivela") { const k = id + ":" + campo; vista.rivela.has(k) ? vista.rivela.delete(k) : vista.rivela.add(k); return render(); }
    if (nome === "copia") return copia((voci.get(id) || {})[campo]);
    if (nome === "nuova") { vista.modo = "modifica"; vista.rivela.clear(); vista.bozza = { tipo: "login", titolo: "" }; vista.errore = vista.messaggio = ""; return render(); }
    if (nome === "modifica") { vista.modo = "modifica"; vista.rivela.clear(); vista.bozza = { ...voci.get(id) }; vista.errore = vista.messaggio = ""; return render(); }
    if (nome === "rivelaBozza") { const k = "bozza:" + campo; vista.rivela.has(k) ? vista.rivela.delete(k) : vista.rivela.add(k); return render(); }
    if (nome === "genera") { vista.bozza.password = generaPassword(); vista.rivela.add("bozza:password"); return render(); }
    if (nome === "salva") {
      const b = vista.bozza;
      if (!String(b.titolo || "").trim()) { vista.errore = "Dai un titolo alla voce."; return render(); }
      return conAttesa(async () => {
        const vid = b.id || crypto.randomUUID();
        const dati = { tipo: b.tipo, titolo: b.titolo.trim(), creato: b.creato || Date.now(), modificato: Date.now() };
        if (b.raccolta) dati.raccolta = b.raccolta;
        (TIPI[b.tipo] || TIPI.nota).campi.forEach(c => { if (b[c]) dati[c] = String(b[c]); });
        if (b.allegati && b.allegati.length) dati.allegati = b.allegati;
        await col().doc(vid).set(await cifra(dati, vid));
        voci.set(vid, { id: vid, ...dati });
        await eliminaAllegati(vista.allegatiRimossi).catch(() => {});
        const cerca = vista.cerca; vista = vistaIniziale(); vista.cerca = cerca; vista.messaggio = "Voce salvata.";
      });
    }
    if (nome === "elimina") {
      const b = vista.bozza;
      if (!confirm(`Eliminare definitivamente “${b.titolo}”?`)) return;
      return conAttesa(async () => {
        await col().doc(b.id).delete();
        voci.delete(b.id);
        await eliminaAllegati((b.allegati || []).concat(vista.allegatiRimossi || [])).catch(() => {});
        vista = vistaIniziale(); vista.messaggio = "Voce eliminata.";
      });
    }
    if (nome === "salvaSlot") {
      const persona = valoreInput("nome").trim(), attuale = valoreInput("attuale"), password = valoreInput("password");
      if (!persona) { vista.errore = "Scrivi il nome della persona."; return render(); }
      const errore = passwordValida(password, valoreInput("conferma"));
      if (errore) { vista.errore = errore; return render(); }
      return conAttesa(async () => {
        const k = await confermaIdentita(attuale);
        const nuovo = await creaSlot(k, password, persona, "password");
        await aggiornaSlot(slots => slots.filter(s => !(s.tipo === "password" && s.nome.toLowerCase() === persona.toLowerCase())).concat(nuovo));
        vista.messaggio = `Password di ${persona} salvata.`;
      });
    }
    if (nome === "rimuoviSlot") {
      const slot = (chiavi.slots || []).find(s => s.id === id);
      const avvisoRimozione = slot && slot.tipo === "passkey"
        ? `La passkey di ${slot.nome} non aprirà più la cassaforte. Poi puoi cancellarla anche dal gestore delle password del telefono. Continuare?`
        : `${slot && slot.nome} non potrà più aprire la cassaforte. Continuare?`;
      if (!slot || !confirm(avvisoRimozione)) return;
      return conAttesa(async () => {
        await aggiornaSlot(slots => {
          const resto = slots.filter(s => s.id !== id);
          if (!resto.some(s => s.tipo !== "recupero")) throw new Error("Deve restare almeno una passkey o una password.");
          return resto;
        });
        vista.messaggio = "Accesso rimosso.";
      });
    }
    if (nome === "aggiungiPasskey") {
      const persona = valoreInput("nomePasskey").trim(), attuale = valoreInput("attualePasskey");
      if (!persona) { vista.errore = "Scrivi di chi è la passkey."; return render(); }
      return conAttesa(async () => {
        const k = await confermaIdentita(attuale);
        const nuovo = await creaSlotPasskey(k, persona);
        await aggiornaSlot(slots => slots.concat(nuovo));
        vista.messaggio = `Passkey di ${persona} aggiunta: prova a bloccare e sbloccare con “Usa la passkey”.`;
      });
    }
    if (nome === "nuovoRecupero") {
      const attuale = valoreInput("attualeRecupero");
      return conAttesa(async () => {
        const k = await confermaIdentita(attuale);
        const recupero = nuovaChiaveRecupero();
        const nuovo = await creaSlot(k, recupero, "Chiave di recupero", "recupero");
        await aggiornaSlot(slots => slots.filter(s => s.tipo !== "recupero").concat(nuovo));
        vista.chiaveRecupero = recupero;
      });
    }
    if (nome === "esporta") return conAttesa(esporta);
  }

  async function copia(valore){
    if (!valore) return;
    try {
      await navigator.clipboard.writeText(valore);
      vista.messaggio = "Copiato. Lo cancello dagli appunti tra 30 secondi."; render();
      setTimeout(async () => {
        try { if ((await navigator.clipboard.readText()) === valore) await navigator.clipboard.writeText(""); } catch (err) { /* lettura appunti non permessa */ }
      }, PULIZIA_APPUNTI);
    } catch (err) { vista.errore = "Copia non riuscita: " + err.message; render(); }
  }

  async function esporta(){
    const [snap, snapAllegati] = await Promise.all([col().get(), colAllegati().get()]);
    const dati = { formato: "cassaforte-bilancio", versione: 1, esportato: new Date().toISOString(),
      documenti: snap.docs.map(d => ({ id: d.id, ...d.data() })), allegati: snapAllegati.docs.map(d => ({ id: d.id, ...d.data() })) };
    const url = URL.createObjectURL(new Blob([JSON.stringify(dati, null, 1)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = `cassaforte-cifrata-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    vista.messaggio = "Copia cifrata scaricata.";
  }

  // Eventi delegati: valgono a ogni ridisegno senza ricollegare i gestori.
  document.addEventListener("click", ev => {
    const el = ev.target.closest("[data-cf]");
    if (!el || !document.getElementById("content").contains(el)) return;
    ev.preventDefault();
    azione(el.dataset.cf, el);
  });
  document.addEventListener("keydown", ev => {
    if (ev.key !== "Enter" || !ev.target.matches || !ev.target.matches('[data-cf-input="password"], [data-cf-input="conferma"]')) return;
    const bottone = document.querySelector('[data-cf="sblocca"], [data-cf="crea"], [data-cf="recupera"]');
    if (bottone) { ev.preventDefault(); bottone.click(); }
  });
  const aggiornaCampo = ev => {
    const el = ev.target;
    if (el.dataset && el.dataset.cfCampo && vista.bozza) {
      vista.bozza[el.dataset.cfCampo] = el.value;
      if (el.dataset.cfCampo === "tipo") render();
    } else if (el.dataset && el.dataset.cfInput === "cerca") {
      vista.cerca = el.value; render();
    }
  };
  document.addEventListener("input", aggiornaCampo);
  document.addEventListener("change", ev => { if (ev.target.matches && ev.target.matches("[data-cf-file]")) azione("caricaAllegati", ev.target); });

  return { render: renderVista, blocca, apriCedolino };
})();
