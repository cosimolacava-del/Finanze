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
  const COL = "bilancio_familiare_cassaforte", DOC_CHIAVI = "_chiavi";
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
  function ascoltaVoci(){
    if (stopVoci) return;
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

  function sblocca(k){
    chiave = k; vista = vistaIniziale(); ultimoUso = Date.now();
    ascoltaVoci();
  }
  function blocca(){
    chiave = null;
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
      <p class="sub">Qui puoi tenere password, codici e dati importanti della famiglia. Tutto viene cifrato su questo dispositivo prima di essere salvato: senza la password nessuno può leggerlo, neanche Google.</p>
      <p class="sub"><b>Scegli una password lunga che ricordi bene</b> (almeno ${MIN_PASSWORD} caratteri; va bene una frase di 4-5 parole). Non salvarla nel browser e non usarla altrove. Se la dimentichi, i dati si recuperano con la chiave di recupero che ti mostro subito dopo, oppure con una passkey del telefono se poi ne aggiungi una in Impostazioni.</p>
      <div class="cf-form">
        <label class="cf-campo"><span>Il tuo nome</span><input type="text" data-cf-input="nome" value="Cosimo" autocomplete="off"></label>
        ${campoPassword("password", "Password della cassaforte", "new-password")}
        ${campoPassword("conferma", "Ripeti la password", "new-password")}
      </div>
      ${avviso()}
      <button class="add-btn" data-cf="crea" ${vista.attesa ? "disabled" : ""}>${vista.attesa ? "Creazione…" : "Crea la cassaforte"}</button>
    </div>`;
  }

  function renderChiaveRecupero(){
    return `<div class="card cf">${intestazione()}
      <h4 style="margin:6px 0">Chiave di recupero</h4>
      <p class="sub">Scrivila su carta e conservala in un posto sicuro in casa. Serve se dimentichi la password: senza password e senza questa chiave i dati sono persi per sempre. Non verrà più mostrata.</p>
      <div class="cf-recupero">${e(vista.chiaveRecupero)}</div>
      <label style="display:flex;gap:8px;align-items:center;margin:12px 0"><input type="checkbox" data-cf-input="presaNota"> L'ho scritta e conservata</label>
      ${avviso()}
      <button class="add-btn" data-cf="chiudiRecupero">Continua</button>
    </div>`;
  }

  function renderSblocco(){
    const recupero = vista.modo === "recupero";
    const nomi = (chiavi.slots || []).filter(s => s.tipo === "password").map(s => s.nome);
    const conPasskey = passkeyDisponibili() && (chiavi.slots || []).some(s => s.tipo === "passkey");
    return `<div class="card cf">${intestazione()}
      ${recupero ? `
        <p class="sub">Scegli una nuova password, poi conferma con la chiave di recupero${conPasskey ? " oppure con la passkey del telefono" : ""}.</p>
        <div class="cf-form">
          <label class="cf-campo"><span>Password di</span><select data-cf-input="nome">${nomi.map(n => `<option>${e(n)}</option>`).join("")}</select></label>
          ${campoPassword("password", "Nuova password", "new-password")}
          ${campoPassword("conferma", "Ripeti la nuova password", "new-password")}
          <label class="cf-campo"><span>Chiave di recupero</span><input type="text" data-cf-input="recupero" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
        </div>
        ${avviso()}
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="add-btn" data-cf="recupera" ${vista.attesa ? "disabled" : ""}>${vista.attesa ? "Verifica…" : "Conferma con la chiave di recupero"}</button>
        ${conPasskey ? `<button class="add-btn" data-cf="recuperaPasskey" ${vista.attesa ? "disabled" : ""}>&#128241; Conferma con la passkey</button>` : ""}
        ${pulsante("annullaRecupero", "Annulla")}</div>` : `
        <p class="sub">La cassaforte è bloccata. Si blocca da sola dopo 5 minuti di inattività.</p>
        <div class="cf-form">${campoPassword("password", "Password", "current-password")}</div>
        ${avviso()}
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><button class="add-btn" data-cf="sblocca" ${vista.attesa ? "disabled" : ""}>${vista.attesa ? "Sblocco…" : "Sblocca"}</button>
        ${conPasskey ? pulsante("sbloccaPasskey", "&#128241; Usa la passkey", vista.attesa ? "disabled" : "") : ""}
        <a href="#" data-cf="mostraRecupero" class="sub">Ho dimenticato la password</a></div>`}
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
      .filter(v => !q || [v.titolo, v.utente, v.url, v.note, TIPI[v.tipo]?.nome].some(x => String(x || "").toLowerCase().includes(q)))
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
        ${v.note ? `<div class="cf-note">${e(v.note)}</div>` : ""}
      </div>`;
    }).join("");
    return `<div class="card cf">${intestazione(pulsante("nuova", "+ Nuova voce") + pulsante("impostazioni", "&#9881; Impostazioni") + pulsante("blocca", "&#128274; Blocca"))}
      ${avviso()}
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
      ${avviso()}
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:space-between">
        <div style="display:flex;gap:8px"><button class="add-btn" data-cf="salva" ${vista.attesa ? "disabled" : ""}>Salva</button>${pulsante("annulla", "Annulla")}</div>
        ${b.id ? `<button class="range-btn" data-cf="elimina" style="color:var(--rust)">Elimina</button>` : ""}
      </div>
    </div>`;
  }

  function renderImpostazioni(){
    const slots = chiavi.slots || [];
    const persone = slots.filter(s => s.tipo === "password");
    const descrizione = s => s.tipo === "recupero" ? "Chiave di recupero" : (s.tipo === "passkey" ? "Passkey di " : "Password di ") + e(s.nome);
    const elenco = slots.map(s => `<div class="cf-riga"><span class="cf-etichetta">${descrizione(s)}</span>
      <span class="sub">creata il ${new Date(s.creato).toLocaleDateString("it-IT")}</span>
      ${s.tipo === "passkey" || (s.tipo === "password" && persone.length > 1) ? pulsante("rimuoviSlot", "Rimuovi", `data-id="${e(s.id)}"`) : ""}</div>`).join("");
    return `<div class="card cf">${intestazione(pulsante("lista", "&larr; Torna alle voci") + pulsante("blocca", "&#128274; Blocca"))}
      ${avviso()}
      <h4 style="margin:6px 0">Chi può aprire la cassaforte</h4>
      ${elenco}
      <h4 style="margin:18px 0 6px">Aggiungi una persona o cambia una password</h4>
      <p class="sub">Ognuno ha la sua password. Per confermare serve la password di chi sta facendo la modifica.</p>
      <div class="cf-form">
        <label class="cf-campo"><span>Nome</span><input type="text" data-cf-input="nome" list="cfNomi" autocomplete="off" placeholder="es. Chiara"><datalist id="cfNomi">${persone.map(s => `<option value="${e(s.nome)}">`).join("")}</datalist></label>
        ${campoPassword("attuale", "La tua password attuale", "current-password")}
        ${campoPassword("password", "Nuova password", "new-password")}
        ${campoPassword("conferma", "Ripeti la nuova password", "new-password")}
      </div>
      <button class="add-btn" data-cf="salvaSlot" ${vista.attesa ? "disabled" : ""}>Salva password</button>
      <h4 style="margin:18px 0 6px">&#128241; Passkey del telefono</h4>
      <p class="sub">Con una passkey apri la cassaforte con impronta o Face ID e, se dimentichi la password, la reimposti. Si salva nel gestore delle password del telefono (Google o iCloud) e su PC si usa inquadrando il QR code col telefono. Serve un browser che supporti l'estensione PRF: Chrome o Safari recenti.</p>
      ${passkeyDisponibili() ? `<div class="cf-form">
        <label class="cf-campo"><span>Di chi è la passkey</span><input type="text" data-cf-input="nomePasskey" list="cfNomi" autocomplete="off" placeholder="es. Cosimo"></label>
        ${campoPassword("attualePasskey", "La tua password attuale", "current-password")}
      </div>
      ${pulsante("aggiungiPasskey", "Aggiungi passkey", vista.attesa ? "disabled" : "")}` : `<p class="cf-errore">Questo browser non supporta le passkey.</p>`}
      <h4 style="margin:18px 0 6px">Chiave di recupero</h4>
      <p class="sub">Se l'hai persa o pensi che qualcuno l'abbia vista, generane una nuova: quella vecchia smette di funzionare.</p>
      <div class="cf-form">${campoPassword("attualeRecupero", "La tua password attuale", "current-password")}</div>
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

  async function crea(){
    const nome = valoreInput("nome").trim() || "Cosimo", password = valoreInput("password");
    const errore = passwordValida(password, valoreInput("conferma"));
    if (errore) { vista.errore = errore; return render(); }
    await conAttesa(async () => {
      const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const recupero = nuovaChiaveRecupero();
      const slots = [await creaSlot(k, password, nome, "password"), await creaSlot(k, recupero, "Chiave di recupero", "recupero")];
      const ref = col().doc(DOC_CHIAVI);
      // In transazione: non sovrascrive una cassaforte creata nel frattempo da un altro dispositivo.
      await db.runTransaction(async tx => {
        if ((await tx.get(ref)).exists) throw new Error("La cassaforte esiste già: ricarica la pagina.");
        tx.set(ref, { versione: 1, slots, creato: Date.now(), aggiornato: Date.now() });
      });
      sblocca(await nonEstraibile(k));
      vista.chiaveRecupero = recupero;
    });
  }

  async function azione(nome, el){
    ultimoUso = Date.now();
    if (nome === "crea") return crea();
    if (nome === "chiudiRecupero") {
      if (!(document.querySelector('[data-cf-input="presaNota"]') || {}).checked) { vista.errore = "Conferma di averla scritta prima di continuare."; return render(); }
      vista.chiaveRecupero = null; vista.errore = ""; return render();
    }
    if (nome === "sblocca") {
      const password = valoreInput("password");
      return conAttesa(async () => { sblocca((await apriConPassword(password, false)).chiave); });
    }
    if (nome === "sbloccaPasskey") return conAttesa(async () => { sblocca((await apriConPasskey(false)).chiave); });
    if (nome === "recuperaPasskey") {
      const persona = valoreInput("nome"), password = valoreInput("password");
      const errore = passwordValida(password, valoreInput("conferma"));
      if (errore) { vista.errore = errore; return render(); }
      return conAttesa(async () => {
        const { chiave: k } = await apriConPasskey(true);
        const nuovo = await creaSlot(k, password, persona, "password");
        await aggiornaSlot(slots => slots.filter(s => !(s.tipo === "password" && s.nome === persona)).concat(nuovo));
        sblocca(await nonEstraibile(k));
        vista.messaggio = `Password di ${persona} cambiata.`;
      });
    }
    if (nome === "mostraRecupero") { vista.modo = "recupero"; vista.errore = ""; return render(); }
    if (nome === "annullaRecupero") { vista = vistaIniziale(); return render(); }
    if (nome === "recupera") {
      const codice = normalizzaRecupero(valoreInput("recupero")), persona = valoreInput("nome"), password = valoreInput("password");
      const errore = passwordValida(password, valoreInput("conferma"));
      if (errore) { vista.errore = errore; return render(); }
      return conAttesa(async () => {
        const slotRec = (chiavi.slots || []).find(s => s.tipo === "recupero");
        let k;
        try { k = await apriSlot(slotRec, codice, true); } catch (err) { throw new Error("Chiave di recupero errata."); }
        const nuovo = await creaSlot(k, password, persona, "password");
        await aggiornaSlot(slots => slots.filter(s => !(s.tipo === "password" && s.nome === persona)).concat(nuovo));
        sblocca(await nonEstraibile(k));
        vista.messaggio = `Password di ${persona} cambiata.`;
      });
    }
    if (!chiave) return;
    const id = el && el.dataset.id, campo = el && el.dataset.campo;
    if (nome === "blocca") return blocca();
    if (nome === "lista" || nome === "annulla") { const cerca = vista.cerca; vista = vistaIniziale(); vista.cerca = cerca; return render(); }
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
        (TIPI[b.tipo] || TIPI.nota).campi.forEach(c => { if (b[c]) dati[c] = String(b[c]); });
        await col().doc(vid).set(await cifra(dati, vid));
        voci.set(vid, { id: vid, ...dati });
        const cerca = vista.cerca; vista = vistaIniziale(); vista.cerca = cerca; vista.messaggio = "Voce salvata.";
      });
    }
    if (nome === "elimina") {
      const b = vista.bozza;
      if (!confirm(`Eliminare definitivamente “${b.titolo}”?`)) return;
      return conAttesa(async () => {
        await col().doc(b.id).delete();
        voci.delete(b.id);
        vista = vistaIniziale(); vista.messaggio = "Voce eliminata.";
      });
    }
    if (nome === "salvaSlot") {
      const persona = valoreInput("nome").trim(), attuale = valoreInput("attuale"), password = valoreInput("password");
      if (!persona) { vista.errore = "Scrivi il nome della persona."; return render(); }
      const errore = passwordValida(password, valoreInput("conferma"));
      if (errore) { vista.errore = errore; return render(); }
      return conAttesa(async () => {
        const { chiave: k } = await apriConPassword(attuale, true);
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
          if (!resto.some(s => s.tipo === "password")) throw new Error("Deve restare almeno una password.");
          return resto;
        });
        vista.messaggio = "Accesso rimosso.";
      });
    }
    if (nome === "aggiungiPasskey") {
      const persona = valoreInput("nomePasskey").trim(), attuale = valoreInput("attualePasskey");
      if (!persona) { vista.errore = "Scrivi di chi è la passkey."; return render(); }
      return conAttesa(async () => {
        const { chiave: k } = await apriConPassword(attuale, true);
        const nuovo = await creaSlotPasskey(k, persona);
        await aggiornaSlot(slots => slots.concat(nuovo));
        vista.messaggio = `Passkey di ${persona} aggiunta: prova a bloccare e sbloccare con “Usa la passkey”.`;
      });
    }
    if (nome === "nuovoRecupero") {
      const attuale = valoreInput("attualeRecupero");
      return conAttesa(async () => {
        const { chiave: k } = await apriConPassword(attuale, true);
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
    const snap = await col().get();
    const dati = { formato: "cassaforte-bilancio", versione: 1, esportato: new Date().toISOString(), documenti: snap.docs.map(d => ({ id: d.id, ...d.data() })) };
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

  return { render: renderVista, blocca };
})();
