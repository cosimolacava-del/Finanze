# Sincronizzazione automatica BPER + AMEX

Script Google Apps Script che scarica i movimenti e li mette nella sezione
**"Da confermare"** dell'app (tab Mese). Niente entra nel bilancio finché non lo
confermi tu.

- **BPER**: movimenti del conto via [Enable Banking](https://enablebanking.com) (open banking PSD2), alle 8, alle 14 e alle 20.
- **AMEX**: email di avviso acquisto lette da Gmail, ogni ora.

L'addebito mensile AMEX sul conto BPER viene escluso, perché gli acquisti arrivano già uno per uno dalle email.

Lo script gira sul tuo account Google: chiavi e dati non passano da server di terzi (a parte Enable Banking per BPER).

## 1. Enable Banking

1. Registrati su <https://enablebanking.com/cp/> (Control Panel).
2. Crea un'applicazione in modalità **Restricted Production**. Fai generare la chiave nel browser e salva il file `.pem` della chiave privata: non viene mostrato una seconda volta.
3. Annota l'**Application ID**.
4. Il **Redirect URL** lo aggiungi al passo 3.7, quando hai l'URL dell'app web dello script.
5. Nel Control Panel collega i tuoi conti BPER all'applicazione: in Restricted Production funzionano solo i conti collegati da te.

Apps Script accetta solo chiavi in formato PKCS#8, cioè con la riga `-----BEGIN PRIVATE KEY-----`. Se il tuo file inizia con `BEGIN RSA PRIVATE KEY`, convertilo così:

```bash
openssl pkcs8 -topk8 -nocrypt -in chiave.pem -out chiave-pkcs8.pem
```

## 2. Firebase

Lo script scrive su Firestore con il tuo account Google. Quell'account deve avere accesso al progetto `bilancio-lacavagiroletti` (lo ha già se ne è il proprietario).

L'app invece legge la collezione `bilancio_familiare_inbox` con il login normale. Nelle **regole di Firestore** (Console Firebase → Firestore → Regole) aggiungi questa collezione con le stesse condizioni che usi per `bilancio_familiare_movimenti`. Per esempio, se lì c'è `allow read, write: if request.auth != null && request.auth.token.email in [...]`, copia la stessa condizione:

```
match /bilancio_familiare_inbox/{id} {
  allow read, update: if <stessa condizione di bilancio_familiare_movimenti>;
}
```

## 3. Google Apps Script

1. Vai su <https://script.google.com> con l'account proprietario del progetto Firebase e crea un nuovo progetto, per esempio "Bilancio Sync".
2. Copia il contenuto di `Code.gs` nel file `Code.gs` del progetto.
3. In **Impostazioni progetto**, attiva "Mostra file manifest appsscript.json" e incolla il contenuto di `appsscript.json`.
4. Sempre in **Impostazioni progetto → Proprietà dello script**, aggiungi:

   | Proprietà | Valore |
   |---|---|
   | `EB_APP_ID` | Application ID di Enable Banking |
   | `EB_PRIVATE_KEY` | contenuto completo del file `.pem` (PKCS#8) |
   | `FIREBASE_PROJECT_ID` | `bilancio-lacavagiroletti` |
   | `AMEX_QUERY` | *(facoltativa)* ricerca Gmail delle email AMEX, predefinita `from:americanexpress newer_than:14d` |
   | `EB_ASPSP_NAME` | *(facoltativa)* predefinita `BPER Banca` |
   | `WEB_APP_URL` | l'URL `/exec` dell'app web (viene salvato anche da solo al primo collegamento BPER) |
   | `AMEX_ATTIVO` | `si` per attivare la lettura delle email AMEX, dopo aver verificato `parseAvvisoAmex` |

5. **Distribuisci → Nuova distribuzione → App web**: esegui come "Me", accesso "Solo io". Copia l'URL dell'app web (finisce con `/exec`).
6. Dall'editor esegui la funzione `installaPianificazione` e concedi le autorizzazioni richieste.
7. In Enable Banking aggiungi l'URL `/exec` tra i **Redirect URL** dell'applicazione.
8. Apri l'URL `/exec` e clicca **Collega / rinnova BPER**. Autorizza su BPER e torni alla pagina con la data di scadenza del consenso.

Il consenso dura al massimo circa 6 mesi, come prevede la PSD2. Due settimane prima della scadenza ricevi un'email e l'app mostra un avviso con il link per rinnovarlo.

## 4. Email AMEX

1. Nell'app o nel sito American Express attiva gli avvisi email per **ogni acquisto**.
2. La funzione `parseAvvisoAmex` in `Code.gs` è un punto di partenza: va adattata al testo reale delle email.
   - Le email riconosciute ricevono l'etichetta Gmail `finanze-importata`.
   - Quelle non riconosciute ricevono `finanze-da-controllare`: se ne vedi, il riconoscimento va sistemato.

## Cosa resta da verificare

- Il testo delle email AMEX Italia, per completare `parseAvvisoAmex`.
- Nome esatto e durata del consenso di BPER su Enable Banking: lo script li legge da `/aspsps`.
