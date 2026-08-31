# Collegamento Gmail personale

La prima integrazione usa un client OAuth di tipo **Desktop app**, browser di
sistema, redirect su `127.0.0.1` e PKCE S256. Il redirect loopback è quello
raccomandato da Google per applicazioni desktop su macOS.

## Permesso richiesto

Verrà richiesto esattamente e soltanto:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Non verranno richiesti `mail.google.com`, `gmail.modify`, `gmail.send`, scope delle
impostazioni o altri prodotti Google.

Questa affermazione riguarda acquisizione, quiz e scansione shadow. Il pilot
operativo opzionale richiede in un secondo consenso il solo `gmail.modify`, salvato
con un refresh token separato; vedere la sezione dedicata sotto.

## Preparazione nella console Google

1. Creare un progetto personale in Google Cloud.
2. Abilitare esclusivamente Gmail API.
3. Configurare la schermata di consenso e aggiungere il proprio account come utente
   di test, se necessario.
4. Creare credenziali OAuth `Desktop app`.
5. Scaricare il JSON in una posizione locale fuori dal repository.
6. Avviare il comando di autorizzazione riportato sotto.
7. Verificare nella schermata Google che compaia soltanto l'accesso in lettura.

Nella GUI multipiattaforma il refresh token viene conservato dal gestore credenziali
nativo del sistema. Il comando CLI storico usa direttamente il Portachiavi macOS.
Il JSON OAuth, i token e gli indirizzi email non vengono inseriti nel repository o
nei log.

Il file scaricato deve avere la struttura `installed`, non `web`. InboxLume
rifiuta endpoint OAuth non Google e redirect diversi da localhost/loopback.

## Autorizzazione

Il comando apre il browser predefinito. Sostituire il percorso con quello reale del
JSON scaricato; non copiarlo nel repository.

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-authorize \
  --config config/accounts.example.json \
  --account gmail_personale \
  --client-json "/percorso/esterno/client_secret.json"
```

Il listener esiste soltanto durante il consenso, si lega a una porta casuale di
`127.0.0.1` e termina subito dopo. Usa `state` casuale e PKCE S256. Il client OAuth e
il refresh token vengono salvati come due voci separate del gestore credenziali.
L'access token non viene scritto su disco.

## Prova minima della Inbox

Dopo il consenso, questo comando elenca al massimo un ID della Inbox. Non richiede
il corpo, non stampa ID, mittente o oggetto e non modifica la casella.

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-probe \
  --config config/accounts.example.json \
  --account gmail_personale
```

Una volta verificato il probe, la scansione dry-run può leggere un piccolo lotto di
vecchi messaggi non letti e possibili codici monouso già letti. Prima si può ottenere
una stima senza leggere alcun corpo:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-count \
  --config config/accounts.example.json \
  --account gmail_personale
```

La stima del prefiltro OTP non è una classificazione: il contenuto verrà confermato
soltanto dal modello locale. Per la scansione il flag di conferma è obbligatorio:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-dry-run \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend heuristic \
  --limit 5 \
  --confirm-read-bodies
```

L'output non contiene mittente, oggetto, corpo o intestazioni. Dopo questa prova si
può avviare manualmente il quiz descritto in
[CALIBRATION_QUIZ.md](CALIBRATION_QUIZ.md). Il quiz non deve essere pianificato.

## Consenso separato per il pilot di quarantena

Gmail richiede `gmail.modify` per applicare etichette ai messaggi. Google descrive
questo scope come capace anche di leggere, comporre e inviare email, pur senza
consentire la cancellazione permanente che bypassa il Cestino. InboxLume salva
il relativo refresh token in una voce separata del Portachiavi e lo passa soltanto a
un trasporto con endpoint e payload in allowlist.

Il consenso non modifica alcun messaggio:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-authorize-quarantine \
  --config config/accounts.example.json \
  --account gmail_personale
```

Il primo pilot applica solamente `InboxLume/Quarantena` a una email ancora in
Inbox, non Importante/Preferita, già proposta dalla policy `gemma26-policy-v2` e già
confermata `Non tenere`:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-quarantine-pilot \
  --config config/accounts.example.json \
  --account gmail_personale \
  --limit 1 \
  --search-limit 500 \
  --scan-profile gemma26-policy-v2 \
  --apply-verified-labels
```

Il comando non rilegge il corpo, non rimuove `INBOX`, non cambia letto/non letto e
non può inviare, spostare in Spam/Cestino o eliminare email. L'etichetta è visibile
nella lista dei messaggi; dal menu a tre puntini accanto a essa Gmail permette di
scegliere un colore. Rimuovere l'etichetta da una mail è anche un annullamento
esplicito della futura finalizzazione.

L'eventuale etichetta precedente `Mail Guardian/Quarantena` non viene rinominata o
cancellata. È riconosciuta soltanto per completare in sicurezza operazioni già
registrate prima del cambio di nome.

Nell'app grafica questa etichettatura avviene automaticamente subito dopo ogni
scansione Gemma per le sole decisioni `quarantine` del lotto. Il quiz resta opzionale:
serve a correggere e migliorare le preferenze, mentre `Proteggi` o `Non so` blocca
comunque la finalizzazione successiva.

La spunta Gmail `Invia direttamente al Cestino (salta Quarantena)` cambia soltanto
la destinazione delle future proposte. In questa modalità un esecutore separato
ricontrolla che il messaggio sia ancora in Inbox e non sia `STARRED`, `IMPORTANT`,
`SENT` o `DRAFT`, poi ammette esclusivamente `messages.trash` con corpo vuoto. Non
sono disponibili `delete`, `batchDelete`, `emptyTrash` o `untrash`. Gmail conserva
normalmente le email nel Cestino per 30 giorni.

## Finalizzazione reversibile dopo tre giorni

Dopo tre giorni interi dall'applicazione dell'etichetta, un comando distinto può
spostare al massimo cinque quarantene mature. Ricontrolla immediatamente che ogni
messaggio sia ancora in Inbox, abbia ancora l'etichetta e non sia `STARRED` o
`IMPORTANT`. Pubblicità, social e codici monouso vengono spostati nel Cestino; solo
la categoria spam esplicita viene spostata in Spam.

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-finalize-quarantine \
  --config config/accounts.example.json \
  --account gmail_personale \
  --limit 1 \
  --search-limit 500 \
  --scan-profile gemma26-policy-v2 \
  --state-db data/preferences.sqlite3 \
  --move-mature-quarantine
```

Non rilegge il corpo. Non esiste alcun comando o endpoint per eliminazione permanente
o svuotamento del Cestino.

## Confini implementati

- solo richieste HTTPS `GET` verso `gmail.googleapis.com`;
- proxy e redirect HTTP disabilitati;
- `labelIds=INBOX` e `includeSpamTrash=false`;
- esclusione aggiuntiva dei messaggi che contengono le etichette `SENT`, `DRAFT`,
  `SPAM` o `TRASH`;
- codici monouso letti: soglia predefinita di 7 giorni, configurabile tramite
  `read_one_time_code_age_days`;
- nessun endpoint threads, attachments, modify, trash, send o settings;
- allegati mai scaricati;
- testo HTML trasformato localmente senza caricare risorse remote;
- dimensioni di risposta e corpo limitate.

Il trasporto pilot separato aggiunge questi confini:

- token `gmail.modify` distinto da quello read-only;
- massimo cinque messaggi già confermati per comando;
- nuova verifica immediata di `INBOX`, `SENT`, `DRAFT`, `SPAM`, `TRASH`, `STARRED`
  e `IMPORTANT` prima dell'applicazione;
- nessuna lettura del corpo e nessuna rimozione di etichette;
- nessun endpoint send, drafts, settings, trash, untrash, delete o batch;
- esecuzione idempotente registrata esclusivamente tramite HMAC.

Il finalizzatore separato aggiunge:

- attesa obbligatoria di tre giorni interi;
- annullamento se l'etichetta visibile è stata rimossa o la mail è diventata
  `STARRED`/`IMPORTANT`;
- allowlist POST limitata a `messages.trash` con corpo vuoto e all'esatto cambio
  `INBOX -> SPAM`;
- nessun endpoint delete, batchDelete, emptyTrash, untrash, send, drafts o settings.

Lo scope `gmail.readonly` è più ampio del solo Inbox a livello Google. La limitazione
alla Inbox è quindi applicata anche dal codice: allowlist degli URL, `labelIds=INBOX`
e controllo delle etichette su ogni messaggio.

Documentazione ufficiale:

- <https://developers.google.com/identity/protocols/oauth2/native-app>
- <https://developers.google.com/workspace/gmail/api/auth/scopes>
- <https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list>
- <https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get>
- <https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify>
- <https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/trash>
