# Inventario dei permessi

Questo documento descrive il minimo necessario e costituisce un gate di revisione:
ogni nuova capacità deve aggiornare inventario, threat model e test prima di entrare
in una release.

| Componente | Rete | Segreti | Dati ricevuti | Azioni consentite |
|---|---|---|---|---|
| Gmail reader | endpoint Google allowlist | token read-only | ID e testo Inbox | sole letture Inbox |
| Yahoo reader | `imap.mail.yahoo.com:993` | password per app | ID e testo Inbox | `SELECT INBOX` read-only, `BODY.PEEK` |
| Modello locale | nessuna rete prevista | nessuno | testo sanificato in RAM | classificazione JSON |
| Decision engine | nessuna rete | chiave HMAC | feature e classificazione | keep/review/quarantine |
| Gmail executor | endpoint Google allowlist | token azioni separato | ID opaco | etichetta Quarantena o trash singolo |
| Yahoo executor | IMAP TLS Yahoo | password per app | UID opaco | `UID MOVE` a Quarantena/Trash |
| Scheduler | nessuna rete propria | nessuno | ID account e percorso settings | avvio entry point fisso |

## Gmail

- `gmail.readonly` è usato per leggere; Google lo descrive più ampio della sola
  Inbox, quindi il codice applica anche endpoint allowlist e `labelIds=INBOX`.
- `gmail.modify` è richiesto separatamente per Quarantena/Cestino. Il token è
  conservato in una voce keyring distinta.
- Non esistono endpoint applicativi per send, drafts, settings, batch delete,
  permanent delete, empty trash o untrash.

## Yahoo

- connessione esclusiva a IMAP TLS, nessun SMTP;
- lettura con Inbox selezionata read-only e senza marcare i messaggi come letti;
- scrittura limitata a `UID MOVE` dalla Inbox verso una cartella letterale ammessa;
- nessun `STORE \\Deleted`, `EXPUNGE`, creazione di regole o svuotamento cartelle.

## Sistema operativo

- file di preferenze e database nella directory applicativa dell'utente;
- credenziali nel keyring nativo;
- cache modello letta dai soli percorsi consentiti;
- pianificazione opt-in nel servizio nativo dell'utente, senza privilegi elevati;
- nessuna telemetria, analytics, crash upload o aggiornamento automatico.

Il futuro Capability Firewall renderà alcuni di questi confini imposti anche dal
sistema operativo. Finché non sarà implementato, la documentazione deve distinguere
una restrizione applicativa da un sandbox OS verificato.
