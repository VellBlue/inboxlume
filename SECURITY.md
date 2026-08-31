# Modello di sicurezza

## Segnalare una vulnerabilità

Usare **Report a vulnerability** nella scheda Security del repository per inviare
una GitHub Security Advisory privata, invece di aprire una issue pubblica. Non
allegare email reali, token, database o log contenenti dati personali; costruire
una riproduzione sintetica minima. Il canale privato è attivo, ma nessuna versione
dell'app è ancora dichiarata supportata.

| Versione | Supporto di sicurezza |
|---|---|
| `0.x-dev` | sviluppo locale, nessuna release pubblica |

L'inventario verificabile di rete, credenziali e azioni è in
[docs/PERMISSIONS.md](docs/PERMISSIONS.md).

InboxLume è deliberatamente diviso in componenti con privilegi differenti:

```text
Gmail/Yahoo -> acquisitore read-only -> memoria del processo
                                             |
                                             v
                                    classificatore locale
                                             |
                                             v
                                policy deterministica shadow
                                             |
                                             v
                          selettore HMAC approvato dalla policy
                                             |
                                             v
                      selettore destinazione separato (senza corpi)
                              /                         \
                             v                           v
                    Quarantena reversibile       Cestino diretto opzionale
                             |
                      attesa minima 3 giorni
                             |
                             v
                    finalizzatore Cestino/Spam
```

La casella contiene dati non fidati. Oggetto, corpo, HTML e intestazioni non sono
mai considerati istruzioni. Il classificatore non possiede credenziali, strumenti,
shell o metodi per modificare la casella.

## Proprietà della fase 1

- Il contratto provider espone soltanto elenco e lettura.
- Il contratto provider espone esclusivamente letture Inbox: non esistono operazioni
  su Posta inviata, bozze, archivio, Spam o Cestino nel suo dominio.
- La sola modalità accettata dalla configurazione è `shadow`.
- La classificazione resta shadow. Solo dopo la chiusura del modello, il flag
  esplicito usato dalla GUI abilita l'esecutore separato. La destinazione predefinita
  è Quarantena; due preferenze GUI indipendenti possono scegliere il Cestino diretto
  per Gmail o Yahoo. Il quiz non è un prerequisito.
- `PolicyAction` non contiene cancellazione, svuotamento, invio, inoltro o modifica
  delle impostazioni.
- Il client Ollama accetta solo HTTP loopback, ignora i proxy e ammette soltanto
  modelli locali in allowlist. Il modello resta in RAM soltanto per il lotto in corso:
  viene scaricato esplicitamente alla fine e, se il processo si interrompe, scade
  comunque dopo cinque minuti.
- Il worker Gemma/MLX usa esclusivamente snapshot già presenti nella cache locale;
  `HF_HUB_OFFLINE` e `TRANSFORMERS_OFFLINE` sono obbligatori, i proxy vengono
  rimossi e il processo termina alla fine di ogni lotto.
- HTML viene convertito in testo senza caricare immagini, fogli di stile o URL.
- Gli allegati non vengono aperti e richiedono revisione.
- L'apprendimento salva soltanto feature e impronte di somiglianza HMAC in SQLite,
  non mittente, oggetto o corpo in chiaro. Categoria e mittente non autorizzano da
  soli una proposta di quarantena; esempi di contenuto contrastanti impongono la
  revisione.
- OAuth usa PKCE S256, `state` casuale e callback su una porta effimera legata
  esattamente a `127.0.0.1`; Tailscale e le interfacce LAN non sono in ascolto.
- Le chiamate token accettano soltanto `https://oauth2.googleapis.com/token`, senza
  proxy o redirect. L'acquisitore read-only accetta GET list/get dei messaggi e GET
  strettamente filtrati di profilo/cronologia per le sole variazioni delle etichette
  Inbox `UNREAD`, `STARRED` e `IMPORTANT`. Il trasporto operativo separato accetta
  GET di etichette/metadati e POST solo per creare o applicare l'etichetta esatta
  `InboxLume/Quarantena`. La finalizzazione riconosce anche la precedente
  `Mail Guardian/Quarantena` esclusivamente per non lasciare sospese quarantene
  create prima del rebranding; le nuove scansioni non la creano.
- Client OAuth e refresh token sono voci separate nel gestore credenziali nativo:
  Portachiavi su macOS, Gestione credenziali su Windows e Secret Service/KWallet su
  Linux. Se non è disponibile un backend sicuro, l'app rifiuta il salvataggio.
  L'access token non viene scritto su disco e non viene stampato.
- La scansione non salva corpi, oggetti, mittenti o intestazioni e non li include
  nell'output. Il quiz li mostra soltanto nel Terminale manuale; nel database salva
  solo HMAC e risposte. La chiave HMAC è una voce separata del Portachiavi.
- La scansione shadow progressiva conserva soltanto HMAC del messaggio, profilo di
  policy, categoria e proposta. Gli HMAC già visti vengono caricati in RAM; l'elenco
  degli ID può avanzare attraverso tutte le pagine Gmail, mentre il corpo viene
  scaricato soltanto per il nuovo lotto richiesto.
- Il worker multipiattaforma riceve argomenti strutturati, non comandi shell, e
  ricontrolla la conferma esplicita alle azioni. Il Cestino diretto richiede per lo
  specifico account almeno 40 risposte di calibrazione, incluse almeno 3 `Tieni` e
  20 `Non tenere`; il controllo non è affidato soltanto allo stato dei pulsanti GUI.
- Il worker pianificato accetta esclusivamente ID account e percorso assoluto delle
  preferenze, rilegge le regole salvate e richiede la calibrazione completa anche
  per la Quarantena. Un lock per account impedisce esecuzioni sovrapposte. I backend
  nativi avviano soltanto questo entry point con vettori di argomenti, senza shell.
- Un lotto shadow viene registrato come elaborato solo dopo che l'intera fase di
  classificazione è terminata. Un annullamento precedente non lascia ID parziali
  che verrebbero saltati o applicati silenziosamente al run seguente.
- L'apprendimento comportamentale associa agli HMAC già noti soltanto eventi
  apertura/stella/importante e impronte HMAC del contenuto. Ha decadimento temporale
  e può solo proteggere o richiedere revisione, mai autorizzare una quarantena.
- La lettura dei corpi richiede sempre il flag esplicito `--confirm-read-bodies`.
- Le risposte duplicate del quiz sono idempotenti: un retry non rafforza due volte
  lo stesso segnale.

## Limiti della garanzia

Non è tecnicamente corretto promettere sicurezza assoluta contro qualsiasi bug,
malware, compromissione del sistema operativo o del provider. La proprietà che
progetteremo e verificheremo è più precisa: il contenuto viene ricevuto dai provider
scelti e, dopo il download, non viene inviato ad alcun servizio esterno.

Gemma usa un processo MLX separato con pesi già locali e librerie forzate offline.
Ollama resta utile per il benchmark, ma il suo daemon deve essere limitato a modelli
locali e bloccato verso Internet a livello di sistema prima dell'uso con messaggi
reali.

L'applicazione non sarà un demone residente: ogni esecuzione avvia i componenti,
elabora un lotto limitato, chiude connessioni e processi e libera il modello. La
pianificazione, se attivata esplicitamente, lancerà questa stessa esecuzione one-shot
tramite il servizio nativo rilevato: `launchd` su macOS, Utilità di pianificazione su
Windows o timer `systemd` utente su Linux. Potrà creare o rimuovere soltanto
l'attività InboxLume e non amplierà i permessi email.

Gmail richiede inizialmente il solo scope `gmail.readonly`. Questo scope Google può
leggere più della Inbox: il confine più stretto è imposto anche dal codice tramite
endpoint allowlist, `labelIds=INBOX` e verifica delle etichette. Yahoo verrà aperto con
IMAP SSL e cartella selezionata in sola lettura. Le credenziali sono custodite nel
gestore sicuro del sistema e non sono mai presenti nei prompt, nei log, nelle
preferenze o nel repository.

Yahoo usa una password per app in una voce Portachiavi distinta e un database locale
separato. Il trasporto di lettura apre esclusivamente `imap.mail.yahoo.com:993` con
TLS e seleziona solo `INBOX` con `readonly=True`; usa `BODY.PEEK[]`, quindi la lettura
non marca il messaggio come aperto. Non esiste codice SMTP. Il trasporto operativo
richiede la capacità IMAP `MOVE` e ammette soltanto lo spostamento da Inbox alla
cartella letterale selezionata dalla GUI: `InboxLume-Quarantena` oppure `Trash`.
La cartella `Trash` deve esistere e viene aperta in sola lettura prima dell'uso; non
implementa `EXPUNGE`, `DELETE` o il fallback `STORE \\Deleted`.

Il pilot di etichettatura richiede separatamente `gmail.modify`, perché Gmail non
offre uno scope ristretto alla sola applicazione di etichette. Lo scope Google può
tecnicamente anche leggere, comporre e inviare email, ma il relativo refresh token è
separato. Il trasporto di etichettatura non espone endpoint di invio, bozze, settings,
Trash, delete, batch o rimozione di etichette. Il finalizzatore separato ammette solo
l'endpoint singolo `trash` con corpo vuoto oppure l'esatto cambio di label
`INBOX -> SPAM`; rifiuta delete, batchDelete, emptyTrash, untrash, send, drafts e
settings. Un token compromesso resta comunque un limite esterno che nessun guardrail
applicativo può annullare.

Il percorso Gmail diretto usa un trasporto ancora più ristretto: GET dei soli
metadati del singolo messaggio e POST soltanto a `messages.trash` con corpo vuoto.
Il percorso Yahoo diretto usa esclusivamente `UID MOVE <uid> Trash`. Entrambi
ricontrollano Inbox e protezioni subito prima dello spostamento. La scelta è salvata
separatamente per provider e non retroagisce sulle quarantene esistenti.

## Azioni non implementate

Gli esecutori non ricevono corpi, ma soltanto ID opachi già verificati. Nel percorso
Quarantena, prima della finalizzazione devono trascorrere tre giorni interi;
togliere l'etichetta visibile, applicare `STARRED`/`IMPORTANT` o rimuovere la mail
dalla Inbox annulla l'azione. Nel percorso diretto la spunta esplicita salta questa
attesa, ma conserva il ricontrollo immediato delle protezioni.
La cancellazione permanente, lo svuotamento del Cestino, untrash, SMTP, invio,
bozze, regole, impostazioni e modifiche massive non sono implementati.
