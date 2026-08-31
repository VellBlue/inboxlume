# InboxLume

> [English README](README.md) · Versione italiana

> **Private AI for a cleaner inbox.** Il modello e l'apprendimento lavorano sul
> dispositivo dell'utente. Il contenuto viene ricevuto esclusivamente dal provider
> email configurato e non viene inviato a servizi AI esterni.

> [!IMPORTANT]
> InboxLume è ancora in sviluppo e non esiste una release pubblica supportata. CI,
> packaging e sito sono predisposti localmente, ma la pubblicazione è bloccata fino
> al completamento del perimetro concordato e della revisione finale.

Agente locale per classificare vecchie email non lette di Gmail e Yahoo.
Acquisizione, classificazione, apprendimento e scansione restano in modalità
**shadow** e usano il solo token read-only. Quando la GUI viene avviata, un esecutore
separato può mettere automaticamente in quarantena le sole email Inbox proposte
dalla policy `v2`; una spunta separata per ciascun provider può invece mandare le
future proposte direttamente nel Cestino. Un secondo comando
può spostarle in Cestino o Spam soltanto dopo tre giorni e dopo un nuovo controllo
dei vincoli. Invio, cancellazione permanente e svuotamento del Cestino non sono
implementati.

## Stato delle interfacce

La GUI SwiftUI macOS già operativa resta disponibile e non viene sostituita durante
la migrazione. In parallelo è iniziata una nuova GUI Qt/PySide6, mantenuta in file
separati e destinata a macOS, Windows e Linux. Il terzo milestone collega il motore
esistente: supporta più account Gmail e Yahoo, ognuno con credenziali, preferenze,
storico HMAC, calibrazione e destinazione indipendenti. La scansione è one-shot,
mostra l'avanzamento, può essere interrotta e non rilegge gli ID già registrati da
un lotto completato.

Le email inviate a se stessi sono protette da un guardrail deterministico: quando
l'indirizzo del mittente coincide esattamente con uno dei destinatari, la decisione
è sempre `Tieni` e il modello non può sostituirla.

Ricevute e conferme di operazioni economiche o di servizio — incluse tasse
universitarie, ricariche, pagamenti, bonifici, addebiti e accrediti — restano sempre
protette, senza limiti di età. Gli avvisi di accesso non letti e quelli sospetti o
non riconosciuti sono anch'essi sempre protetti. Soltanto un normale avviso di
accesso già letto da almeno 90 giorni può diventare candidato reversibile.

Il quarto milestone aggiunge la pianificazione opzionale e nativa per account:
`launchd` su macOS, Utilità di pianificazione su Windows e timer utente `systemd` su
Linux. Non viene attivata automaticamente e ogni esecuzione resta one-shot.

Il quinto milestone aggiunge tre profili locali controllati: Qwen 8B leggero,
Gemma 12B bilanciato e Gemma 26B-A4B consigliato. La GUI rileva passivamente RAM,
runtime e cache senza caricare o scaricare modelli; la scelta è indipendente per
account e viene usata anche dalla pianificazione. I profili meno validati applicano
soglie più severe e possono usare soltanto la Quarantena. Dettagli e limiti sono in
[docs/LOCAL_MODELS.md](docs/LOCAL_MODELS.md).

Se l'utente ripristina un messaggio che InboxLume aveva spostato, la scansione
successiva registra localmente la correzione usando soltanto identità HMAC. Gmail
usa la cronologia delle etichette; Yahoo riconcilia solo i nuovi UID della Posta in
arrivo e l'header `Message-ID`. Questo controllo non legge il corpo.

Il [Safety Governor personale](docs/it/SAFETY_GOVERNOR.md) misura prudentemente i
falsi cleanup osservati per account, modello e famiglia. Il gate operativo
facoltativo è adattivo: se mancano dati il filtro ordinario non cambia, mentre
un'evidenza concreta di errori ripetuti può limitare soltanto la famiglia
interessata. La preferenza ordinaria Cestino diretto resta indipendente
e conserva i vincoli di modello, calibrazione, policy e conferma. Il Governor
stesso ottiene autorità sul Cestino soltanto per un modello supportato quando sia
l'inviluppo complessivo sia quello della famiglia hanno almeno 299 revisioni
conclusive e zero correzioni `Tieni`. Non autorizza mai eliminazione permanente o
svuotamento del Cestino.

Il primo [backtest locale versionato](docs/it/SAFETY_BACKTEST.md) registra soltanto
gli snapshot aggregati che cambiano e segnala nuove correzioni protettive senza
riaprire messaggi o autorizzare azioni sulla casella.

La [stima locale della durata](docs/it/SCAN_DURATION_ESTIMATE.md) conta soltanto
gli ID idonei non ancora elaborati e mostra un intervallo prudenziale prima di
caricare il modello. Le sessioni concluse migliorano la stima tramite tempi locali
aggregati; non vengono salvati oggetti, corpi, ID del provider o descrizioni in
chiaro dell'hardware.

Il primo componente di [deriva temporale delle preferenze](docs/it/TEMPORAL_DRIFT.md)
confronta per famiglia evidenza recente e storica con data. Un cambiamento
protettivo ripetuto può soltanto restringere un Governor operativo; il calo
d’interesse non sblocca mai più cleanup. Usa il registro locale senza riaprire la
casella né caricare il modello.

Il primo componente definitivo del [rilevamento locale di phishing, truffe e frodi](docs/it/THREAT_DETECTION.md)
estrae segnali controllati di mittente, autenticazione, Unicode, link e ingegneria
sociale senza interrogazioni di rete. È soltanto protettivo e non autorizza cleanup.
I messaggi ad alto rischio ricevono un indicatore visibile e additivo: Gmail
aggiunge l’etichetta `InboxLume/Sospetto phishing` preservando `INBOX` e tutte le
altre etichette; Yahoo aggiunge soltanto il flag IMAP `\Flagged`, preservando la
Inbox e tutti i flag esistenti. Yahoo lo mostra come una stella, che non è esclusiva
di InboxLume. Nessun provider sposta il messaggio per l’antiphishing, usa la
Quarantena ordinaria o il Cestino, e l’indicatore non può autorizzare cleanup.

[LumeGraph](docs/it/LUMEGRAPH.md) costruisce un grafo temporale privato per OTP,
offerte, ordini, spedizioni, prenotazioni, fatture, pagamenti e flussi di sicurezza.
Il livello operativo [Proof of Obsolescence](docs/it/PROOF_OF_OBSOLESCENCE.md) può
usare un testimone di chiusura verificato per promuovere Revisione a Quarantena
reversibile. Non può promuovere direttamente al Cestino, ignorare un Tieni
deterministico, eliminare definitivamente o svuotare il Cestino.

Il prototipo precedente continua ad avviarsi con `Avvia Mail Guardian.command`; la
nuova applicazione usa `Avvia InboxLume.command`. Gli identificatori tecnici delle
credenziali e le preferenze locali precedenti restano compatibili: il rebranding non
richiede una nuova autorizzazione e non sposta né cancella dati dell'utente.

Per avviare l'anteprima multipiattaforma in un ambiente virtuale:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[desktop]'
inboxlume-desktop
```

Su Windows l'attivazione equivalente è `.venv\Scripts\activate`. Le wheel PySide6
includono Qt; non è richiesta un'installazione Qt di sistema. La roadmap incrementale
è in [docs/ROADMAP.md](docs/ROADMAP.md); la memoria di prodotto completa e
sanificata è in [docs/PRODUCT_MEMORY.md](docs/PRODUCT_MEMORY.md).

## Collegamento degli account nella nuova GUI

Le credenziali non sono salvate nel file delle preferenze. La nuova GUI usa il
gestore sicuro del sistema tramite `keyring`: Portachiavi su macOS, Gestione
credenziali su Windows e un backend Secret Service/KWallet disponibile su Linux.
Se il sistema non offre un backend sicuro, l'app rifiuta di salvare le credenziali.

Per Gmail l'utente seleziona un file OAuth di tipo **Applicazione desktop** creato
nel proprio progetto Google. La lettura della Inbox viene autorizzata per prima;
l'autorizzazione separata alle azioni protette può essere aggiunta in seguito. Per
Yahoo la finestra richiede indirizzo e password per app, mai la password principale.
Il test di connessione Gmail elenca al massimo un ID senza leggere il corpo; quello
Yahoo interroga la Inbox in sola lettura. `Disconnetti` elimina soltanto le voci
locali dell'account selezionato e non tocca messaggi o preferenze.

## Calibrazione iniziale

Il quiz è un passaggio fortemente consigliato per ogni account, ma non è l'unica
barriera di sicurezza: policy deterministica e categorie protette restano attive
anche senza risposte. L'obiettivo iniziale è di 40 esempi diversi, comprendenti
almeno 3 risposte `Tieni` e 20 `Non tenere`. La quantità non cresce linearmente con
il numero totale di messaggi: conta la copertura dei diversi tipi di contenuto.

Con calibrazione incompleta, la GUI propone prima il quiz e richiede una conferma
esplicita per proseguire in Quarantena. Il Cestino diretto è invece bloccato sia
nella GUI sia nel worker finché l'account non raggiunge i requisiti ordinari di
modello e calibrazione; il Governor resta indipendente. I quiz
successivi servono come aggiornamento incrementale e le correzioni `Tieni`/`Non so`
prevalgono sempre sulle proposte del modello.

Se una scansione viene interrotta durante la classificazione, il lotto parziale non
viene registrato come completato: quei messaggi potranno essere ripresi correttamente
alla sessione successiva. Le risposte del quiz già confermate restano invece salvate.

Credenziali, preferenze personali, database e log sono esclusi dal repository. Le
regole per evitare pubblicazioni accidentali sono documentate in
[docs/REPOSITORY_PRIVACY.md](docs/REPOSITORY_PRIVACY.md) e verificate da un test
dedicato. Il futuro sito GitHub Pages userà soltanto contenuti e asset sanificati.

## Documentazione di progetto

- [Installazione e compatibilità](docs/INSTALLATION.md)
- [Autenticazione Gmail](docs/GMAIL_SETUP.md) e [Yahoo](docs/YAHOO_SETUP.md)
- [Modelli locali](docs/LOCAL_MODELS.md) e [benchmark](docs/MODEL_BENCHMARKS.md)
- [Threat model](SECURITY.md) e [inventario permessi](docs/PERMISSIONS.md)
- [Memoria completa del prodotto](docs/PRODUCT_MEMORY.md)
- [Articolo tecnico in italiano](docs/it/ARTICLE.md) e [versione inglese](docs/ARTICLE.md)
- [Checklist e gate di pubblicazione](docs/RELEASE_CHECKLIST.md)

## Categorie iniziali

- importante, bancaria, scuola, medico/legale e sicurezza;
- codici monouso;
- ricevute, ordini, fatture e prenotazioni;
- personale, social, pubblicità, spam, altro e incerta.

Le categorie protette non vengono proposte per la quarantena, con una sola eccezione
esplicita: un codice monouso già letto, vecchio di almeno 7 giorni e riconosciuto con
confidenza molto alta. Anche in quel caso la versione corrente produce soltanto una
proposta reversibile. Una mail vecchia e non letta viene candidata solo se categoria,
valutazione del contenuto specifico e/o forte somiglianza con esempi confermati
superano le soglie. Categoria e mittente, da soli, non sono sufficienti.

## Prova locale

Non occorrono dipendenze esterne:

```bash
PYTHONPATH=src python3 -m inboxlume.cli evaluate \
  --config config/accounts.example.json \
  --account gmail_personale \
  --input examples/messages.example.jsonl \
  --backend heuristic \
  --now 2026-08-29T12:00:00+00:00
```

Per provare il modello Ollama già in cache, dopo aver avviato Ollama:

```bash
PYTHONPATH=src python3 -m inboxlume.cli evaluate \
  --config config/accounts.example.json \
  --account gmail_personale \
  --input examples/messages.example.jsonl \
  --backend ollama \
  --ollama-model qwen3-vl:8b
```

Il client rifiuta endpoint non locali e modelli diversi dall'allowlist. Prima di
usarlo con email reali verrà aggiunto un controllo di isolamento di rete del daemon.

## Conteggio e scansione Gmail in dry-run

Il conteggio iniziale usa soltanto la ricerca Gmail: non scarica corpi, oggetti o
mittenti. Restituisce la stima dei vecchi non letti e quella del prefiltro per codici
monouso già letti:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-count \
  --config config/accounts.example.json \
  --account gmail_personale
```

La prima prova reale consigliata usa il classificatore deterministico e un lotto
molto piccolo. Include vecchi non letti e una piccola quota di possibili codici
monouso già letti. `--confirm-read-bodies` rende esplicito che il testo sarà letto
sul Mac:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-dry-run \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend heuristic \
  --limit 5 \
  --confirm-read-bodies
```

L'output contiene ID opaco, data, categoria, confidenza e proposta. Non stampa
mittente, oggetto, corpo o intestazioni. Ogni risultato riporta
`"changes_mailbox": false`.

Per la calibrazione provvisoria con Qwen già presente in Ollama:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-dry-run \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend ollama \
  --ollama-model qwen3-vl:8b \
  --limit 5 \
  --confirm-read-bodies
```

Il client parla soltanto con l'endpoint loopback, non usa proxy, non fornisce tool al
modello e scarica Qwen dalla RAM alla fine del lotto.

Dopo il confronto sulle email etichettate, la scelta provvisoria per lo shadow mode
è Gemma 26B-A4B. La scansione manuale equivalente usa:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-dry-run \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend gemma26 \
  --limit 10 \
  --confirm-read-bodies
```

Gemma viene caricata dalla cache Hugging Face con rete disabilitata e il processo
MLX termina alla fine del lotto.

La scansione progressiva destinata alla futura esecuzione giornaliera usa invece
`gmail-shadow-run`. Registra soltanto HMAC, categoria e proposta, così le esecuzioni
successive saltano gli ID già elaborati prima di scaricarne il corpo:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-shadow-run \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend gemma26 \
  --limit 50 \
  --search-limit 0 \
  --state-db data/preferences.sqlite3 \
  --confirm-read-bodies
```

`--search-limit 0` permette di sfogliare progressivamente tutti gli ID candidati,
senza un tetto complessivo: vengono però scaricati e classificati soltanto i 50 nuovi
messaggi del lotto. Gli HMAC già registrati sono caricati in RAM e saltati prima di
leggere il corpo. Senza `--apply-shadow-labels` il comando resta un puro shadow run;
la GUI passa esplicitamente questo flag per applicare la sola etichetta reversibile.
Cambiare versione di modello o policy crea un nuovo profilo di scansione senza
cancellare lo storico.

Per l'account Gmail di esempio, i candidati non letti partono ora da 30 giorni; la
regola separata per i codici monouso già letti resta a 7 giorni. Queste soglie
selezionano cosa analizzare, ma non autorizzano da sole quarantena o Cestino.

## Interfaccia semplice

Aprire `Avvia InboxLume.command`. La schermata iniziale propone 50 email vecchie
per sessione, modificabili da 1 a 500 oppure impostabili su `Tutte le idonee`, un
selettore separato `Gmail`/`Yahoo` e il pulsante `Avvia controllo con Gemma`.
Il controllo è one-shot: Gemma classifica il lotto, viene chiusa e l'esecutore applica
automaticamente l'etichetta alle proposte sicure, lasciandole nella Inbox. Le sessioni
successive non rileggono email già registrate con lo stesso profilo. Il pulsante
`Quiz opzionale: correggi proposte` usa lo stesso numero impostato e serve soltanto a
migliorare o correggere le preferenze; non è necessario per la quarantena. Una
risposta `Proteggi` o `Non so` impedisce comunque la futura finalizzazione.
Il quiz salta gli HMAC già giudicati prima di scaricare i corpi e continua a scorrere
la Inbox finché trova il numero richiesto di esempi nuovi. Non esiste un limite
complessivo allo storico: `Tutte le idonee` concatena lotti interni sicuri e si
ferma quando non restano messaggi idonei non ancora elaborati.

La spunta `Invia direttamente al Cestino (salta Quarantena)` è memorizzata
separatamente per Gmail e Yahoo. Se è attiva, riguarda soltanto le nuove proposte
sicure delle scansioni successive: non sposta le quarantene già esistenti. Prima di
ogni azione vengono ricontrollati Inbox, `STARRED`/`IMPORTANT`, Posta inviata e bozze.
L'esecutore non espone eliminazione permanente o svuotamento del Cestino. Gmail
mantiene normalmente il Cestino per 30 giorni; Yahoo lo svuota automaticamente dopo
7 giorni, perciò l'app mostra un avviso più evidente per Yahoo.

Yahoo usa credenziali e database distinti. Le proposte vengono spostate dalla Inbox
alla cartella `InboxLume-Quarantena`; Gmail continua invece a lasciare i messaggi
nella Inbox con un'etichetta. Vedi [docs/YAHOO_SETUP.md](docs/YAHOO_SETUP.md).

## Pilot operativo con etichetta

Il pilot usa un secondo refresh token, separato da quello read-only. Google richiede
lo scope `gmail.modify` per applicare un'etichetta a un messaggio; lo scope è più
ampio dell'azione desiderata, quindi il trasporto locale applica un'allowlist più
stretta: GET di sole etichette/metadati e POST soltanto per creare o applicare
`InboxLume/Quarantena`. Il trasporto del pilot non possiede endpoint per invio,
bozze, impostazioni, Cestino, eliminazione o rimozione di etichette.

Autorizzazione separata, senza modificare messaggi:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-authorize-quarantine \
  --config config/accounts.example.json \
  --account gmail_personale
```

Primo pilot reale, limitato a una email già confermata `Non tenere`:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-quarantine-pilot \
  --config config/accounts.example.json \
  --account gmail_personale \
  --limit 1 \
  --search-limit 500 \
  --scan-profile gemma26-policy-v2 \
  --apply-verified-labels
```

Il pilot non legge corpi, lascia il messaggio nella Inbox ed è idempotente. Registra
soltanto HMAC ed esito aggregato, così non ripete la stessa email.

L'etichetta è configurata per comparire nella lista dei messaggi. In Gmail è possibile
assegnarle manualmente un colore dal menu a tre puntini accanto all'etichetta; togliere
l'etichetta da una mail annulla la sua successiva finalizzazione.

Dopo tre giorni interi, il comando separato di finalizzazione può spostare al massimo
cinque quarantene mature. Pubblicità, social e codici monouso vanno nel Cestino; solo
la categoria spam esplicita va in Spam. Prima dell'azione ricontrolla che la mail sia
ancora in Inbox, abbia ancora l'etichetta e non sia `Speciale` o `Importante`:

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

Questo comando non legge corpi e non può cancellare definitivamente email né svuotare
il Cestino.

I benchmark già svolti sono annotati in
[docs/MODEL_BENCHMARKS.md](docs/MODEL_BENCHMARKS.md); non vanno ripetuti prima del
quiz.

## Apprendimento delle preferenze

Per Gmail l'apprendimento è attivo nella sola modalità shadow. Apertura, stella,
etichetta `Importante` e correzione manuale sono segnali positivi; lasciare una mail
non letta è un segnale negativo debole. Categoria e mittente non decidono da soli:
le risposte esplicite alimentano anche una somiglianza del contenuto tramite impronte
HMAC non reversibili. Un esempio molto simile può influenzare la proposta; esempi
contrastanti obbligano alla revisione. Oggetto e corpo non vengono conservati.

La scansione legge dalla cronologia Gmail soltanto aggiunte/rimozioni delle etichette
`UNREAD`, `STARRED` e `IMPORTANT` riferite alla Inbox e solo per messaggi già
analizzati. I segnali recenti decadono nel tempo (emivita 45 giorni) e possono
unicamente proteggere una mail simile o inviarla in revisione: non possono mai
proporre la quarantena. Alla prima esecuzione viene solo inizializzato il cursore,
senza dedurre comportamenti retroattivi.

Gemma restituisce separatamente categoria e valutazione del contenuto della singola
email (`protect`, `discard_candidate` o `uncertain`). La quarantena shadow richiede
una valutazione specifica e molto sicura, oppure una forte somiglianza con un esempio
`Non tenere`; una categoria o un mittente, da soli, non sono sufficienti.

Il metodo principale sarà un quiz locale con tre scelte: `Tieni`, `Non tenere` e
`Non so`. Leggi [docs/CALIBRATION_QUIZ.md](docs/CALIBRATION_QUIZ.md) per selezione,
privacy e funzionamento.

Il quiz manuale si avvia così:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-quiz \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend ollama \
  --ollama-model qwen3-vl:8b \
  --limit 12 \
  --sample-limit 60 \
  --confirm-read-bodies
```

Oggetto, mittente e anteprima compaiono soltanto nel Terminale durante il quiz. Il
database locale `data/preferences.sqlite3` non contiene questi testi; la chiave HMAC
separata è custodita nel gestore credenziali nativo del sistema.

Il quiz generale resta disponibile dalla riga di comando. Dopo una scansione shadow,
la stessa GUI apre anche una revisione minimale delle sole proposte di quarantena non
ancora giudicate. I pulsanti `Proteggi`, `Conferma non tenere`, `Non so` ed `Esci`
registrano preferenze e non agiscono sulle email.

## Confronto locale dei modelli

Dopo 40–60 risposte, `gmail-model-eval` recupera in RAM soltanto le email già
giudicate tramite il loro HMAC e confronta Qwen 8B, Gemma 12B e Gemma 26B dalla
cache locale. Non salva i testi e stampa una sola riga di metriche aggregate:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-model-eval \
  --config config/accounts.example.json \
  --account gmail_personale \
  --models qwen8 gemma12 gemma26 \
  --search-limit 500 \
  --confirm-read-bodies
```

Hugging Face e Transformers vengono forzati in modalità offline per Gemma; ogni
modello viene caricato soltanto durante la propria prova e poi rimosso dalla RAM.
Il confronto dà priorità assoluta ai falsi positivi sulle email marcate `Tieni`.

## Gmail e Yahoo

Gmail verrà collegato con OAuth e scope `gmail.readonly`, che permette di visualizzare
messaggi e impostazioni senza modificarli. La documentazione Google raccomanda lo
scope più ristretto possibile: <https://developers.google.com/workspace/gmail/api/auth/scopes>.

Yahoo documenta IMAP SSL su `imap.mail.yahoo.com:993` e l'uso di una password per app:
<https://help.yahoo.com/kb/imap-internet-message-access-protocol-sln4075.html>.

La preparazione OAuth personale e i comandi `gmail-authorize` e `gmail-probe` sono
descritti in [docs/GMAIL_SETUP.md](docs/GMAIL_SETUP.md). Client OAuth e refresh token
sono conservati nel gestore credenziali nativo; l'access token resta soltanto in
memoria. I comandi CLI storici usano direttamente il Portachiavi su macOS.

L'esecuzione manuale resta il primo ingresso operativo. La GUI può installare una
pianificazione opzionale per ciascun account, dopo conferma esplicita e calibrazione
completa. Rileva il sistema e usa `launchd`, Utilità di pianificazione Windows o un
timer `systemd` utente. Non resta alcun agente residente: ogni esecuzione termina e
libera il modello dalla RAM. È consigliato scegliere un orario in cui il computer è
acceso ma non sotto sforzo. Vedi [docs/SCHEDULING.md](docs/SCHEDULING.md).

L'acquisizione è fissata nel codice alla sola cartella `INBOX`. Posta inviata,
bozze, archivio, Spam e Cestino non sono selezionabili dalla configurazione. Per
Yahoo, il solo esecutore operativo può inoltre aprire la cartella esatta creata da
InboxLume per eseguire `MOVE` dalla Inbox; non possiede SMTP, `EXPUNGE` o
comandi di cancellazione.

InboxLume non include né installa un job globale predefinito alle 04:00. Ogni attività
è generata dalla GUI per uno specifico account e usa soltanto l'entry point fisso
`inboxlume.scheduled_run`; `KeepAlive` e `RunAtLoad` sono falsi su macOS.

Vedi [SECURITY.md](SECURITY.md) per confini, minacce e garanzie tecniche.
