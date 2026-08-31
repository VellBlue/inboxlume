# InboxLume: ripulire una casella molto grande senza consegnarla a un'altra IA

> [Leggi l'articolo in inglese](../article.html) · Versione italiana curata

> Articolo pubblico di sviluppo. Descrive lo stato attuale del codice sorgente,
> non una versione installabile ufficialmente supportata. Sarà aggiornato insieme
> alle funzioni reali e ai risultati misurati.

> Per i risultati misurati durante esecuzioni reali di sviluppo, consulta il
> [diario di ingegneria](engineering-log.html).

Una casella personale non è soltanto un elenco di messaggi. È una cronologia di
acquisti, relazioni, accessi, scuola, salute, lavoro e periodi della vita. Proprio
per questo, quando decine di migliaia di email rendono insufficienti le regole
tradizionali, la soluzione più comoda — inviare il contenuto a un servizio di IA — è
anche quella che introduce la domanda più difficile: quanta memoria privata siamo
disposti a consegnare per riordinare la nostra memoria privata?

InboxLume nasce da un vincolo semplice: **l'IA deve capire la posta senza farla
uscire dal dispositivo**. Il fornitore di posta elettronica continua
inevitabilmente a ospitare e consegnare i messaggi, ma inferenza, apprendimento e
stato personale restano locali. Non è un programma di posta universale, non è un
assistente con accesso al computer e non agisce in autonomia senza limiti. È uno
strumento circoscritto alla Posta in arrivo, con poche azioni verificabili.

## Perché filtri e liste di blocco non bastano

Il mittente non determina il valore di un messaggio. La stessa banca può inviare un
estratto importante e una promozione irrilevante; lo stesso negozio può inviare una
pubblicità generica e la ricevuta necessaria per una garanzia. Anche lo stato
letto/non letto è ambiguo: una vecchia email mai aperta può essere rumore, oppure
qualcosa di importante che è sfuggito.

InboxLume combina quindi tre livelli:

1. un modello locale valuta categoria e utilità del contenuto specifico;
2. la memoria privata confronta quel caso con correzioni e segnali locali;
3. un insieme di regole deterministiche decide se proteggere, chiedere una
   revisione o proporre una quarantena reversibile.

Il modello non prende direttamente il controllo. La distinzione è essenziale: un
modello linguistico è utile per comprendere sfumature linguistiche, ma il suo
punteggio di affidabilità non è una garanzia e il testo di una email può contenere
istruzioni ostili.

Italiano e inglese vengono valutati insieme, nello stesso gruppo. Una casella non
deve essere configurata come “italiana” o “inglese”: anche un singolo messaggio può
mescolare le due lingue. La lingua scelta per l’interfaccia cambia soltanto il modo
in cui InboxLume parla con l’utente, mai i contenuti che il classificatore accetta.

## Un'architettura a capacità separate

```text
fornitore Gmail/Yahoo
        |
        v
lettore della Posta in arrivo ----> testo sanificato in RAM
                                      |
                                      v
                              modello di IA locale
                                      |
                                      v
                         motore decisionale
                                      |
                               ID opachi approvati
                                      |
                                      v
                            esecutore ristretto
                         Quarantena oppure Cestino
```

Il lettore possiede le credenziali necessarie per ricevere la Posta in arrivo. Il
processo del modello riceve il contenuto, ma nessuna credenziale e nessuna funzione
per agire sulla posta. Il motore decisionale applica categorie protette, soglie e
correzioni. L'esecutore riceve soltanto identificativi opachi e una destinazione
scelta fra quelle previste.

Le operazioni più pericolose non sono nascoste dietro un pulsante: **non esistono nel
codice operativo**. InboxLume non implementa invio, SMTP, bozze, accesso alla Posta
inviata, eliminazione permanente, `EXPUNGE`, svuotamento del Cestino o modifiche
massive alle regole. Su Yahoo non usa il ripiego `STORE \\Deleted`; su Gmail le
operazioni disponibili sono separate e limitate da un elenco esplicito.

Questo non rende impossibile ogni errore software o compromissione del sistema
operativo. Rende però il perimetro più piccolo, verificabile e trasparente rispetto
a un agente generico.

## La protezione dalle minacce non può autorizzare la pulizia

La protezione da phishing e truffe segue un percorso separato, non è un altro
classificatore per la pulizia. Un livello deterministico controlla segnali
specifici su identità, autenticazione, collegamenti, anomalie Unicode e richieste
sospette. Un secondo passaggio del modello locale è facoltativo e mirato: nella
modalità consigliata parte soltanto quando il livello tecnico ha già rilevato un
allarme.

La combinazione è volutamente additiva. Un giudizio semantico che indica una
minaccia può rafforzare prove tecniche indipendenti, ma una risposta rassicurante
del modello non può cancellarle. Un risultato ad alto rischio può imporre Revisione
e aggiungere un indicatore visibile — l'etichetta Gmail
`InboxLume/Sospetto phishing` oppure il contrassegno aggiuntivo Yahoo `\Flagged` —
preservando Posta in arrivo, etichette e contrassegni esistenti.
Non può mai autorizzare Quarantena, Cestino o eliminazione permanente.

Questo confine è stato verificato sulla raccolta sintetica bilingue inclusa. La prima
esecuzione con un modello reale ha inoltre scoperto un disallineamento tra le
istruzioni date al modello e il formato della risposta. Il punteggio aggregato di
precisione non lo mostrava. Errore misurato e correzione sono descritti nel
[diario di ingegneria](engineering-log.html#modello).

## Che cosa significa davvero “locale”

La parola *locale* viene spesso usata senza specificarne il confine. Per InboxLume
significa:

- il contenuto passa direttamente dal fornitore scelto al computer dell'utente;
- non viene inviato ad API di modelli, servizi di analisi o telemetria;
- i pesi del modello sono già presenti sul dispositivo e non vengono scaricati
  durante una scansione;
- il modello viene caricato soltanto per un quiz o una scansione e scaricato alla
  fine;
- le preferenze apprese restano separate per account;
- il database conserva impronte HMAC e informazioni ridotte al minimo, non
  oggetto, corpo o mittente in chiaro.

Non significa che Gmail o Yahoo smettano di ospitare le email. Non significa nemmeno
che un modello locale sia automaticamente sicuro: ambiente di esecuzione,
indirizzo locale, percorsi della memoria temporanea e possibilità di rete devono
essere controllati. La direzione futura *Verifiable Locality* aggiungerà un
isolamento imposto dal sistema operativo e un resoconto delle
capacità effettivamente usate durante ogni esecuzione.

## Risultati operativi senza riaprire i messaggi

L'interfaccia desktop include ora un pannello operativo separato per account.
Legge gli stessi registri aggregati privati usati dai componenti di sicurezza e
mostra, per l'account e il modello selezionati, analisi completate, spostamenti
reversibili realmente eseguiti verso la Quarantena, messaggi sospetti protetti,
prove verificate da Proof of Obsolescence, attività di LumeGraph e avanzamento
verso la soglia richiesta dal Safety Governor.

Durante una scansione il pannello identifica l'esecuzione in corso e dichiara
esplicitamente se protezione antiphishing, Safety Governor, LumeGraph e Proof of
Obsolescence sono attivi. Le selezioni bloccate conservano una spunta visibile, così
un controllo disabilitato non diventa un quadrato grigio ambiguo. L'aggiornamento
dei conteggi non riapre messaggi e non espone identificativi del fornitore o testo
in chiaro.

Il pannello evita volutamente di inventare grafici statistici da semplici totali
cumulativi. Un andamento diventa significativo soltanto quando esiste una serie
temporale confrontabile tra più esecuzioni; fino ad allora, contatori precisi e la
soglia reale del Safety Governor comunicano più di una curva decorativa.

## Apprendere senza costruire un nuovo archivio della persona

Il quiz presenta email reali sul dispositivo e chiede `Tieni`, `Non tenere` o
`Non so`. L'obiettivo iniziale è quaranta esempi diversi, con almeno tre
casi da proteggere e venti da non tenere. Non dipende linearmente dalle dimensioni
della casella: sessantamila email ripetitive non richiedono sessantamila etichette,
ma una casella con famiglie rare e molto diverse richiede copertura maggiore.

Per misurare la somiglianza, InboxLume normalizza il testo, estrae caratteristiche
essenziali e conserva impronte HMAC legate all'account. Messaggi molto simili a
esempi `Non tenere` possono
rafforzare una proposta; un esempio simile `Tieni` o un conflitto forza invece la
revisione. Non viene creata una lista di blocco assoluta del mittente.

Le aperture recenti sono segnali deboli e possono soltanto proteggere o aumentare
l'astensione. In futuro *Preference Weather* manterrà scale temporali distinte: un
interesse stabile, un progetto di alcuni mesi e una curiosità di pochi giorni non
devono decadere allo stesso modo.

## La matematica dell'astensione

Un classificatore per pulire la posta non va valutato soltanto con l'accuratezza
complessiva. Gli errori hanno costi asimmetrici: lasciare nella Posta in arrivo una
pubblicità costa poco; mettere da parte una comunicazione importante può costare
molto. Le misure prioritarie sono quindi:

- **azioni di pulizia errate** sulle email da tenere;
- **copertura**, cioè quanta parte della posta il sistema automatizza;
- **astensione**, cioè quanta parte lascia alla revisione;
- risultati separati per famiglia semantica e periodo.

Anche zero errori osservati non significa rischio zero. Con `n` casi indipendenti e
zero errori, un limite superiore unilaterale elementare al 95% è:

```text
p_upper = 1 - 0.05^(1/n)
```

Con quaranta casi il limite è ancora circa 7,2%. Per scendere sotto l'1%, con le
stesse ipotesi e sempre zero errori, servono circa 299 casi comparabili. Nella posta
reale indipendenza e stazionarietà sono ipotesi fragili: temi, stagioni e interessi
cambiano. Per questo il quiz è una configurazione iniziale, non una certificazione.

Il **Safety Governor personale** calcola questo limite superiore del rischio per
account, modello e famiglia usando soltanto correzioni aggregate collegate tramite
HMAC. Il controllo operativo facoltativo aggiunge un vincolo, non sostituisce le
altre regole: quando le osservazioni sono ancora poche, le proposte prudenti
continuano a seguire i limiti ordinari, mentre soltanto errori concreti e
ripetuti limitano la famiglia interessata dalla Quarantena reversibile. La
preferenza ordinaria Cestino diretto resta indipendente con i suoi
vincoli. L'autorità del Safety Governor sul Cestino è invece una capacità distinta
e più severa: richiede un modello supportato e almeno 299 revisioni conclusive senza
errori sia nel limite globale sia nella famiglia. Cancellazione permanente e
svuotamento del Cestino restano fuori dalla sua autorità. La deriva temporale delle
preferenze è già implementata come segnale usato esclusivamente per proteggere:
indicazioni recenti e attendibili di Tieni, ripristino, stella o importanza possono
limitare la famiglia interessata, mentre un calo d'interesse non può mai autorizzare
più azioni di pulizia.
*Counterfactual Safety Lab* resta un obiettivo di ricerca.

I riferimenti metodologici di partenza includono i lavori sugli insiemi conformali
con falsi positivi limitati e sulle regole di astensione conformalizzate:

- https://proceedings.mlr.press/v162/fisch22a.html
- https://proceedings.mlr.press/v304/tayebati26a.html

## Modelli differenti, limiti differenti

InboxLume non presenta un modello da 8 miliardi di parametri come equivalente a uno
più capace. La prima matrice controllata prevede:

| Profilo | RAM consigliata | Soglia di pulizia | Destinazione massima |
|---|---:|---:|---|
| Qwen 8B leggero | 12 GB | 0,97 | sola Quarantena |
| Gemma 12B bilanciato | 16 GB | 0,95 | sola Quarantena |
| Gemma 26B-A4B consigliato | 24 GB | 0,93 | Cestino solo se calibrato |

Su un singolo Mac di sviluppo, per cinque messaggi sintetici includendo caricamento
e scaricamento del modello, sono stati osservati circa 5,4 secondi con Qwen 8B, 8,7
con Gemma 12B e 9,7 con Gemma 26B-A4B. I picchi annotati per i due Gemma sono 11,2
e 14,7 GB. Questi numeri non sono misure universali.

Sul campione locale più ampio finora disponibile, Gemma 26B-A4B non ha prodotto
azioni di pulizia errate sui quattro esempi `Tieni` valutabili e ha riconosciuto il
66,22% dei `Non tenere` come candidati. Quattro casi protetti sono decisamente insufficienti
per stimare un evento raro: la conclusione corretta non è “sicuro”, ma “migliore tra
i candidati provati, con Quarantena e vincoli di sicurezza ancora necessari”.

## Quarantena prima dell'automazione irreversibile

La destinazione predefinita è una quarantena visibile. Su Gmail è un'etichetta e il
messaggio può restare nella Posta in arrivo; su Yahoo è una cartella dedicata. Il
successivo passaggio al Cestino può richiedere almeno tre giorni e un nuovo
controllo dello stato.

Il Cestino non è una cassaforte: Gmail e Yahoo applicano propri tempi di
conservazione. Per questo l'interfaccia avverte che il fornitore può svuotarlo,
mentre InboxLume non possiede alcuna funzione per farlo. La scelta diretta è separata per account,
richiede calibrazione e, secondo le regole correnti, è ammessa soltanto con il profilo
consigliato.

## Dove InboxLume vuole arrivare

L'elemento distintivo non può essere semplicemente “usa Gemma in locale”. I
modelli sono sostituibili e il codice open source è copiabile. Il vantaggio difficile
da replicare deve nascere dalla combinazione tra stato personale accumulato,
metodologia del rischio e confini verificabili:

```text
LumeGraph
  -> Proof of Obsolescence
  -> Safety Governor
  -> Counterfactual Safety Lab
  -> autorizzazione firmata
  -> esecutore ristretto
  -> quarantena reversibile
  -> correzione causale
```

**LumeGraph** rappresenta ora il
ciclo di utilità: ordine, spedizione, consegna; prenotazione, modifica, evento
concluso; codice, uso o scadenza. Il controllo operativo **Proof of Obsolescence**
richiede una prova locale verificata che l’utilità sia conclusa e può promuovere
Revisione soltanto a Quarantena reversibile. **Proof-Carrying Cleanup** trasformerà
la decisione in un'autorizzazione firmata, limitata a un identificativo, una
destinazione e una scadenza.

Altre direzioni previste sono il rilevamento di comunicazioni attese ma mancanti, un
profilo personale dei mittenti oltre l'attuale protezione tecnica e semantica
dalle minacce e **LumeReply**, consigliere su richiesta che individua domande e
impegni senza leggere Posta inviata e senza spedire nulla. Sono ricerca futura: non devono
apparire come funzioni già disponibili.

Per l'estrazione strutturata da email e i suoi vincoli di privacy, un riferimento
utile è il lavoro di Google Research:
https://research.google/pubs/anatomy-of-a-privacy-safe-large-scale-information-extraction-system-over-email/

## Stato del progetto e trasparenza sulla pubblicazione

InboxLume è un progetto gratuito e open source su GitHub, non un servizio
commerciale. Codice sorgente e documentazione di progetto sono distribuiti con licenza
Apache-2.0; pesi dei modelli, dipendenze di terze parti e dati dell'utente conservano
le rispettive condizioni. Il repository pubblico fotografa un progetto ancora in
sviluppo, non una versione installabile ufficialmente supportata.

Interfaccia grafica, Gmail/Yahoo, più account, quiz, scansioni avviate su richiesta,
profili modello, pianificazione nativa, protezione locale dalle minacce, LumeGraph,
Proof of Obsolescence, deriva temporale, prove del Safety Governor e pannello
operativo per account hanno una
base funzionante. L'integrazione continua (CI) e il sito sono pubblici, ma il
controllo di pubblicazione separato resta deliberatamente chiuso. Prima di una
versione installabile servono almeno funzioni concordate, test su macchine pulite,
firme, revisione dei permessi, misurazioni più robuste e
materiali di pubblicazione approvati.

InboxLume non prometterà sicurezza al 100%, non chiamerà un punteggio di
affidabilità del modello “probabilità” senza calibrazione e non dichiarerà primati
mondiali senza una ricerca
professionale. La promessa più utile è più concreta:

> ogni intervento automatico di pulizia dovrà spiegare quale utilità è terminata,
> con quale livello misurato di rischio personale e con quale permesso tecnico,
> limitato e reversibile, è stato eseguito.

Questa è la direzione: non un'altra IA che possiede la posta, ma un sistema locale
che deve guadagnarsi il diritto di intervenire su ogni sua parte.
