# InboxLume: ripulire una casella enorme senza consegnarla a un'altra AI

> [English article](../ARTICLE.md) · Versione italiana curata per il proprio contesto

> Articolo pubblico di sviluppo. Descrive lo snapshot corrente del sorgente, non
> una release pacchettizzata supportata, e continuerà a essere aggiornato rispetto
> a funzioni e benchmark misurati.

> Per i risultati misurati durante esecuzioni reali di sviluppo, consulta il
> [diario di ingegneria](engineering-log.html).

Una casella personale non è soltanto un elenco di messaggi. È una cronologia di
acquisti, relazioni, accessi, scuola, salute, lavoro e periodi della vita. Proprio
per questo, quando decine di migliaia di email rendono insufficienti le regole
tradizionali, la soluzione più comoda — inviare il contenuto a un servizio AI — è
anche quella che introduce la domanda più difficile: quanta memoria privata siamo
disposti a consegnare per riordinare la nostra memoria privata?

InboxLume nasce da un vincolo semplice: **l'AI deve capire la posta senza farla
uscire dal dispositivo**. Il provider email continua inevitabilmente a ospitare e
consegnare i messaggi, ma inferenza, apprendimento e stato personale restano locali.
Non è un client universale, non è un assistente con accesso al computer e non è un
autopilota. È un agente ristretto alla Posta in arrivo, con un vocabolario di azioni
piccolo e verificabile.

## Perché filtri e blacklist non bastano

Il mittente non determina il valore di un messaggio. La stessa banca può inviare un
estratto importante e una promozione irrilevante; lo stesso negozio può inviare una
pubblicità generica e la ricevuta necessaria per una garanzia. Anche lo stato
letto/non letto è ambiguo: una vecchia email mai aperta può essere rumore, oppure
qualcosa di importante che è sfuggito.

InboxLume combina quindi tre livelli:

1. un modello locale valuta categoria e utilità del contenuto specifico;
2. la memoria privata confronta quel caso con correzioni e segnali locali;
3. una policy deterministica decide se proteggere, chiedere revisione o proporre una
   quarantena reversibile.

Il modello non prende direttamente il controllo. La distinzione è essenziale: un
LLM è utile per comprendere sfumature linguistiche, ma la sua confidenza non è una
garanzia e il testo di una email può contenere istruzioni ostili.

Italiano e inglese vengono valutati insieme, nello stesso lotto. Una casella non
deve essere configurata come “italiana” o “inglese”: anche un singolo messaggio può
mescolare le due lingue. La lingua scelta per l’interfaccia cambia soltanto il modo
in cui InboxLume parla con l’utente, mai i contenuti che il classificatore accetta.

## Un'architettura a capacità separate

```text
provider Gmail/Yahoo
        |
        v
lettore Inbox ristretto ----> testo sanificato in RAM
                                      |
                                      v
                              modello AI locale
                                      |
                                      v
                        decision engine deterministico
                                      |
                               ID opachi approvati
                                      |
                                      v
                            esecutore ristretto
                         Quarantena oppure Cestino
```

Il lettore possiede le credenziali necessarie per ricevere la Inbox. Il processo del
modello riceve il contenuto, ma nessuna credenziale e nessun metodo email. Il
decision engine applica categorie protette, soglie e feedback. L'esecutore riceve
soltanto ID opachi e una destinazione enumerata.

Le operazioni più pericolose non sono nascoste dietro un pulsante: **non esistono nel
codice operativo**. InboxLume non implementa invio, SMTP, bozze, accesso a Posta
inviata, permanent delete, `EXPUNGE`, empty-trash o modifiche massive alle regole.
Su Yahoo non usa il fallback `STORE \\Deleted`; su Gmail gli endpoint disponibili
sono separati e allowlistati.

Questo non rende impossibile ogni bug o compromissione del sistema operativo. Rende
però il perimetro più piccolo, testabile e onesto rispetto a un agente generico.

## La protezione dalle minacce non può autorizzare cleanup

La protezione da phishing e truffe è un percorso protettivo separato, non un altro
classificatore per il cleanup. Un livello deterministico controlla evidenza
circoscritta su identità, autenticazione, link, anomalie Unicode e richieste
sospette. Un secondo passaggio del modello locale è facoltativo e mirato: nella
modalità consigliata parte soltanto quando il livello tecnico ha già rilevato un
allarme.

La combinazione è volutamente additiva. Un giudizio semantico malevolo può
rafforzare evidenza tecnica indipendente, ma una risposta benigna del modello non
può cancellarla. Un risultato ad alto rischio può imporre Revisione e aggiungere un
indicatore nativo visibile — l'etichetta Gmail `InboxLume/Sospetto phishing` oppure
il flag additivo Yahoo `\Flagged` — preservando Inbox, etichette e flag esistenti.
Non può mai autorizzare Quarantena, Cestino o eliminazione permanente.

Questo confine è stato esercitato sul corpus sintetico bilingue incluso. La prima
esecuzione con un modello reale ha inoltre scoperto un disallineamento tra prompt e
parser che il punteggio aggregato di precisione non mostrava: errore misurato e
correzione sono descritti nel
[diario di ingegneria](engineering-log.html#modello).

## Che cosa significa davvero “locale”

La parola *locale* viene spesso usata senza specificarne il confine. Per InboxLume
significa:

- il contenuto passa direttamente dal provider scelto al computer dell'utente;
- non viene inviato a API di modelli, analytics o servizi di telemetria;
- i pesi sono già presenti in una cache locale e non vengono scaricati durante una
  scansione;
- il modello viene caricato soltanto per quiz o lotto e scaricato alla fine;
- le preferenze apprese restano compartimentate per account;
- il database conserva HMAC e feature minimizzate, non oggetto, corpo o mittente in
  chiaro.

Non significa che Gmail o Yahoo smettano di ospitare le email. Non significa nemmeno
che un modello locale sia automaticamente sicuro: runtime, endpoint loopback,
percorsi cache e possibilità di rete devono essere controllati. La direzione futura
*Verifiable Locality* aggiungerà sandbox del sistema operativo e un resoconto delle
capacità effettivamente usate durante ogni esecuzione.

## Evidenza operativa senza riaprire i messaggi

L'interfaccia desktop include ora una dashboard operativa separata per account.
Legge gli stessi registri aggregati privati usati dai componenti di sicurezza e
mostra, per l'account e il modello selezionati, analisi completate, spostamenti
reversibili realmente eseguiti verso la Quarantena, messaggi sospetti protetti,
prove verificate da Proof of Obsolescence, attività di LumeGraph e avanzamento
verso la soglia di evidenza del Safety Governor.

Durante una scansione la dashboard identifica l'esecuzione in corso e dichiara
esplicitamente se protezione antiphishing, Governor operativo, LumeGraph e Proof of
Obsolescence sono attivi. Le selezioni bloccate conservano una spunta visibile, così
un controllo disabilitato non diventa un quadrato grigio ambiguo. L'aggiornamento
dei conteggi non riapre messaggi e non espone ID del provider o testo in chiaro.

Il pannello evita volutamente di inventare grafici statistici da semplici totali
cumulativi. Un andamento diventa significativo soltanto quando esiste una serie
temporale comparabile per esecuzione; fino ad allora, contatori precisi e la soglia
reale del Governor comunicano più di una curva decorativa.

## Apprendere senza costruire un nuovo archivio della persona

Il quiz presenta email reali sul dispositivo e chiede `Tieni`, `Non tenere` o
`Non so`. L'obiettivo iniziale corrente è quaranta esempi diversi, con almeno tre
casi da proteggere e venti da non tenere. Non dipende linearmente dalle dimensioni
della casella: sessantamila email ripetitive non richiedono sessantamila etichette,
ma una casella con famiglie rare e molto diverse richiede copertura maggiore.

Per la similarità, InboxLume normalizza il testo, estrae feature e conserva impronte
HMAC legate all'account. Messaggi molto simili a esempi `Non tenere` possono
rafforzare una proposta; un esempio simile `Tieni` o un conflitto forza invece la
revisione. Non viene creata una blacklist assoluta del mittente.

Le aperture recenti sono segnali deboli e possono soltanto proteggere o aumentare
l'astensione. In futuro *Preference Weather* manterrà scale temporali distinte: un
interesse stabile, un progetto di alcuni mesi e una curiosità di pochi giorni non
devono decadere allo stesso modo.

## La matematica dell'astensione

Un classificatore per pulire la posta non va valutato soltanto con l'accuracy. Gli
errori hanno costi asimmetrici: lasciare in Inbox una pubblicità costa poco; mettere
da parte una comunicazione importante può costare molto. Le metriche prioritarie
sono quindi:

- **false cleanup** sulle email da tenere;
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
cambiano. Per questo il quiz è onboarding, non certificazione.

Il **Safety Governor personale** calcola quell'inviluppo per account, modello e
famiglia usando soltanto correzioni aggregate collegate tramite HMAC. Il gate
operativo facoltativo è un'intersezione, non un override: quando l'evidenza è scarsa
le proposte ordinarie prudenti continuano, mentre soltanto errori concreti e
ripetuti limitano la famiglia interessata dalla Quarantena reversibile. La
preferenza ordinaria Cestino diretto resta indipendente con i suoi
vincoli. L'autorità del Governor sul Cestino è invece una capacità distinta e più
severa: richiede un modello supportato e almeno 299 revisioni conclusive senza
errori sia nell'inviluppo globale sia nella famiglia. Cancellazione permanente e
svuotamento del Cestino restano fuori dalla sua autorità. La deriva temporale delle
preferenze è già implementata come ingresso esclusivamente protettivo: evidenza
recente qualificata di Tieni, ripristino, stella o importanza può limitare la
famiglia interessata, mentre un calo d'interesse non può mai sbloccare più cleanup.
*Counterfactual Safety Lab* resta una milestone di ricerca.

Riferimenti metodologici di partenza includono il lavoro sui set conformali con
falsi positivi limitati e sulle policy di astensione conformalizzate:

- https://proceedings.mlr.press/v162/fisch22a.html
- https://proceedings.mlr.press/v304/tayebati26a.html

## Modelli differenti, limiti differenti

InboxLume non presenta un modello da 8 miliardi di parametri come equivalente a uno
più capace. La prima matrice controllata prevede:

| Profilo | RAM consigliata | Soglia cleanup | Destinazione massima |
|---|---:|---:|---|
| Qwen 8B leggero | 12 GB | 0,97 | sola Quarantena |
| Gemma 12B bilanciato | 16 GB | 0,95 | sola Quarantena |
| Gemma 26B-A4B consigliato | 24 GB | 0,93 | Cestino solo se calibrato |

Su un singolo Mac di sviluppo, per cinque messaggi sintetici incluso carico e
scarico, sono stati osservati circa 5,4 secondi con Qwen 8B, 8,7 con Gemma 12B e 9,7
con Gemma 26B-A4B. I picchi annotati per i due Gemma sono 11,2 e 14,7 GB. Questi
numeri non sono benchmark universali.

Sul campione locale più ampio finora disponibile, Gemma 26B-A4B non ha prodotto
falsi cleanup sui quattro esempi `Tieni` valutabili e ha riconosciuto il 66,22% dei
`Non tenere` come candidati. Quattro casi protetti sono decisamente insufficienti
per stimare un evento raro: la conclusione corretta non è “sicuro”, ma “migliore tra
i candidati provati, con Quarantena e guardrail ancora necessari”.

## Quarantena prima dell'automazione irreversibile

La destinazione predefinita è una quarantena visibile. Su Gmail è un'etichetta e il
messaggio può restare nella Inbox; su Yahoo è una cartella dedicata. Il successivo
passaggio al Cestino può richiedere almeno tre giorni e un nuovo controllo dello
stato.

Il Cestino non è una cassaforte: Gmail e Yahoo applicano retention proprie. Per
questo l'interfaccia avverte che il provider può svuotarlo, mentre InboxLume non
possiede alcuna funzione per farlo. La scelta diretta è separata per account,
richiede calibrazione e, nella policy corrente, è ammessa soltanto con il profilo
consigliato.

## Dove InboxLume vuole arrivare

Il vero differenziatore non può essere semplicemente “usa Gemma in locale”. I
modelli sono sostituibili e il codice open source è copiabile. Il vantaggio difficile
da replicare deve nascere dalla combinazione tra stato personale accumulato,
metodologia del rischio e confini verificabili:

```text
LumeGraph
  -> Proof of Obsolescence
  -> Safety Governor
  -> Counterfactual Safety Lab
  -> capability firmata
  -> esecutore ristretto
  -> quarantena reversibile
  -> correzione causale
```

**LumeGraph** rappresenta ora il
ciclo di utilità: ordine, spedizione, consegna; prenotazione, modifica, evento
concluso; codice, uso o scadenza. Il gate operativo **Proof of Obsolescence**
richiede una prova locale verificata che l’utilità sia conclusa e può promuovere
Revisione soltanto a Quarantena reversibile. **Proof-Carrying Cleanup** trasformerà la
decisione in una capability firmata, limitata a un ID, una destinazione e una
scadenza.

Altre linee approvate sono il rilevamento di comunicazioni attese ma mancanti, una
baseline personale dei mittenti oltre l'attuale protezione tecnica e semantica
dalle minacce e **LumeReply**, consigliere on-demand che copre domande e impegni
senza leggere Posta inviata e senza spedire nulla. Sono ricerca futura: non devono
apparire come funzioni già disponibili.

Per l'estrazione strutturata da email e i suoi vincoli di privacy, un riferimento
utile è il lavoro di Google Research:
https://research.google/pubs/anatomy-of-a-privacy-safe-large-scale-information-extraction-system-over-email/

## Stato e onestà della release

InboxLume è un progetto gratuito e open source su GitHub, non un servizio
commerciale. Sorgente e documentazione di progetto sono distribuiti con licenza
Apache-2.0; pesi dei modelli, dipendenze di terze parti e dati dell'utente conservano
le rispettive condizioni. Il repository pubblico resta uno snapshot di sviluppo,
non una release pacchettizzata supportata.

GUI, Gmail/Yahoo, più account, quiz, scansioni one-shot, profili modello, schedule
nativa, protezione locale dalle minacce, LumeGraph, Proof of Obsolescence, deriva
temporale, evidenza del Safety Governor e dashboard operativa per account hanno una
base funzionante. CI e sito sono pubblici, ma il release gate separato resta
deliberatamente chiuso. Prima di una release servono almeno funzioni concordate,
test su macchine pulite, firme, revisione dei permessi, benchmark più robusti e
asset di release approvati.

InboxLume non prometterà sicurezza al 100%, non chiamerà una confidenza LLM
“probabilità” senza calibrazione e non dichiarerà primati mondiali senza una ricerca
professionale. La promessa più utile è più concreta:

> ogni cleanup automatico dovrà spiegare quale utilità è terminata, entro quale
> rischio personale misurato e con quale permesso tecnico limitato e reversibile è
> stato eseguito.

Questa è la direzione: non un'altra AI che possiede la posta, ma un sistema locale
che deve guadagnarsi il diritto di intervenire su ogni sua parte.
