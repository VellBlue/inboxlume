# InboxLume: ripulire una casella molto grande con un modello di IA locale

> [Leggi l'articolo in inglese](../article.html) · Versione italiana curata

> Articolo pubblico di sviluppo. Descrive lo stato attuale del codice sorgente,
> non una versione installabile pronta e supportata per l'uso pubblico. Verrà
> aggiornato quando cambieranno le funzioni disponibili o saranno pubblicati nuovi
> risultati misurati.

> Per i risultati misurati durante esecuzioni reali di sviluppo, consulta il
> [diario di ingegneria](engineering-log.html).

Una casella personale non è soltanto un elenco di messaggi. Contiene una cronologia
di acquisti, relazioni, accessi, scuola, salute, lavoro e periodi della vita. Quando
decine di migliaia di email rendono insufficienti le regole tradizionali, inviare il
contenuto a un servizio di IA esterno può sembrare la soluzione più comoda. Significa
però affidare a un altro servizio una parte molto ampia della propria vita privata.

InboxLume nasce da un vincolo semplice: **l'IA deve analizzare la posta senza
inviarne il contenuto a un servizio di IA esterno**. Il fornitore di posta elettronica
continua inevitabilmente a ospitare e consegnare i messaggi, ma l'analisi del modello,
l'apprendimento e i dati di personalizzazione restano locali. Non è un programma di posta universale, non è un
assistente con accesso al computer e non agisce in autonomia senza limiti. È uno
strumento circoscritto alla Posta in arrivo, con poche azioni verificabili.

## Perché filtri e liste di blocco non bastano

Il mittente non determina il valore di un messaggio. La stessa banca può inviare un
estratto importante e una promozione irrilevante; lo stesso negozio può inviare una
pubblicità generica e la ricevuta necessaria per una garanzia. Anche lo stato
letto/non letto è ambiguo: una vecchia email mai aperta può essere rumore, oppure
qualcosa di importante che è sfuggito.

InboxLume combina quindi tre livelli:

1. un modello locale valuta la categoria e l'utilità di ogni messaggio;
2. il sistema confronta il messaggio con le correzioni precedenti dello stesso account,
   conservate localmente in forma ridotta;
3. regole di sicurezza esplicite decidono se proteggere il messaggio, chiedere una
   revisione o proporre una quarantena reversibile.

Il modello non prende direttamente il controllo. La distinzione è essenziale: un
modello linguistico è utile per comprendere sfumature linguistiche, ma il suo
punteggio di affidabilità non è una garanzia. Inoltre, un'email può contenere testo
creato appositamente per indurre il modello a ignorare le regole.

Il sistema analizza sia l'italiano sia l'inglese. Non occorre configurare una casella
come “italiana” o “inglese”, perché anche un singolo messaggio può mescolare le due
lingue. La lingua scelta per l'interfaccia cambia soltanto i testi mostrati all'utente,
non le lingue che InboxLume può analizzare.

## Componenti separati con permessi diversi

```text
fornitore Gmail/Yahoo
        |
        v
lettore della Posta in arrivo ----> testo preparato in RAM
                                      |
                                      v
                              modello di IA locale
                                      |
                                      v
                         motore decisionale
                                      |
                               ID tecnici approvati
                                      |
                                      v
                            esecutore ristretto
                         Quarantena oppure Cestino
```

Il componente di lettura possiede le credenziali necessarie per ricevere la Posta in
arrivo. Il processo del modello riceve il contenuto, ma nessuna credenziale e nessuna
funzione per modificare la posta. Il motore decisionale applica categorie protette,
soglie e correzioni. Il componente che esegue le azioni riceve soltanto identificativi
tecnici che non contengono il testo dei messaggi e una destinazione scelta fra quelle
previste.

Le operazioni più pericolose non sono nascoste dietro un pulsante: **non esistono nel
codice operativo**. InboxLume non implementa invio, SMTP, bozze, accesso alla Posta
inviata, eliminazione permanente, `EXPUNGE`, svuotamento del Cestino o modifiche
in blocco alle regole. Su Yahoo non usa il comando alternativo `STORE \\Deleted`, che
contrassegnerebbe il messaggio come eliminato; su Gmail le
operazioni disponibili sono separate e limitate da un elenco esplicito.

Questo non rende impossibile ogni errore software o compromissione del sistema
operativo. Rispetto a un assistente con accesso generale al computer, limita i
permessi a un insieme più piccolo, verificabile e trasparente.

## La protezione dalle minacce non può autorizzare la pulizia

La protezione da phishing e truffe segue un percorso separato: non serve a decidere
quali email ripulire. Un insieme di regole fisse controlla elementi tecnici
specifici relativi a identità, autenticazione, collegamenti, anomalie Unicode e
richieste sospette. Un secondo passaggio del modello locale è facoltativo e mirato: nella
modalità consigliata parte soltanto quando le regole tecniche hanno già rilevato un
allarme.

Il modello può aumentare il livello di rischio, ma non può ridurre quello prodotto
dai controlli tecnici. Un'analisi del significato che indica una minaccia può quindi
rafforzare prove tecniche indipendenti, mentre una risposta rassicurante del modello
non può cancellarle. Un risultato ad alto rischio può imporre Revisione
e aggiungere un indicatore visibile — l'etichetta Gmail
`InboxLume/Sospetto phishing` oppure il contrassegno aggiuntivo Yahoo `\Flagged` —
preservando Posta in arrivo, etichette e contrassegni esistenti.
Non può mai autorizzare Quarantena, Cestino o eliminazione permanente.

Questo confine è stato verificato sulla raccolta sintetica bilingue inclusa. La prima
esecuzione con un modello reale ha inoltre scoperto un disallineamento tra le
istruzioni date al modello e il formato della risposta. Il punteggio complessivo di
precisione non mostrava il problema. L'errore misurato e la correzione sono descritti nel
[diario di ingegneria](engineering-log.html#modello).

## Che cosa significa davvero “locale”

La parola *locale* viene spesso usata senza specificarne il confine. Per InboxLume
significa:

- il contenuto passa direttamente dal fornitore scelto al computer dell'utente;
- non viene inviato ad API di modelli, servizi di analisi o telemetria;
- i file del modello sono già presenti sul dispositivo e non vengono scaricati
  durante una scansione;
- il modello viene caricato soltanto per un quiz o una scansione e scaricato alla
  fine;
- le preferenze apprese restano separate per account;
- il database conserva impronte HMAC e informazioni ridotte al minimo, non
  oggetto, corpo o mittente in chiaro.

Non significa che Gmail o Yahoo smettano di ospitare le email. Non significa nemmeno
che un modello locale sia automaticamente sicuro: occorre controllare il processo
che lo esegue, l'indirizzo di rete locale su cui risponde, i file temporanei e
l'eventuale accesso alla rete. La futura funzione *Verifiable Locality* dovrebbe
aggiungere un isolamento imposto dal sistema operativo e un resoconto dei permessi
effettivamente usati durante ogni esecuzione.

## Risultati operativi senza riaprire i messaggi

L'interfaccia desktop include ora un pannello operativo separato per account.
Legge registri privati che contengono soltanto totali, gli stessi usati dai componenti
di sicurezza. Per l'account e il modello selezionati mostra quante email sono state analizzate,
quante sono state spostate in modo reversibile verso la Quarantena e quanti messaggi
sospetti sono stati protetti. Mostra inoltre i risultati di Proof Of Obsolescence,
il controllo che verifica se l'utilità di un messaggio è terminata; l'attività di
LumeGraph, che segue il ciclo di utilità; e l'avanzamento verso la soglia richiesta
dal Safety Governor.

Durante una scansione il pannello identifica l'esecuzione in corso e dichiara
esplicitamente se protezione antiphishing, Safety Governor, LumeGraph e Proof Of
Obsolescence sono attivi. Le selezioni bloccate conservano una spunta visibile, così
un controllo disabilitato non diventa un quadrato grigio ambiguo. L'aggiornamento
dei conteggi non riapre messaggi e non espone identificativi del fornitore o testo
in chiaro.

Il pannello non trasforma semplici totali cumulativi in grafici che suggerirebbero
un andamento inesistente. Un grafico temporale diventa significativo soltanto dopo
più scansioni confrontabili. Fino ad allora, contatori precisi e la soglia effettiva
del Safety Governor descrivono meglio lo stato del sistema.

## Apprendere senza costruire un nuovo archivio della persona

Il quiz presenta email reali sul dispositivo e chiede `Tieni`, `Non tenere` o
`Non so`. L'obiettivo iniziale è quaranta esempi diversi, con almeno tre
casi da proteggere e venti da non tenere. Il numero di esempi necessari non cresce
automaticamente insieme al numero di email: sessantamila messaggi molto simili non
richiedono sessantamila risposte, mentre una casella con molti tipi di messaggi rari
e diversi richiede più esempi.

Per misurare la somiglianza, InboxLume normalizza il testo, estrae caratteristiche
essenziali e conserva impronte crittografiche HMAC legate all'account. Queste
impronte permettono confronti senza salvare il testo originale. Una forte somiglianza
con esempi `Non tenere` può rafforzare una proposta. Una somiglianza con un esempio
`Tieni`, oppure segnali in conflitto, impone invece la revisione. Il mittente non
viene mai inserito in una lista di blocco assoluta.

Le aperture recenti sono segnali deboli e possono soltanto proteggere un messaggio o
aumentare i casi lasciati alla revisione. La futura funzione *Preference Weather*
distinguerebbe preferenze con durate diverse: un interesse stabile, un progetto di
alcuni mesi e una curiosità di pochi giorni non dovrebbero perdere importanza con
la stessa velocità.

## La matematica dei casi lasciati alla revisione

Un sistema che decide quali email ripulire non va valutato soltanto con l'accuratezza
complessiva. I diversi errori hanno conseguenze molto diverse: lasciare nella Posta in arrivo una
pubblicità costa poco; mettere da parte una comunicazione importante può costare
molto. Le misure prioritarie sono quindi:

- **azioni di pulizia errate** sulle email da tenere;
- **copertura**, cioè quanta parte della posta il sistema automatizza;
- **astensione**, cioè la percentuale di messaggi sui quali non compie azioni
  automatiche e chiede una revisione;
- risultati separati per tipo di email e periodo.

Anche zero errori osservati non significa rischio zero. Con `n` casi indipendenti e
zero errori, una stima prudente del valore massimo del rischio compatibile con i
dati, calcolata con un livello di confidenza del 95%, è:

```text
p_upper = 1 - 0.05^(1/n)
```

Con quaranta casi il limite è ancora circa 7,2%. Per scendere sotto l'1%, con le
stesse ipotesi e sempre zero errori, servono circa 299 casi comparabili. Nella posta
reale i messaggi non sono sempre indipendenti e le preferenze non restano costanti:
temi, stagioni e interessi cambiano. Per questo il quiz è una configurazione iniziale,
non una certificazione.

Il **Safety Governor personale** calcola questo limite superiore del rischio per
account, modello e tipo di email usando soltanto risultati complessivi collegati
tramite HMAC. È un controllo facoltativo che aggiunge restrizioni alle regole
ordinarie e non le sostituisce.

Quando le osservazioni sono poche, continuano a valere i normali limiti di sicurezza.
Se invece si ripetono errori concreti in uno specifico tipo di email, il Safety
Governor limita le proposte di Quarantena soltanto per quel tipo. L'opzione ordinaria
che consente di proporre direttamente il Cestino rimane separata e conserva i propri
vincoli.

Il Safety Governor può autorizzare il Cestino soltanto in condizioni più severe:
serve un modello supportato e occorrono almeno 299 revisioni senza errori, sia nel
totale sia per il tipo di email interessato. Non può mai autorizzare l'eliminazione
permanente o lo svuotamento del Cestino.

InboxLume considera anche i cambiamenti delle preferenze nel tempo, ma soltanto per
aumentare la protezione. Indicazioni recenti e attendibili come `Tieni`, ripristino,
stella o importanza possono ridurre le azioni automatiche per un tipo di email. Un
calo di interesse, invece, non può mai autorizzare più pulizia.
*Counterfactual Safety Lab*, la linea di ricerca sulle variazioni controfattuali dei
messaggi, non è ancora una funzione disponibile.

I riferimenti metodologici di partenza includono studi su metodi statistici che
limitano i falsi positivi e decidono quando un classificatore deve astenersi, cioè
lasciare la decisione alla revisione:

- https://proceedings.mlr.press/v162/fisch22a.html
- https://proceedings.mlr.press/v304/tayebati26a.html

## Modelli differenti, limiti differenti

InboxLume non considera equivalenti modelli con dimensioni e capacità diverse. Ogni
profilo ha quindi requisiti e limiti operativi specifici:

| Profilo | RAM consigliata | Punteggio minimo per proporre la pulizia | Destinazione massima |
|---|---:|---:|---|
| Qwen 8B leggero | 12 GB | 0,97 | sola Quarantena |
| Gemma 12B bilanciato | 16 GB | 0,95 | sola Quarantena |
| Gemma 26B-A4B consigliato | 24 GB | 0,93 | Cestino solo dopo calibrazione |

Su un singolo Mac di sviluppo, per cinque messaggi sintetici includendo caricamento
e scaricamento del modello, sono stati osservati circa 5,4 secondi con Qwen 8B, 8,7
con Gemma 12B e 9,7 con Gemma 26B-A4B. La memoria massima registrata per i due Gemma
è stata rispettivamente 11,2 e 14,7 GB. Questi numeri provengono da un solo ambiente
di prova e non rappresentano prestazioni universali.

Sul campione locale più ampio finora disponibile, Gemma 26B-A4B non ha prodotto
azioni di pulizia errate sui quattro esempi `Tieni` valutabili e ha riconosciuto il
66,22% dei `Non tenere` come candidati alla pulizia. Quattro esempi da proteggere sono troppo pochi
per stimare un errore raro. Il risultato consente soltanto di dire che, fra i modelli
provati, è il candidato migliore; Quarantena e vincoli di sicurezza restano necessari.

## Quarantena prima del Cestino

La destinazione predefinita è una quarantena visibile. Su Gmail è un'etichetta e il
messaggio può restare nella Posta in arrivo; su Yahoo è una cartella dedicata. Prima
di proporre il successivo passaggio al Cestino devono trascorrere almeno tre giorni
e il messaggio viene controllato di nuovo.

Il Cestino non garantisce la conservazione dei messaggi: Gmail e Yahoo applicano i
propri tempi di eliminazione. Per questo l'interfaccia avverte che il fornitore può svuotarlo,
mentre InboxLume non possiede alcuna funzione per farlo. L'opzione che consente di
proporre direttamente il Cestino è configurata separatamente per ogni account,
richiede calibrazione e, secondo le regole correnti, è disponibile soltanto con il
profilo consigliato.

## Dove InboxLume vuole arrivare

L'elemento distintivo non può essere semplicemente “usa Gemma in locale”. I
modelli sono sostituibili e il codice open source è copiabile. L'elemento più difficile
da replicare deve nascere dalla combinazione tra preferenze locali apprese nel tempo,
misurazione del rischio e limiti tecnici verificabili:

```text
LumeGraph (segue il ciclo di utilità)
  -> Proof Of Obsolescence (verifica che l'utilità sia terminata)
  -> Safety Governor (limita le azioni in base agli errori osservati)
  -> Counterfactual Safety Lab (ricerca futura)
  -> autorizzazione tecnica firmata e con scadenza
  -> componente con permessi limitati
  -> Quarantena reversibile
  -> correzione dell'utente registrata localmente
```

**LumeGraph** rappresenta il ciclo di utilità di alcuni messaggi: per esempio ordine,
spedizione e consegna; oppure prenotazione, modifica ed evento concluso. Il controllo
**Proof Of Obsolescence** richiede un elemento locale che indichi in modo verificabile
che questo ciclo è terminato. Può trasformare una proposta di sola Revisione in uno spostamento verso
la Quarantena reversibile, mai verso il Cestino. La futura funzione
**Proof-Carrying Cleanup** dovrebbe associare alla decisione un'autorizzazione
firmata, valida soltanto per uno specifico identificativo, una destinazione e un
periodo limitato.

Fra le funzioni future ci sono il rilevamento di comunicazioni attese ma mai arrivate,
un profilo personale dei mittenti distinto dall'attuale protezione antiphishing e
**LumeReply**. Quest'ultimo sarebbe un consigliere attivato su richiesta per individuare
domande e impegni, senza leggere la Posta inviata e senza spedire messaggi. Queste
funzioni non sono ancora disponibili.

Per l'estrazione strutturata da email e i suoi vincoli di privacy, un riferimento
utile è il lavoro di Google Research:
https://research.google/pubs/anatomy-of-a-privacy-safe-large-scale-information-extraction-system-over-email/

## Stato del progetto e trasparenza sulla pubblicazione

Il [diario di ingegneria](engineering-log.html) descrive cosa è successo durante le
prime prove del sistema con un modello locale, un server IMAP e un Mac reali. Riporta
i risultati misurati e chiarisce anche ciò che quei risultati non dimostrano.

InboxLume è un progetto gratuito e open source su GitHub, non un servizio
commerciale. Codice sorgente e documentazione di progetto sono distribuiti con licenza
Apache-2.0; i file dei modelli e le dipendenze di terze parti mantengono le rispettive
licenze e condizioni d'uso. Queste licenze non si applicano ai dati dell'utente. Il
repository pubblico fotografa un progetto ancora in
sviluppo, non una versione installabile pronta e supportata per l'uso pubblico.

Sono già presenti e funzionanti:

- interfaccia grafica, collegamento a Gmail e Yahoo e gestione separata di più account;
- quiz, scansioni avviate su richiesta, profili dei modelli e pianificazione tramite
  il sistema operativo;
- protezione locale dalle minacce;
- LumeGraph, Proof Of Obsolescence, controllo dei cambiamenti nel tempo e Safety
  Governor;
- pannello operativo separato per ogni account.

L'integrazione continua (CI) e il sito sono pubblici, ma un controllo automatico
continua a bloccare la creazione di una versione installabile destinata al pubblico.
Prima di consentire la distribuzione servono almeno il completamento delle funzioni
previste, test su macchine pulite, firma dei pacchetti, revisione dei permessi,
misurazioni più robuste e materiali di pubblicazione approvati.

InboxLume non prometterà sicurezza al 100%, non chiamerà un punteggio di
affidabilità del modello “probabilità” senza calibrazione e non dichiarerà di essere
il primo o il migliore prodotto senza una ricerca indipendente e documentata. La promessa più
utile è più concreta:

> per ogni intervento automatico, InboxLume dovrà spiegare perché il messaggio non è
> più utile, quale rischio personale è stato misurato e quale permesso tecnico,
> limitato e reversibile, ha autorizzato l'azione.

Questa è la direzione: non un altro servizio di IA a cui affidare la posta, ma un
sistema locale che può intervenire soltanto quando dispone di prove e permessi
sufficienti.
