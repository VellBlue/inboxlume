# InboxLume Private Twin

Stato: proposta approvata per una milestone futura; non ancora implementata.

## Obiettivo

Private Twin sarà un modello personale dell'inbox costruito e conservato soltanto
sul dispositivo. Non sarà una semplice lista di mittenti o categorie: dovrà
apprendere come cambiano nel tempo gli interessi dell'utente e quale comportamento
è normale per ciascuna relazione, senza inviare contenuti o profili a servizi cloud.

Il vantaggio difendibile di InboxLume non sarà il modello Gemma in sé, sostituibile
con altri modelli locali, ma la combinazione tra memoria personale temporale,
valutazione semantica del singolo messaggio, sicurezza deterministica e capacità di
astenersi quando le prove non sono sufficienti.

La direzione completa è descritta in
[PIONEERING_FEATURES.md](PIONEERING_FEATURES.md). Il flagship proposto è **Proof of
Obsolescence**: nessuna azione perché una mail sembra genericamente poco importante,
ma soltanto quando esiste una prova locale che la sua utilità è conclusa, il rischio
personale è entro il limite misurato e l'esecutore riceve una capability limitata.

Poiché InboxLume sarà open source, nessuna funzione basata sul solo codice può
essere dichiarata incopiabile. Il vantaggio difficile da replicare dovrà essere il
risultato composto di:

1. uno stato personale che nasce nel tempo e non esiste fuori dal dispositivo;
2. un metodo quantitativo per decidere quando il sistema non è abbastanza affidabile;
3. un confine privacy dimostrabile tecnicamente, non soltanto dichiarato;
4. una cronologia di correzioni e simulazioni che rende il sistema progressivamente
   più adatto a quella persona senza creare un dataset centralizzato.

## Differenziatori di ricerca candidati

### Preference Half-Life

Un modello temporale attribuisce a ogni interesse una vita media appresa. Una
newsletter può essere rilevante durante un progetto e diventare rumore dopo mesi;
una categoria bancaria può restare protetta, mentre singoli avvisi ripetitivi
perdono utilità. Correzioni esplicite e categorie di sicurezza non decadono nello
stesso modo dei semplici segnali di apertura.

### Utility Lifecycle Engine

InboxLume non domanda soltanto «che categoria è?», ma «questa informazione ha ancora
utilità?». Il sistema può distinguere, per esempio, una prenotazione futura da una
conclusa, una spedizione in corso da una consegnata, un codice monouso attivo da uno
scaduto e una promozione ancora valida da una terminata. L'azione dipende dal ciclo
di vita estratto dal contenuto e non da una regola globale sul mittente.

### Personal Risk Calibration

Prima di consentire automazioni, InboxLume riproduce le decisioni in shadow mode su
esempi locali e calcola una soglia personale con un metodo di classificazione
selettiva/conformal risk control. L'obiettivo è autorizzare soltanto la porzione di
messaggi per cui il limite empirico dei falsi positivi è compatibile con il rischio
scelto; il resto produce astensione. Le ipotesi e i limiti statistici devono essere
mostrati chiaramente, senza promesse assolute.

### Capability Firewall

Lettura della posta e inferenza locale devono vivere in processi distinti. Il bridge
del provider possiede solo gli endpoint email consentiti; il processo del modello
riceve testo sanitizzato ma viene avviato senza rete e senza capacità di modificare
la casella. L'esecutore operativo riceve soltanto ID opachi già approvati e non il
corpo. Questo rende verificabile che un prompt contenuto in una mail non possa
trasformare Gemma in un agente generico o farle esfiltrare dati.

### Personal Phishing Immune System

Private Twin costruisce la baseline di ciascuna relazione e, interamente in locale,
può generare perturbazioni sintetiche controllate: cambio di `Reply-To`, dominio
simile, nuova richiesta urgente, variazione di tono o destinazione di pagamento.
Questi esempi non vengono inviati né spediti; servono per verificare se i guardrail
riconoscerebbero un attacco plausibile rivolto proprio a quell'utente. La funzione
deve essere progettata esclusivamente come test difensivo offline.

### Proof-Carrying Action

Ogni spostamento automatico porta una ricevuta locale: versione di modello e policy,
segnali concordanti, guardrail superati, motivi di astensione e impronta HMAC della
decisione. La ricevuta non contiene testo email e permette di ricostruire perché
un'azione è stata autorizzata, anche dopo un aggiornamento del modello.

## Funzioni previste

- profilo temporale degli interessi: riconoscere che lo stesso tipo di email può
  interessare in un periodo e non interessare in un altro;
- valutazione basata sul contenuto specifico: categoria e mittente non devono mai
  imporre da soli la decisione;
- memoria di similarità: una mail molto simile a esempi confermati può ereditare il
  segnale, mentre esempi contrastanti devono forzare revisione o astensione;
- baseline privata delle relazioni: argomenti abituali, tono, frequenza, orari,
  domini dei link, `From`, `Reply-To` e caratteristiche delle intestazioni;
- anomalia personale antiphishing: rilevare richieste o identità incoerenti con il
  comportamento storico di quel corrispondente, anche quando il messaggio appare
  genericamente credibile;
- consenso a più livelli: automatizzare soltanto quando modello semantico, memoria
  personale e guardrail deterministici concordano;
- astensione esplicita: `Non so` e segnali in conflitto devono produrre revisione,
  non un'azione forzata;
- simulazione sullo storico prima dell'automazione, con misurazione di falsi
  positivi, copertura e categorie non sufficientemente rappresentate;
- calibrazione statistica personale delle soglie, con obiettivo dichiarato di
  limitare i falsi positivi invece di mostrare soltanto una generica percentuale di
  confidenza;
- ricevuta decisionale locale e comprensibile, priva di testo email in chiaro, che
  registri quali famiglie di segnali e quali regole hanno autorizzato o bloccato
  un'azione;
- decadimento controllato della memoria: segnali vecchi devono perdere peso senza
  cancellare correzioni esplicite importanti;
- compartimenti tra account: nessun trasferimento di preferenze tra Gmail e Yahoo
  o tra account diversi senza un consenso esplicito dell'utente.

## Principi di sicurezza

- nessun corpo, oggetto, indirizzo o embedding reversibile deve lasciare il
  dispositivo;
- nessuna scansione di Posta inviata, bozze, Spam o Cestino;
- nessun accesso a file, calendario, browser o altre risorse esterne all'email;
- nessuna eliminazione permanente e nessuna funzione per svuotare il Cestino;
- il testo delle email è dati non affidabili, mai istruzioni per l'agente;
- il rilevamento antiphishing non deve visitare automaticamente link o aprire
  allegati;
- in caso di modello assente, errore, deriva o dati insufficienti il sistema deve
  fallire in sicurezza e non applicare azioni.

## Criteri prima del rilascio

Private Twin potrà essere attivato soltanto dopo test sintetici e locali che
dimostrino isolamento tra account, resistenza ai conflitti, corretta astensione,
assenza di testo in chiaro nello stato e regressioni nulle sulle categorie protette.
Le dichiarazioni pubbliche dovranno descrivere misure osservate, non promettere
sicurezza assoluta o unicità mondiale non verificabile.
