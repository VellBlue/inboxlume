# Roadmap

InboxLume viene evoluto per milestone verificabili, mantenendo utilizzabile il
prototipo macOS fino a quando la nuova applicazione non avrà raggiunto la stessa
copertura funzionale.

La fonte di verità sanificata per tutti i requisiti concordati, inclusi quelli
successivi alla prima release, è [PRODUCT_MEMORY.md](PRODUCT_MEMORY.md).

## Milestone 1 — Fondazione multipiattaforma

Stato: completato.

- nuova GUI Qt/PySide6 separata dalla GUI SwiftUI;
- supporto previsto per macOS, Windows e Linux;
- preferenze validate e indipendenti per Gmail e Yahoo;
- soglie configurabili da 1 a 3650 giorni per non lette e codici monouso;
- ordine dalle più recenti o dalle più vecchie;
- scansione configurabile da 1 a 500 o su tutte le email idonee; quiz da 1 a 500;
- scelta separata Quarantena/Cestino;
- salvataggio JSON atomico nella directory applicativa nativa del sistema;
- nessuna credenziale o porzione di email nelle preferenze;
- messaggio privacy locale visibile nella schermata principale.

Questa schermata non è ancora collegata all'esecuzione del motore email: nel primo
milestone non apre connessioni e non modifica messaggi.

## Milestone 2 — Account e autenticazione guidata

Stato: completato.

- procedura OAuth Gmail comprensibile e test di connessione non invasivo;
- procedura Yahoo con password per app e test IMAP;
- archivio credenziali nativo per macOS, Windows e Linux;
- stati account, riconnessione e disconnessione;
- nessuna credenziale in log, preferenze o repository.

Il test Gmail elenca al massimo un ID senza leggere corpi; il test Yahoo apre la
Inbox in sola lettura. La disconnessione rimuove soltanto le credenziali locali
dell'account selezionato. Nessuna connessione reale è stata usata nei test automatici.

## Milestone 3 — Esecuzione dalla nuova GUI

Stato: completato.

- collegamento delle preferenze al motore esistente;
- scansione one-shot, avanzamento, annullamento e riepiloghi aggregati;
- applicazione dell'ordine scelto senza rileggere messaggi già elaborati;
- quiz opzionale e destinazioni operative con gli stessi guardrail correnti;
- più account Gmail e Yahoo, con credenziali, regole, database e controlli separati;
- calibrazione iniziale fortemente consigliata e stato visibile per account;
- Cestino diretto bloccato nel worker finché la calibrazione non è sufficiente;
- commit del lotto solo a classificazione conclusa, per annullamenti prevedibili.
- launcher separato per usare subito la nuova GUI senza sostituire il prototipo;
- identità pubblica InboxLume, namespace e comandi coerenti, con shim temporanei
  per il prototipo e riuso sicuro di preferenze e credenziali già presenti;
- esclusioni Git e audit dei candidati al commit contro dati e percorsi personali.

Il milestone è stato verificato esclusivamente con provider e credenziali finti: non
sono state aperte connessioni alle caselle reali durante lo sviluppo.

## Milestone 4 — Pianificazione multipiattaforma

Stato: completato.

- pianificazione opzionale, disattivata finché l'utente non la conferma;
- rilevamento automatico del sistema operativo;
- integrazione nativa con `launchd` su macOS, Utilità di pianificazione su Windows
  e timer `systemd` utente su Linux;
- creazione, aggiornamento, verifica e rimozione della sola attività InboxLume;
- esecuzione one-shot: il modello viene caricato per il lotto e poi chiuso;
- account, orario, frequenza, dimensione del lotto e destinazione indipendenti;
- diagnostica chiara quando il servizio nativo non è disponibile.

La pianificazione non deve poter ampliare i permessi del motore né creare comandi
generici: avvia esclusivamente l'entry point controllato di InboxLume.
Il contratto operativo e descritto in [SCHEDULING.md](SCHEDULING.md).

## Milestone 5 — Modelli locali e compatibilità hardware

Stato: completato.

- profili controllati Qwen 8B leggero, Gemma 12B bilanciato e Gemma 26B-A4B
  consigliato, salvati separatamente per account;
- rilevamento passivo di sistema, architettura, RAM, runtime e cache, senza caricare
  né scaricare modelli;
- MLX opzionale su Apple Silicon e profilo Ollama predisposto per i tre sistemi;
- selezione GUI propagata a quiz, scansioni manuali e pianificate;
- migrazione delle preferenze precedenti senza cambiare il modello già usato;
- soglie più severe e sola Quarantena per i modelli meno validati;
- benchmark documentati di qualità, falsi positivi, RAM e velocità.

Il contratto dei profili e i limiti di compatibilità sono descritti in
[LOCAL_MODELS.md](LOCAL_MODELS.md).

## Milestone 6 — Pubblicazione

Stato: predisposizione locale completata; pubblicazione bloccata.

- CI di test sui tre sistemi e packaging smoke test manuale, senza upload;
- packaging unsigned predisposto e template di firma/installer per i tre sistemi;
- release gate versionato, chiuso finché perimetro, licenza, asset, pacchetti e
  revisione di sicurezza non saranno completati e autorizzati;
- documentazione utente, contributi, changelog, inventario permessi e checklist;
- screenshot sintetico, articolo tecnico e sito statico GitHub Pages predisposti
  localmente, senza analytics o deploy;
- audit privacy integrato nella CI.

Non esistono workflow di release, pubblicazione artifact o GitHub Pages. Firma,
notarizzazione e release pubblica restano intenzionalmente da eseguire soltanto dopo
le funzionalità concordate e una nuova autorizzazione esplicita.

## Milestone 7 — Safety Governor personale, prima fase

Stato: evidenza shadow e primo gate operativo per Quarantena completati.

- evidenza separata per account e profilo modello-policy;
- collegamento locale tramite HMAC tra proposte di Quarantena e correzioni del quiz;
- conteggi aggregati per famiglia senza ID o testo in chiaro;
- limite superiore esatto unilaterale di Clopper–Pearson al 95%;
- obiettivo di ricerca dell'1% e stati di raccolta/qualificazione visibili nella GUI;
- livello operativo facoltativo, adattivo e separato per account/modello/famiglia;
- evidenza insufficiente non altera il filtro ordinario; soltanto errori ripetuti
  con limite inferiore sopra l'obiettivo restringono la famiglia interessata;
- soltanto proposte già ammesse dalla policy possono raggiungere la Quarantena;
- Cestino diretto ordinario indipendente dal Governor, con i propri vincoli;
- autorità del Governor sul Cestino come capacità separata: modello supportato,
  almeno 299 revisioni conclusive e zero correzioni `Tieni` nell'inviluppo globale
  e nella famiglia;
- eliminazione permanente e svuotamento del Cestino non sono autorizzati.

Deriva temporale e backtest controfattuale restano milestone separati. Il contratto è descritto in
[SAFETY_GOVERNOR.md](SAFETY_GOVERNOR.md).

## Milestone 8 — Safety Lab, backtest storico versionato

Stato: primo componente completato in modalità informativa.

- snapshot aggregati immutabili per account, profilo modello-policy e motore
  `historical-v1`;
- nuova versione registrata soltanto quando cambia l'evidenza;
- confronto con lo snapshot precedente e regressioni protettive specifiche per
  famiglia quando emergono nuovi `Tieni` o ripristini;
- nessuna rilettura della casella, nessun caricamento del modello e nessuna azione
  autorizzata;
- comando esplicito nella GUI e risultato bilingue.

Deriva temporale, perturbazioni controfattuali e confronto di una nuova policy
prima dell'attivazione restano i componenti successivi. Il contratto è descritto
in [SAFETY_BACKTEST.md](SAFETY_BACKTEST.md).

## Milestone 9 — Stima locale della durata

Stato: completato.

- conteggio esplicito dei soli ID idonei non ancora elaborati, senza leggere corpi;
- nessun caricamento o download del modello e nessuna modifica alla casella;
- intervallo prudenziale basato su modello, hardware, provider, destinazione e
  stato del Governor;
- apprendimento dai tempi aggregati delle sole sessioni locali corrispondenti;
- affidabilità bassa, media o alta mostrata senza promettere un tempo esatto;
- supporto sia al limite finito sia a `Tutte le idonee` per Gmail e Yahoo.

Il contratto è descritto in
[SCAN_DURATION_ESTIMATE.md](SCAN_DURATION_ESTIMATE.md).

## Milestone 10 — Deriva temporale delle preferenze

Stato: primo componente completato.

- confronto locale per famiglia tra ultimi 45 giorni e storico precedente fino a
  180 giorni;
- pesi distinti per apertura, stella/importanza, ripristino e risposta del quiz;
- soglie minime di messaggi ed evidenza per evitare inferenze da una singola
  apertura;
- deriva protettiva limitata alla famiglia interessata e attiva soltanto con il
  Governor operativo;
- calo d’interesse visibile ma incapace di autorizzare più cleanup;
- nessuna rilettura della casella, nessun modello e nessuna azione retroattiva.

Il contratto è descritto in [TEMPORAL_DRIFT.md](TEMPORAL_DRIFT.md). Preference
Weather con regimi multipli e decadimento appreso resta un’evoluzione successiva.

## Milestone 11 — LumeGraph

Stato: nucleo completo del grafo implementato e collegato al gate Proof.

- cicli per OTP, ordini, spedizioni, prenotazioni, fatture, pagamenti e sicurezza;
- stati, condizioni residue e quattro dimensioni di utilità indipendenti;
- inferenza locale separata dalla classificazione operativa esistente;
- relazioni tra successori tramite soli riferimenti HMAC, anche con mittenti diversi;
- nessun testo, ID provider, riferimento estratto o data esatta nel ledger;
- riepilogo aggregato bilingue nella GUI e costo incluso nella stima della durata;
- fallimento isolato dal filtro ordinario;
- nessuna autorità derivante dal solo stato del grafo.

Il contratto è descritto in [LUMEGRAPH.md](LUMEGRAPH.md).

## Milestone 12 — Proof of Obsolescence

Stato: implementata e operativa.

- testimoni per OTP scaduti, date di offerta verificate, successori di spedizione
  e consenso tra modello, correzioni ripetute e regime recente;
- ordinamento dei successori tramite settimana, senza salvare date esatte;
- `Tieni` e ogni utilità probatoria, personale o di sicurezza prevalgono sempre;
- può promuovere Revisione soltanto a Quarantena reversibile;
- con Cestino diretto conferma candidati ordinari ma non promuove Revisione;
- nessuna eliminazione permanente o svuotamento del Cestino.

Contratto bilingue: [PROOF_OF_OBSOLESCENCE.md](PROOF_OF_OBSOLESCENCE.md) e
[it/PROOF_OF_OBSOLESCENCE.md](it/PROOF_OF_OBSOLESCENCE.md).

## Milestone 13 — Local Threat Protection

Stato: motore, screening tecnico configurabile, consenso semantico mirato, policy
protettiva, ledger privato, spiegazioni GUI bilingui e backtest sintetico versionato
eseguibile dalla GUI implementati; indicatori phishing visibili e additivi
implementati; baseline personali ancora da completare.

- segnali deterministici offline e seconda inferenza locale indipendente;
- consenso asimmetrico: il solo modello non può dichiarare rischio alto;
- rischio `high` o `critical` trasforma qualsiasi candidato di cleanup in
  Revisione, senza indebolire un `keep` già stabilito;
- Proof of Obsolescence, recupero di lotti precedenti, Quarantena e Cestino
  diretto rispettano lo stesso blocco;
- ledger per account e profilo composto solo da HMAC, bucket e vocabolario
  controllato, mai testo o identificativi provider.
- la GUI mostra soltanto conteggi aggregati di valutazioni, messaggi protetti,
  verifiche semantiche mirate e fallback; la stima della durata distingue controllo
  tecnico e IA locale mirata e ignora automaticamente i campioni di una pipeline
  diversa.
- corpus installabile di 25 casi sintetici EN/IT/misti, con benigni difficili,
  impronta riproducibile e metriche aggregate; non accede alle caselle e non
  certifica né autorizza azioni operative.
- esecuzione GUI in processo separato con il modello scelto, avanzamento, Stop,
  resoconto bilingue e scaricamento finale del modello.
- indicatore phishing additivo distinto dalla Quarantena: Gmail aggiunge l’etichetta
  `InboxLume/Sospetto phishing` preservando `INBOX` e le altre etichette; Yahoo
  aggiunge soltanto `\Flagged`, preservando Inbox e tutti i flag esistenti, senza
  `MOVE`. La stella Yahoo non è esclusiva di InboxLume. Non esistono passaggi verso
  il Cestino né autorità di cleanup.

La modalità antiphishing a due livelli è ora separata per account: il primo livello
tecnico offline può essere usato da solo oppure seguito da Gemma/Qwen soltanto per
messaggi già sospetti. Mantiene il consenso tra segnali indipendenti, non autorizza
mai cleanup e mostra i passaggi semantici effettivi nel resoconto del lotto.

Contratto bilingue: [THREAT_DETECTION.md](THREAT_DETECTION.md) e
[it/THREAT_DETECTION.md](it/THREAT_DETECTION.md). Backtest:
[THREAT_BACKTEST.md](THREAT_BACKTEST.md) e
[it/THREAT_BACKTEST.md](it/THREAT_BACKTEST.md).

## Milestone 14 futuro — Danger Zone irreversibile

Stato: specifica conservata, non implementata.

- modulo separato, spento e non selezionabile per impostazione predefinita;
- requisiti più severi del Governor ordinario: evidenza molto ampia senza errori,
  stabilità temporale, backtest locale e modello esplicitamente approvato;
- anteprima e conferma umana fresca per ogni lotto;
- mai eseguibile da pianificazione o agente autonomo;
- nessun accesso a Posta inviata, Bozze o altre parti dell'account.
- prima dell'implementazione verrà scelto un gate locale distinto tra PIN,
  password, credenziale del sistema operativo o un meccanismo equivalente; la
  scelta non è ancora stata presa.

## Milestone 15 futuro — Scansione in tempo reale

Stato: specifica conservata, non implementata e fortemente sconsigliata.

- opt-in esplicito e sessione visibile, arrestabile immediatamente;
- acquisisce un cursore al momento di `Avvia` e considera soltanto messaggi Inbox
  arrivati dopo quel momento e prima di `Interrompi`, mai l'archivio precedente;
- separata per account; non accede mai a Posta inviata, Bozze o altre cartelle;
- il modello locale può restare caricato soltanto durante quella sessione, con
  indicazione chiara dell'uso di RAM/CPU/GPU, e viene scaricato allo stop;
- nessuna attivazione implicita all'avvio e nessuna persistenza silenziosa come
  daemon; la scansione one-shot e pianificata resta la modalità consigliata.

## Evoluzione approvata — InboxLume Private Twin

Dopo la base multipiattaforma verrà sviluppato un gemello privato dell'inbox:
memoria personale temporale, baseline delle relazioni, rilevamento delle anomalie
antiphishing e automazione soltanto con consenso tra segnali indipendenti. La
specifica e i criteri di sicurezza sono in
[PRIVATE_TWIN.md](PRIVATE_TWIN.md). La funzione non è ancora implementata.
La ricerca sui differenziatori pionieristici, incluso il protocollo flagship
`LumeGraph -> Proof of Obsolescence -> Safety Governor -> capability firmata`, è
raccolta in [PIONEERING_FEATURES.md](PIONEERING_FEATURES.md).
