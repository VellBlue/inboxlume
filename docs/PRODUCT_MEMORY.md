# InboxLume — memoria di prodotto

Questa è la fonte di verità sanificata per le decisioni concordate sul prodotto.
Non contiene account, indirizzi, credenziali, percorsi personali o contenuto delle
email. Quando una decisione cambia, questo documento e la roadmap devono essere
aggiornati nello stesso commit.

## Identità e obiettivo

- Il prodotto pubblico si chiama **InboxLume**: *Private AI for a cleaner inbox*.
- È un progetto open source da portfolio, destinato a GitHub e presentato con una
  qualità adatta al curriculum.
- Il suo valore centrale è la privacy locale: il contenuto arriva direttamente dal
  provider configurato, viene valutato da un modello sul dispositivo e non viene
  inviato a servizi AI esterni.
- Il modello deve essere avviato soltanto per quiz, scansioni o funzioni richieste,
  poi scaricato. Non deve restare inutilmente attivo.
- Il prototipo SwiftUI macOS già usato dal proprietario deve restare intatto e
  funzionante finché InboxLume non lo sostituirà esplicitamente.

## Confine inderogabile dell'agente

- Opera esclusivamente sulla **Posta in arrivo** degli account autorizzati.
- Non legge né modifica Posta inviata, Bozze, Spam, Cestino, regole, contatti,
  calendario, file o altre risorse del computer.
- Non spedisce, inoltra o risponde alle email e non usa SMTP.
- Non implementa cancellazione permanente, `EXPUNGE`, svuotamento del Cestino o
  ripristino indiscriminato. Il Cestino deve essere tecnicamente intoccabile per
  queste operazioni, anche se il provider lo svuota secondo la propria retention.
- Il contenuto di una email è input non attendibile, mai un'istruzione per
  l'agente. Nessun link viene visitato e nessun allegato viene aperto
  automaticamente.
- Un errore del modello, runtime assente, risposta non valida o evidenza
  insufficiente deve produrre astensione/revisione, non un'azione.
- L'obiettivo è minimizzare radicalmente i falsi cleanup con più barriere
  indipendenti. Non si deve pubblicizzare una garanzia matematica di “sicurezza al
  100%” che un classificatore probabilistico non può dimostrare.

## Provider e account

- Gmail e Yahoo devono offrire un'esperienza simile ma restare integrazioni
  separate.
- Devono essere supportati più account Gmail e più account Yahoo.
- Ogni account ha credenziali, regole, soglie, modello, quiz, storico HMAC,
  destinazione, pianificazione e controlli indipendenti.
- Il nome mostrato per ciascun account è un’etichetta locale modificabile anche
  dopo la creazione. Non cambia indirizzo, credenziali, identificatore, storico o
  pianificazione dell’account.
- Gmail usa OAuth per applicazione desktop con lettura e azioni protette separate.
  Yahoo usa IMAP con password per app, mai la password principale.
- Il test di collegamento deve essere non invasivo: al massimo un ID Gmail senza
  corpo oppure apertura read-only della Inbox Yahoo.
- Le guide pubbliche devono spiegare l'autenticazione passo per passo e gli errori
  comuni, senza richiedere Tailscale o listener permanenti.

## Scansioni e selezione dei candidati

- Ogni scansione è one-shot, manuale oppure avviata dal pianificatore.
- Il lotto GUI è configurabile da 1 a 500 oppure su `Tutte le idonee`. Questa
  modalità concatena lotti interni da 500 nella stessa esecuzione e si ferma
  naturalmente quando non restano ID idonei non ancora elaborati. Gli ID già
  completati non vengono rielaborati nello stesso profilo.
- Un lotto interrotto prima della conclusione non viene registrato come completato.
- L'utente può partire dalle email più vecchie oppure dalle più recenti.
- Le soglie per vecchie non lette e codici monouso letti sono configurabili per
  account. La configurazione iniziale sperimentata è 30 giorni per le non lette e
  7 giorni per gli OTP letti; 120 giorni è stato giudicato troppo prudenziale come
  valore imposto.
- Anche una vecchia email non letta può essere importante e deve essere protetta in
  base al contenuto. Età, stato letto/non letto, categoria e mittente non bastano da
  soli per decidere.
- Le email inviate a se stessi sono un archivio personale comune: se l'indirizzo
  del mittente coincide esattamente con almeno un destinatario, un guardrail
  deterministico deve produrre `Tieni` prima di qualunque valutazione del modello,
  indipendentemente da età, categoria, allegati e Governor. Il confronto avviene
  solo in memoria e non salva indirizzi in chiaro.
- Ricevute e conferme di operazioni economiche o di servizio sono sempre `Tieni`,
  senza scadenza: bonifici, pagamenti, addebiti/accrediti, tasse universitarie,
  ricariche telefoniche e casi equivalenti. Questa precedenza vale anche se il
  modello assegna per errore una categoria eliminabile, se la mail è letta o molto
  vecchia e se il Governor è attivo.
- Le email bancarie operative sono protette; la pubblicità proveniente da una banca
  non eredita la protezione del mittente e viene valutata per il contenuto specifico.
- Gli avvisi di accesso non letti sono protetti. Un accesso sospetto/non
  riconosciuto, un cambio password o un possibile account compromesso è sempre
  `Tieni`. Soltanto un avviso ordinario già letto da almeno 90 giorni può diventare
  candidato reversibile; la soglia non si applica mai alle ricevute. Il futuro
  rilevamento phishing dovrà aggiungere protezione/astensione senza indebolire
  questi guardrail.
- Il classificatore deve leggere localmente il contenuto necessario e distinguere
  almeno: importante, bancaria, scuola, medico/legale, sicurezza, codice monouso,
  transazionale, personale, social, pubblicità, spam, altro e incerta.
- Una decisione riguarda il singolo messaggio. Scartare una mail non deve
  condannare automaticamente tutto il mittente o tutta la categoria.
- Messaggi molto simili a esempi confermati `Non tenere` possono ereditare quel
  segnale; esempi contrastanti o caratteristiche protette devono forzare revisione.
- La scansione operativa applica automaticamente le azioni ammesse. Il quiz è una
  funzione separata e non deve essere richiesto dopo ogni lotto.

## Quiz, apprendimento e comportamento nel tempo

- Il quiz iniziale è fortemente consigliato e vicino a un onboarding obbligato;
  l'utente deve poter proseguire prudentemente in Quarantena dopo conferma.
- Il target iniziale attuale è 40 esempi diversi, con almeno 3 `Tieni` e 20
  `Non tenere`. Non cresce linearmente con 66.000 o più messaggi: conta la copertura
  di famiglie e casi ambigui. Non è una certificazione statistica.
- Le sessioni successive e il numero totale di risposte sono illimitati. La GUI può
  presentare pagine brevi senza confondere la dimensione della pagina con il totale.
- Le etichette sono `Tieni`, `Non tenere`, `Non so`; le correzioni protettive devono
  prevalere sulle proposte automatiche.
- Le risposte e le similarità devono essere archiviate senza testo email in chiaro.
- Gli inviti successivi devono essere micro-quiz attivi di 5–10 esempi, proposti
  soltanto quando aumentano davvero la copertura: nuova famiglia, ambiguità,
  conflitto, deriva o requisito avanzato ancora privo di evidenza. Devono avere un
  limite di frequenza, poter essere ignorati e cessare quando il guadagno
  informativo stimato è marginale. Il conteggio globale da solo non giustifica un
  altro quiz.
- InboxLume apprende già aperture, stelle e importanza Gmail e i ripristini da
  Quarantena/Cestino su Gmail e Yahoo. Il ripristino conta soltanto se InboxLume
  aveva prima spostato quel messaggio; viene conservata solo l'identità HMAC. Su
  Yahoo la prima osservazione crea una baseline UID senza inferenze retroattive e
  le riconciliazioni successive leggono soltanto l'header `Message-ID`, mai il
  corpo. Un'apertura resta un segnale debole; l'interesse per periodo e il
  decadimento temporale restano da implementare.
- La correzione deve cercare la caratteristica del contenuto che ha causato
  l'errore, non creare semplicemente blacklist o whitelist globali del mittente.

## Quarantena, Cestino e reversibilità

- La **Quarantena** è la destinazione consigliata e reversibile per ogni account.
- Su Gmail è un'etichetta visibile (`InboxLume/Quarantena`) e il messaggio può
  restare nella Inbox, così l'utente vede il contrassegno.
- Su Yahoo è una cartella dedicata con comportamento equivalente per quanto
  consentito da IMAP.
- Una preferenza separata per account può scegliere il Cestino diretto; deve essere
  calibrata, esplicita e indipendente tra Gmail e Yahoo.
- Il percorso consigliato resta manuale: revisionare la Quarantena nel provider e
  spostare in Cestino i messaggi selezionati; se si usa il Cestino diretto,
  ricontrollarlo e usare manualmente `Svuota Cestino` soltanto quando soddisfatti.
- Il passaggio finale dalla quarantena al Cestino può avvenire dopo almeno 3 giorni
  e solo dopo un nuovo controllo di guardrail e stato.
- Le retention del provider devono essere spiegate chiaramente: normalmente Gmail
  elimina dal Cestino dopo 30 giorni e Yahoo dopo 7 giorni. InboxLume non deve mai
  anticipare né invocare quello svuotamento.

## Pianificazione

- La pianificazione è opzionale e non viene mai attivata automaticamente.
- È separata per account e configura orario, frequenza, lotto, modello e
  destinazione.
- Deve rilevare il sistema operativo e usare il servizio nativo: `launchd` su
  macOS, Utilità di pianificazione su Windows e timer `systemd` utente su Linux.
- Sono previste esecuzioni giornaliere, settimanali e intervalli supportati, con una
  singola esecuzione protetta da lock e gate di calibrazione.
- Il computer deve essere acceso; InboxLume non deve tenerlo sveglio. La GUI deve
  consigliare orari in cui la macchina non è sotto carico, soprattutto con modelli
  grandi.
- Disattivare una pianificazione rimuove soltanto il job InboxLume dell'account.

## Modelli locali e profili hardware

- I profili approvati per la prima release sono controllati, non arbitrari:
  - **Leggero — Qwen 8B**, runtime Ollama, per hardware meno potente; qualità
    inferiore e policy più prudente;
  - **Bilanciato — Gemma 12B**, MLX su Apple Silicon nella prima integrazione;
  - **Consigliato — Gemma 4 26B-A4B**, MLX su Apple Silicon, qualità preferita.
- Benchmark preliminari sul Mac di sviluppo, da descrivere come osservazioni e non
  promesse universali: Qwen 8B circa 5,4 s per cinque messaggi sintetici incluso
  carico/scarico; Gemma 12B circa 8,7 s a freddo e picco 11,2 GB; Gemma 26B-A4B
  circa 9,7 s a freddo e picco 14,7 GB.
- Qwen 8B ha confuso più facilmente pubblicità legittima e spam: l'interfaccia deve
  dichiarare che un 8B non ha la qualità del profilo consigliato.
- Finché benchmark più ampi non dimostrano un rischio adeguato, Qwen 8B e Gemma 12B
  applicano soglie più severe e possono usare soltanto la Quarantena; il Cestino
  diretto calibrato è disponibile solo con Gemma 26B-A4B.
- La GUI deve rilevare in modo passivo RAM, sistema, runtime e cache; non deve
  scaricare modelli né caricarli durante il semplice rilevamento.
- Un profilo indisponibile deve essere spiegato e bloccato in sicurezza. Nessun
  nome modello arbitrario deve diventare comando o percorso.
- Per la compatibilità pubblica si privilegia un runtime comune Ollama/llama.cpp su
  macOS, Windows e Linux; MLX resta un'accelerazione opzionale Apple Silicon.
- I benchmark pubblici dovranno includere qualità, falsi cleanup, copertura,
  astensioni, RAM, latenza e versione esatta di modello/prompt/policy.

## Interfacce e distribuzione

- L’inglese è la lingua primaria del progetto pubblico, della GUI, del README,
  dell’articolo e del sito. Deve esistere anche una versione italiana curata per
  il proprio contesto, non una traduzione meccanica frase per frase.
- Le nuove installazioni partono in inglese. Le preferenze create dalle versioni
  precedenti, che offrivano soltanto l’italiano, migrano in italiano per non
  cambiare silenziosamente l’esperienza dell’utente. La lingua è una preferenza
  globale dell’interfaccia e non altera policy, account o dati email.
- Il classificatore tratta nello stesso lotto messaggi inglesi, italiani e misti:
  non esiste una lingua assegnata alla casella. Prompt Ollama e Gemma/MLX usano
  istruzioni canoniche in inglese e uno schema di output indipendente dalla lingua.
- La nuova GUI PySide6 deve restare semplice: selezione account, modello, soglie,
  ordine, lotto, destinazione, quiz, scansione, avanzamento, riepilogo e schedule.
- Deve essere utilizzabile già con gli account locali del proprietario, ma nessuna
  configurazione privata deve entrare nel progetto pubblico.
- Su macOS esiste un'app InboxLume con icona e avvio dal Dock; il prototipo Mail
  Guardian conserva app e launcher separati.
- La release pubblica richiederà packaging nativo, firma e istruzioni chiare per
  macOS, Windows e Linux; non si deve presentare l'attuale bundle di sviluppo come
  installer finale.

## Funzioni pionieristiche approvate

La specifica estesa è in [PIONEERING_FEATURES.md](PIONEERING_FEATURES.md). La catena
flagship prevista è:

```text
LumeGraph
  -> Proof of Obsolescence
  -> Safety Governor personale
  -> Counterfactual Safety Lab
  -> capability firmata
  -> esecutore ristretto
  -> quarantena reversibile
  -> correzione causale
```

Sono inoltre approvati come ricerca futura:

- **Preference Weather**, interessi a più scale temporali con decadimento;
- **Negative-Space Sentinel**, rilevamento locale di email attese ma mancanti;
- **Personal Phishing Immune System**, baseline personale e test difensivi offline;
- **Proof-Carrying Cleanup**, ricevute HMAC senza testo che limitano l'esecutore;
- **Verifiable Locality / Capability Firewall**, processi separati con rete,
  credenziali e permessi minimi;
- **Privacy Flight Recorder**, resoconto privo di contenuti sulle capacità usate;
- **Causal Correction**, correzioni specifiche sottoposte a simulazione locale.

Il **Safety Governor** mantiene l’evidenza shadow e offre un gate operativo
facoltativo:
collega tramite HMAC proposte di Quarantena, risposte del quiz e ripristini
osservati, calcola il limite
superiore binomiale unilaterale al 95% per account, profilo e famiglia, e mostra il
risultato nella GUI. Il Governor interseca la policy esistente senza sostituirla:
evidenza insufficiente lascia invariato il filtro ordinario; una famiglia viene
limitata soltanto con almeno 20 revisioni conclusive, tre falsi cleanup e limite
inferiore unilaterale al 95% sopra l'1%. La restrizione è specifica e reversibile
quando nuove conferme abbassano il rischio stimato. Il Cestino diretto ordinario
resta una preferenza indipendente con vincoli di modello, calibrazione, policy e
conferma: Governor spento e Governor acceso ma non qualificato producono lo stesso
percorso ordinario. Il Governor stesso ottiene autorità sul Cestino soltanto con
modello supportato, almeno 299 revisioni conclusive e zero correzioni `Tieni` sia
globalmente sia nella famiglia. Non autorizza mai cancellazione permanente o
svuotamento del Cestino.

Il primo componente del **Counterfactual Safety Lab** è ora operativo come
backtest storico `historical-v1`: crea snapshot soltanto quando cambiano i conteggi
aggregati HMAC-collegati, li separa per account e profilo modello-policy e segnala
come regressione protettiva nuove correzioni `Tieni` o ripristini per famiglia. Non
riapre email, non carica modelli e non autorizza azioni. Varianti controfattuali,
finestre di deriva e confronti tra nuove versioni della policy restano successivi.

Una futura **Danger Zone** potrà esporre operazioni irreversibili soltanto come
modulo separato, disattivato e non selezionabile finché non siano soddisfatti
requisiti più severi del Governor: campione molto ampio e senza falsi cleanup,
stabilità su finestre temporali, backtest locale superato, modello approvato e
attivazione esplicita. Anche dopo lo sblocco ogni lotto irreversibile richiederà
anteprima e conferma umana fresca; non sarà mai una destinazione pianificabile o
automatica. Questa è una direzione futura, non una capacità implementata.
Il suo gate di accesso locale — PIN, password, credenziale del sistema operativo
o alternativa equivalente — verrà deciso prima dell'implementazione e non è stato
ancora scelto.

Dopo il completamento del rilevamento phishing è conservato anche un milestone di
**scansione in tempo reale**, fortemente sconsigliato. Sarà un opt-in per account:
salverà un cursore all'avvio e analizzerà esclusivamente i nuovi messaggi Inbox
arrivati durante la sessione, fino allo stop. Non recupererà arretrati, non leggerà
Posta inviata e non resterà attivo o riavviabile silenziosamente. Il modello potrà
restare in RAM soltanto durante la finestra esplicitamente visibile e sarà
scaricato alla chiusura; one-shot e pianificazione restano le modalità consigliate.

Queste idee sono direzioni di sviluppo, non funzioni già disponibili e non devono
essere descritte come “uniche al mondo” senza verifica brevettuale professionale.

## LumeReply

- È un consigliere locale di risposta futuro integrato in Gmail e Yahoo tramite
  estensione browser e Native Messaging verso l'app desktop.
- Si attiva soltanto con un clic sulla mail aperta; nessuna analisi continua.
- Recupera soltanto quella mail Inbox, elenca domande/richieste/scadenze, propone
  toni configurabili, mostra punti coperti e impegni creati e si astiene in caso di
  contesto insufficiente o anomalia phishing.
- La prima release offre solo `Copia`: non compila bozze, non incolla, non invia e
  non accede a Posta inviata. Lo stile è configurato manualmente.
- Profili candidati: `Eco` one-shot predefinito, `Qualità` con modello grande e
  sessione calda breve solo come opzione esplicita con timeout.

## Sicurezza verificabile e pubblicazione

- Credenziali nel keyring nativo; preferenze, database e log nella directory dati
  utente; nessun contenuto email in chiaro nello stato applicativo.
- Account compartimentati. Nessun apprendimento incrociato senza consenso esplicito.
- Nessuna email, credenziale, token, ID reale, indirizzo, database, preferenza,
  log, screenshot privato o percorso personale può essere commesso o pubblicato.
- Esempi, test, screenshot, documentazione e sito devono usare solo dati sintetici
  sanificati. L'audit privacy dei candidati al commit è un gate di release.
- Il sito GitHub Pages e l'articolo tecnico presentano utilità, confronto
  locale/cloud, architettura, threat model, matematica della calibrazione,
  benchmark, limiti, falsi positivi e astensioni con linguaggio scientificamente
  onesto.
- La preparazione locale del Milestone 6 non autorizzava repository remoti. Il 31
  agosto 2026 l'utente ha autorizzato separatamente repository pubblico e GitHub
  Pages come anteprima di sviluppo, senza autorizzare release, artefatti, firma o
  pacchetti.
- Sorgente e documentazione usano Apache-2.0. Pesi dei modelli, dipendenze e dati
  dell'utente conservano le rispettive condizioni.
- Il release gate versionato resta chiuso e la versione resta di sviluppo fino a
  una distinta autorizzazione alla release, dopo perimetro finale, pacchetti e
  revisione di sicurezza.
- Le superfici pubbliche sono revisionate in inglese e italiano; screenshot e
  pagine hanno asset sintetici distinti per lingua. Una localizzazione incompleta
  blocca ogni aggiornamento pubblico.

## Ordine di sviluppo conservato

Subito dopo il backtest storico versionato, la prossima funzione approvata è una
**stima locale della durata della scansione**. Deve combinare il numero di email
idonee ancora da elaborare, profilo modello, benchmark osservati sulla macchina,
hardware rilevato e opzioni attive che aggiungono lavoro. La GUI dovrà mostrare una
durata complessiva prudenziale, aggiornarla con i tempi reali delle sessioni locali
e dichiarare chiaramente quando il campione non è ancora sufficiente. La stima non
deve caricare il modello, leggere corpi aggiuntivi o promettere un tempo esatto.

Stato del 30 agosto 2026: implementata. Il conteggio usa soltanto ID candidati,
rispetta il limite della sessione oppure esaurisce `Tutte le idonee`, e i tempi
reali vengono conservati esclusivamente come aggregati per account, profilo,
provider, destinazione, stato Governor e chiave hardware unidirezionale. La GUI
mostra intervallo, livello di affidabilità e limite del campione.

1. Completare profili modello, rilevamento hardware e policy prudenziali.
2. Packaging, autenticazione pubblica, documentazione e prima release verificata.
3. Estendere il Safety Governor operativo con backtest e deriva.
4. Validare LumeGraph shadow già implementato; poi aggiungere Proof of
   Obsolescence come gate separato ad alta precisione.
5. Capability firmata come requisito dell'esecutore.
6. Preference Weather e Causal Correction.
7. Negative-Space Sentinel e Personal Phishing Immune System.
8. LumeReply on-demand con confine Inbox-only invariato.

Stato del 30 agosto 2026: implementato anche il primo rilevatore di deriva
temporale `preference-drift-v1`. Confronta finestre recenti e storiche per famiglia
usando soltanto eventi HMAC con data. Una deriva protettiva qualificata può
limitare la Quarantena governata o revocare l’autorità aggiuntiva del Governor sul
Cestino; non amplia mai le azioni e non modifica il Cestino diretto ordinario.
Preference Weather con regimi multipli resta futuro.

Stato del 30 agosto 2026: implementato `lumegraph-v2`. Il grafo copre OTP,
ordini, spedizioni, prenotazioni, fatture, pagamenti e flussi di sicurezza; conserva
solo stati controllati, utilità separate e relazioni HMAC per account. L’inferenza
del ciclo di vita è separata dalla classificazione operativa, non legge corpi
aggiuntivi. Le sole osservazioni del grafo non autorizzano azioni.

Stato del 30 agosto 2026: implementata `proof-obsolescence-v1` come gate operativo
distinto. Verifica scadenza OTP, date esplicite di offerte, successori di spedizione
e consenso tra modello, correzioni simili e regime recente. Può promuovere
Revisione soltanto a Quarantena reversibile; con Cestino diretto non amplia la
selezione ordinaria. `Tieni`, ricevute, operazioni economiche, allegati, accessi ad
alto rischio e ogni utilità probatoria, personale o di sicurezza prevalgono sempre.
Il ledger salva soltanto HMAC, campi controllati e settimana, mai contenuto o data
esatta.

I test devono essere proporzionati al rischio: unitari e di integrazione con provider
finti, test del bundle reale e audit privacy. Benchmark costosi vanno ripetuti solo
quando cambiano modello, prompt, policy, runtime o hardware, non per routine.

Prossimo milestone approvato: progettare un rilevatore interamente locale di
phishing, truffe e frodi. Dovrà combinare reputazione e anomalie del mittente,
somiglianza a marchi imitati, incongruenze tra dominio, testo e link, errori o
caratteri insoliti, urgenza, richieste anomale di denaro/credenziali e falsi avvisi
di social, banche e corrieri. Nessun singolo indizio deve bastare; il risultato deve
mostrare rischio e motivazioni verificabili e proteggere per revisione i messaggi
sospetti, non eliminarli automaticamente.

Stato del primo incremento: implementato `threat-signals-v1` in forma definitiva.
Il nucleo estrae offline reason code controllati per incoerenze mittente/Reply-To,
imitazione del marchio, Punycode, alfabeti misti, controlli bidi, link IP/Punycode,
fallimenti SPF/DKIM/DMARC provenienti soltanto da header esplicitamente fidati,
richieste urgenti di credenziali o denaro e falsi costi di consegna. Non usa errori
grammaticali da soli, non conserva testo e non autorizza alcun cleanup. Prossimo
incremento: inferenza semantica locale strutturata e consenso con questi segnali.

Stato del secondo incremento: implementata l’inferenza semantica separata per
Gemma 12B/26B e Qwen con schema e vocabolario condivisi, prompt tool-free e output
strettamente validato. Il modello non riceve il punteggio tecnico. Il consenso non
permette al solo LLM di creare un rischio alto, richiede evidenza deterministica
indipendente e non consente mai a un verdetto benigno di sottrarre segnali tecnici.
Il risultato resta protettivo e privo di autorità di cleanup. Prossimo incremento:
integrazione nella policy e ledger privato.

Stato del terzo incremento: integrazione operativa completata. Ogni messaggio del
lotto riceve il consenso tecnico-semantico interamente locale; un livello `high` o
`critical` sostituisce Quarantena/Cestino con Revisione, mentre un `keep` esistente
resta intatto. Lo stesso blocco è applicato ai recuperi di lotti precedenti, alla
finalizzazione della Quarantena e a Proof of Obsolescence. Il ledger separato per
account e profilo conserva soltanto HMAC, bucket e codici ammessi, e aggiorna la
decisione shadow protetta senza salvare testo. Fallimenti dell'inferenza semantica
ricadono sui segnali deterministici e non interrompono il filtro ordinario.
Stato del quarto incremento: la GUI mostra in inglese e italiano lo stato della
Protezione locale dalle minacce, le valutazioni del lotto, i messaggi trattenuti
per Revisione, i fallback semantici e il totale privato, senza identità o testo.
I lotti interni della modalità illimitata aggregano gli stessi contatori. La stima
di durata include ora la seconda inferenza semantica obbligatoria e una versione
della pipeline impedisce ai campioni temporali precedenti di produrre sottostime.
Stato del quinto incremento: implementato `threat-backtest-v1` con corpus
installabile e versionato di 25 casi interamente sintetici EN/IT/misti. Misura
precisione, richiamo, falsi positivi, limite superiore Wilson al 95%, fallimenti
del modello e copertura per scenari controllati. Usa in memoria la stessa pipeline
tecnico-semantica, non accede a Gmail/Yahoo, non emette testo e non autorizza
azioni. Il superamento resta un obiettivo diagnostico preliminare, non una prova
statistica di sicurezza.

Stato del sesto incremento: il backtest antiphishing è eseguibile dal riquadro
dedicato della GUI con il modello selezionato, senza collegarsi agli account. Usa
un worker separato, mostra avanzamento e Stop, restituisce metriche aggregate in
inglese/italiano e scarica il modello anche a fine errore. Va implementato in un
incremento futuro anche un segnale visibile sul messaggio: etichetta Gmail
`InboxLume/Sospetto phishing`, separata dalla Quarantena e senza rimuovere la mail
dall’Inbox; per Yahoo serve un equivalente non distruttivo verificato prima di
sceglierlo.

Stato del settimo incremento: l’indicatore è operativo durante le scansioni con
azioni protette autorizzate. Gmail aggiunge soltanto l’etichetta utente
`InboxLume/Sospetto phishing`, senza rimuovere `INBOX` o altre etichette. Yahoo
aggiunge soltanto il flag IMAP `\Flagged`, visualizzato come stella, senza MOVE;
non cancella mai stelle preesistenti e la GUI chiarisce che la stella Yahoo non è
un segno esclusivo di InboxLume. Entrambe le azioni restano protettive, non
autorizzano cleanup e non persistono ID o testo nei resoconti.

Evoluzione approvata dell’antiphishing: rendere configurabile una pipeline a due
livelli, sempre locale e separata per account. Il livello tecnico dovrà offrire
una modalità **rapida**, senza Gemma/Qwen, e una modalità **approfondita**. Il
passaggio semantico del modello non dovrà più essere eseguito per ogni messaggio:
sarà opzionale e limitato ai casi già sospetti o ambigui secondo i segnali tecnici.
Il consenso tra evidenze indipendenti e il divieto assoluto di cleanup restano
invariati. La GUI e la stima durata dovranno mostrare chiaramente il livello scelto
e il numero previsto di passaggi semantici.

Stato dell’incremento successivo: la pipeline a due livelli è operativa. La modalità
rapida esegue soltanto segnali tecnici offline; la modalità mirata chiama Gemma/Qwen
soltanto per messaggi che possiedono già almeno un segnale tecnico. I campioni di
durata sono separati per modalità. Le valutazioni `high` o `critical`, quando le
azioni protette sono autorizzate, ricevono un indicatore additivo distinto dalla
Quarantena: Gmail aggiunge `InboxLume/Sospetto phishing` senza rimuovere `INBOX` o
altre etichette; Yahoo aggiunge soltanto `\Flagged`, senza `MOVE` e senza rimuovere
la Inbox o flag esistenti. La stella Yahoo non è esclusiva di InboxLume. Non viene
mai usato il Cestino, non può esistere eliminazione permanente e il rilevatore non
riceve autorità di cleanup.
