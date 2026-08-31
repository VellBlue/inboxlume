# Cosa è successo quando l'abbiamo acceso davvero

> [English version](../ENGINEERING_LOG.md) · Versione italiana curata per il proprio contesto
>
> Diario di ingegneria, 31 agosto 2026. Stato: raccoglie osservazioni da un
> repository di sviluppo, non da una release.
> [Torna all'articolo principale](article.html).

I documenti di progetto descrivono come un sistema dovrebbe comportarsi. Questo
registra invece cosa è accaduto la prima volta che InboxLume ha incontrato un
modello locale vero, un server IMAP vero e un Mac vero, nello stesso giorno. Ogni
numero riportato qui viene da un'esecuzione registrata nel repository, e la
diagnostica di sicurezza che ha prodotto il primo di essi può essere rieseguita da
chiunque senza collegare alcun account di posta.

Non sono curiosità. Ognuno di questi casi è una classe di difetti che un documento
di progetto non può intercettare, perché in tutti il codice faceva esattamente ciò
per cui era stato scritto.

## 1. Il modello aveva ragione, e la risposta veniva buttata via

Il backtest sintetico sulle minacce è stato eseguito per la prima volta con un
modello locale reale invece che con un sostituto di test: Gemma 12B tramite MLX su
Apple Silicon, sui 25 casi inclusi, senza account e senza rete.

Il rapporto ha restituito **14 fallimenti del modello su 25 casi** — e i 14
comprendevano **tutti e 12 i casi malevoli**.

Il modello non era in difficoltà. Leggendo il suo output grezzo, riconosceva il
phishing correttamente, con l'intento giusto e i codici di motivazione giusti.
Rispondeva:

```json
{ "verdict": "likely_phishing", "intent": "credential_theft", "confidence": 5 }
```

Il parser esige una confidenza fra 0 e 1. Il modello aveva risposto su una scala
da uno a cinque. In alcuni casi restituiva anche `"impersonation": "none"` dove
serviva un booleano JSON. Il prompt chiedeva un campo chiamato `confidence` e non
diceva mai cosa fosse una confidenza. Il prompt di classificazione, scritto prima,
lo dichiarava — `number 0..1` — ed era l'unico dei tre a non fallire.

Ogni risposta scartata veniva sostituita da un giudizio "incerto". Vale la pena
dirlo senza attenuazioni: **la protezione dalle minacce girava sui soli segnali
lessicali deterministici, proprio sui messaggi per cui esiste.** Il sottosistema
non era spento. Veniva interrogato e poi ignorato.

La correzione è un paragrafo di prompt che dichiara il contratto che il parser già
imponeva. I fallimenti sono passati da **14 a 0**.

La parte interessante è ciò che non è cambiato. Precisione e recall sono rimaste a
**0,9167**, esattamente dov'erano. Il livello deterministico stava reggendo da
solo l'intero risultato.

> Una metrica che non si muove quando un sottosistema muore non stava misurando
> quel sottosistema. Un punteggio aggregato può nascondere un componente
> silenziosamente disattivato da sempre.

Il conteggio dei fallimenti è ora un campo di primo piano del rapporto, alla pari
di precisione e recall, perché è il campo che rivela questa condizione.

## 2. Una ricevuta che non sapeva rispondere all'unica domanda che conta

Quando una scansione viene interrotta, il record locale che lasciava conteneva
`processed = 0` e `applied = 0`.

Sono anche i valori che lascia un'esecuzione fallita prima di cominciare. Il record
non permetteva quindi di distinguere una scansione che non aveva mai toccato la
casella da una fermatasi a metà dello spostamento dei messaggi.

Dopo un errore la domanda dell'utente non è "qual è stato il problema". È **"ha
toccato la mia casella?"** Un valore predefinito risponde in modo sbagliato
avendo però l'aspetto di una risposta.

Il record contiene ora la fase realmente raggiunta, il conteggio realmente
elaborato e un esito esplicito della casella fra `changed`, `unchanged` e
`unknown`, dove `unknown` significa che una modifica era già iniziata e la casella
va verificata. Un'interruzione reale ora si legge così:

```json
{ "status": "failed", "phase": "classification", "processed": 0,
  "mailbox_outcome": "unchanged" }
```

Questo è dimostrabile. La casella non è stata toccata, e il record lo afferma.

La metà onesta di questo capitolo è ciò che non abbiamo fatto. I record scritti
prima della modifica non possono essere aggiornati. Uno completato conserva un
esito dimostrabile, perché i suoi conteggi erano sempre stati reali; uno fallito
dichiara che il proprio esito non è dimostrabile, perché non lo è mai stato.
Ricostruire una storia mai registrata avrebbe prodotto un documento più
soddisfacente e meno affidabile.

## 3. Una suite di test verde che non dimostrava nulla

L'azione di revisione, che permette di riesaminare ciò che il sistema ha proposto,
restituiva **0 candidati** per una scansione che aveva appena spostato 64 messaggi
nella cartella di quarantena reversibile.

Uno spostamento IMAP assegna al messaggio un UID nuovo nella cartella di
destinazione, quindi l'identità registrata durante la scansione non corrisponde
più a nulla di visibile alla revisione. Il ripiego previsto era il puntatore
`COPYUID` di UIDPLUS restituito da `MOVE`.

Quel puntatore non arriva mai. `imaplib.uid()` restituisce le risposte untagged
`FETCH`; RFC 6851 colloca `COPYUID` nella riga tagged `OK`; e un `MOVE` non
produce alcun `FETCH`. La tabella destinata a conservarli è rimasta vuota su
**121 quarantene reali**.

Il test unitario passava sempre. Il suo client finto rispondeva a uno spostamento
con:

```python
return "OK", [b"moved"]
```

Un server reale non mette `COPYUID` lì, e nemmeno il finto ci metteva qualcosa. Il
test verificava che il codice gestisse una forma di risposta che il protocollo non
produce in quella posizione: poteva soltanto passare.

> Un sostituto più semplice del protocollo mette alla prova il codice contro un
> server che non esiste. Più la suite è verde, più a lungo la lacuna sopravvive.

Il ricollegamento usa ora il `Message-ID` RFC, che sopravvive allo spostamento ed
è già conservato soltanto come HMAC, mai come testo dell'intestazione. Misurato su
una casella reale con 65 messaggi in quarantena: **0** ritrovabili per UID, **0**
per puntatore, **65** per `Message-ID`, nessuno irrisolto. Il percorso morto è
stato rimosso invece di restare lì con l'aspetto di codice vivo.

Rimuoverlo ha fatto emergere un secondo difetto introdotto dalla prima
correzione: il percorso vecchio escludeva anche le proposte già valutate
dall'utente, quello nuovo no, perché il controllo a monte usava l'identità
successiva allo spostamento. Senza, una proposta già giudicata sarebbe tornata a
chiedere. Sostituire un meccanismo significa ereditare ogni garanzia che offriva
in silenzio.

## 4. Una facoltà che il sistema si rifiuta di avere

La protezione dalle minacce combina due livelli indipendenti: segnali
deterministici su identità, collegamenti e autenticazione, e un giudizio semantico
del modello locale.

La combinazione è **additiva**. Il punteggio semantico si somma a quello
deterministico e non può mai sottrarvisi. Un verdetto benigno contribuisce zero.

Questo ha un costo, e il costo è il punto. È stato aggiunto un terzo livello di
protezione che interroga il modello locale soltanto sui messaggi che il livello
tecnico segnala già come allarme, invece che su ogni messaggio con una qualsiasi
anomalia. Spende molte meno inferenze e può rafforzare un rilevamento. **Non può
scartare un falso positivo**, per costruzione, e nessuna configurazione glielo
consente.

L'alternativa — lasciare che un modello linguistico revochi un rilevamento di
sicurezza deterministico — significherebbe accettare la confidenza di un modello
come motivo per archiviare prove che quel modello non sa verificare, proprio sui
messaggi che un attaccante sta cercando di far passare. Un test blocca ora questa
modifica, così indebolirla deve essere una decisione e non un riordino del codice.

> Dichiarare cosa a un sistema non è permesso fare, e quanto costa quel rifiuto,
> pesa più di qualsiasi affermazione su ciò che sa fare.

## 5. Il Mac a cui è stato detto che non era un Mac

L'applicazione riportava *"MLX richiede attualmente macOS su Apple Silicon"* su un
Mac Apple Silicon, e disattivava la propria azione principale. La riga di stato
diceva `Sistema rilevato: Darwin x86_64`.

LaunchServices avviava il bundle tradotto da Rosetta. Ogni processo figlio eredita
l'architettura tradotta, MLX non ha alcuna build x86_64, e così tutti e tre i
profili di modello locale risultavano non disponibili su una macchina che li
supporta pienamente.

Il bundle dichiara ora `LSRequiresNativeExecution` e una priorità di architettura
con `arm64` in testa, così la traduzione viene rifiutata all'origine invece che
riparata a posteriori; una guardia nel launcher resta come rete di sicurezza per
una shell già tradotta.

Il messaggio contava quanto il difetto. Incolpare l'hardware spinge chi legge a
valutare l'acquisto di un altro computer per quello che è un problema di
configurazione dell'avvio. La diagnosi ora distingue un processo tradotto da una
piattaforma davvero non supportata, e dice quale dei due sia.

> Un messaggio di errore fa parte della superficie di sicurezza. Una spiegazione
> sicura di sé e sbagliata costa a chi legge più di un onesto "non determinato".

## Cosa può verificare chi legge

La diagnostica di sicurezza è riproducibile senza account, senza accesso di rete e
senza toccare alcuna casella:

```bash
python -m inboxlume.desktop_worker threat-backtest --backend gemma12
```

Valuta in memoria il corpus incluso `synthetic-threat-corpus-v1` e produce solo
output aggregato: conteggi della matrice di confusione, metriche per vocabolario
controllato di lingua e scenario, il numero di fallimenti del modello e
un'impronta SHA-256 del corpus. Non contiene testo dei casi né identità dei
messaggi, e non autorizza mai un'azione sulla casella.

## Cosa non possiamo ancora affermare

Il corpus attuale è di 25 casi. Dopo la correzione del prompt l'esecuzione riporta
precisione 0,9167, recall 0,9167, zero fallimenti del modello — e **continua a non
superare la propria diagnostica**, perché un messaggio benigno italiano viene
segnalato, con un tasso di falsi positivi osservato di 0,0769 contro un obiettivo
di 0,05. Un caso malevolo italiano resta non rilevato.

Con questo corpus il limite superiore al 95% sul tasso di falsi positivi benigni è
**0,33**. Un campione così piccolo non può certificare nulla, e il rapporto stampa
quel limite accanto alle metriche perché il numero non venga letto come una
rassicurazione.

Oltre a questo: nessun pacchetto è stato costruito e collaudato sulle tre
piattaforme dichiarate, nessuna licenza è stata scelta, il comportamento dei
provider è stato verificato su un solo account reale invece che su una matrice di
prova, e il release gate resta chiuso. Questo diario è la prova che il sistema
viene misurato, non la prova che sia pronto.

> L'affermazione che questo progetto è disposto a difendere è ristretta: ogni
> azione automatica dovrebbe saper dichiarare cosa ha esaurito l'utilità del
> messaggio, quale evidenza specifica dell'account la sostiene e quale facoltà
> limitata e reversibile l'ha autorizzata. Tutto quanto sopra è il lavoro di
> scoprire dove quell'affermazione non è ancora vera.
