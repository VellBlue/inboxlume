# Cosa è successo durante le prime prove reali

> [English version](../ENGINEERING_LOG.md) · Versione italiana
>
> Diario di ingegneria, 31 agosto 2026. Descrive un progetto in sviluppo, non una
> versione pronta per la distribuzione.
> [Torna all'articolo principale](article.html).

I documenti di progetto descrivono come un sistema dovrebbe comportarsi. Questo
diario racconta invece cosa è accaduto durante le prime prove di InboxLume con un
modello locale, un server IMAP e un Mac reali. Ogni numero riportato proviene da
un'esecuzione documentata nel repository. La prima prova di sicurezza può essere
ripetuta da chiunque senza collegare un account di posta.

Questi casi mostrano problemi che un documento di progetto, da solo, non può
individuare: in ciascun caso il codice eseguiva esattamente le istruzioni ricevute,
ma quelle istruzioni erano incomplete o basate su un'ipotesi sbagliata.

## 1. Il modello riconosceva la minaccia, ma il programma scartava la risposta

Il test sui casi di minaccia già definiti è stato eseguito per la prima volta con
un modello locale reale, invece che con il simulatore usato nei test: Gemma 12B
tramite MLX su Apple Silicon, sui 25 casi sintetici inclusi nel progetto, senza
account e senza rete.

Prima della correzione, il programma non accettava **14 risposte su 25**, comprese
le risposte relative a **tutti e 12 i casi malevoli**.

Il modello non aveva sbagliato la valutazione. Nella risposta non ancora elaborata
riconosceva correttamente il phishing, indicava l'intento dell'attacco e forniva i
codici che spiegavano la decisione:

```json
{ "verdict": "likely_phishing", "intent": "credential_theft", "confidence": 5 }
```

Il componente che legge la risposta accetta un punteggio di affidabilità compreso
tra 0 e 1, ma il modello aveva usato una scala da 1 a 5. In alcuni casi restituiva
anche `"impersonation": "none"` dove il formato JSON richiedeva un valore
vero/falso. Le istruzioni chiedevano un campo chiamato `confidence`, senza
specificarne la scala. Un altro insieme di istruzioni, scritto in precedenza,
dichiarava chiaramente `number 0..1` ed era l'unico dei tre a non produrre risposte
incompatibili.

Ogni risposta incompatibile veniva sostituita da un giudizio "incerto". Di
conseguenza, **proprio sui messaggi sospetti, il risultato dipendeva soltanto da
regole lessicali fisse, cioè deterministiche.** Il modello veniva interrogato, ma
la sua risposta non contribuiva alla decisione.

La correzione specifica nelle istruzioni il formato che il programma già
richiedeva. Le risposte non accettate sono passate da **14 a 0**. Precisione e
richiamo (*recall*) sono rimasti a **0,9167**: le regole fisse avevano prodotto da
sole l'intero punteggio complessivo, nascondendo il mancato contributo del modello.

> Se una metrica non cambia quando un componente smette di contribuire, quella
> metrica non sta misurando davvero il suo funzionamento. Un punteggio complessivo
> può nascondere un componente rimasto inefficace fin dall'inizio.

Il numero di risposte incompatibili è ora mostrato nel rapporto insieme a
precisione e richiamo, perché è il dato che rende visibile questo problema.

## 2. Il registro non indicava se la scansione avesse modificato la casella

Quando una scansione si interrompeva, il registro locale salvava `processed = 0` e
`applied = 0`: gli stessi valori di un'esecuzione fallita prima di iniziare.

Non era quindi possibile distinguere una scansione che non aveva modificato nulla
da una scansione interrotta durante lo spostamento dei messaggi.

Dopo un errore, l'utente deve sapere soprattutto: **"InboxLume ha modificato la mia
casella?"** Il valore predefinito sembrava rispondere, ma poteva essere sbagliato.

Ora il registro indica la fase raggiunta, il numero effettivo di messaggi elaborati
e uno dei tre esiti: `changed` se la casella è stata modificata, `unchanged` se non
è stata modificata e `unknown` se una modifica era già iniziata e occorre
verificare. Un'interruzione reale ora si legge così:

```json
{ "status": "failed", "phase": "classification", "processed": 0,
  "mailbox_outcome": "unchanged" }
```

In questo caso il registro permette di dimostrare che la casella non è stata
modificata.

È importante chiarire anche ciò che non può essere recuperato. I registri creati
prima della correzione non contengono abbastanza informazioni per essere
aggiornati. Un'esecuzione completata mantiene un esito verificabile perché i
conteggi erano reali; per una vecchia esecuzione fallita, invece, il sistema
dichiara che l'esito non è dimostrabile. Inventare dati mai registrati renderebbe
il documento più rassicurante, ma meno affidabile.

## 3. I test risultavano superati, ma simulavano il protocollo nel modo sbagliato

La funzione di revisione, usata per riesaminare le proposte del sistema, mostrava
**0 candidati** subito dopo una scansione che aveva spostato 64 messaggi nella
Quarantena reversibile.

Quando IMAP sposta un messaggio, gli assegna un nuovo UID, cioè un nuovo
identificatore numerico valido nella cartella di destinazione. L'identificativo
registrato durante la scansione non corrisponde quindi più a quello visibile
durante la revisione. Il codice avrebbe dovuto ricavare la corrispondenza dal
valore `COPYUID` restituito dall'estensione UIDPLUS dopo il comando `MOVE`.

Il codice cercava però `COPYUID` nel punto sbagliato della risposta.
`imaplib.uid()` restituisce le risposte intermedie IMAP, dette *untagged*, come
`FETCH`. La RFC 6851 colloca invece `COPYUID` nella riga finale `OK`, detta
*tagged*, e `MOVE` non produce alcun `FETCH`. Di conseguenza, la tabella destinata
a conservare le nuove associazioni tra UID è rimasta vuota in **121 spostamenti
reali in Quarantena**.

Il test unitario passava sempre. Il suo client finto rispondeva a uno spostamento
con:

```python
return "OK", [b"moved"]
```

Un server reale non inserisce `COPYUID` in quella parte della risposta, e neppure
il simulatore forniva un valore utile. Il test verificava quindi una forma di
risposta che il protocollo reale non produce: non poteva rilevare il difetto.

> Se il simulatore semplifica troppo il protocollo, il codice viene provato contro
> un server che non esiste. I test possono risultare tutti superati mentre il
> difetto rimane.

Per ritrovare il messaggio, InboxLume usa ora il `Message-ID` definito dallo
standard email. Questo valore non cambia durante lo spostamento ed è conservato
soltanto come impronta crittografica HMAC, mai come testo leggibile
dell'intestazione. Su una casella reale con 65 messaggi in Quarantena, **0** sono
stati ritrovati per UID, **0** tramite il precedente puntatore e **65** tramite
`Message-ID`.

La rimozione del codice inutilizzato ha fatto emergere un secondo problema. Il
vecchio meccanismo escludeva anche le proposte già valutate dall'utente; il nuovo
collegamento tramite `Message-ID`, inizialmente, non lo faceva perché il controllo
precedente usava l'identificativo assegnato dopo lo spostamento. Senza un controllo
equivalente, una proposta già valutata sarebbe comparsa di nuovo. Quando si
sostituisce un meccanismo, occorre riprodurre anche le garanzie che forniva
indirettamente.

## 4. Il modello non può annullare un allarme tecnico

La protezione dalle minacce combina controlli tecnici su identità, collegamenti e
autenticazione con l'analisi del significato svolta dal modello locale.

Il modello può aumentare il livello di rischio, ma non può ridurre il punteggio
prodotto dai controlli tecnici. Se considera il messaggio innocuo, aggiunge zero e
lascia invariato l'allarme esistente.

Questa scelta ha un costo deliberato. Un terzo livello di protezione interroga il
modello locale soltanto sui messaggi che i controlli tecnici considerano già
sospetti, invece che su ogni messaggio con una qualsiasi anomalia. In questo modo
il modello viene eseguito meno volte e può rafforzare un allarme. **Non può però
eliminare un falso allarme**, e nessuna impostazione gli concede questo potere.

Permettere al modello di revocare un allarme tecnico significherebbe usare il suo
punteggio di affidabilità per ignorare elementi che il modello non può verificare
direttamente, proprio nei messaggi costruiti per ingannare i controlli. Un test
impedisce ora che questo limite venga rimosso per errore durante una normale
modifica del codice: per cambiarlo servirà una decisione esplicita.

> Specificare ciò che un sistema non può fare, insieme alle conseguenze di quel
> limite, è più significativo di una generica affermazione sulle sue capacità.

## 5. Un Mac compatibile veniva identificato come non supportato

L'applicazione riportava *"MLX richiede attualmente macOS su Apple Silicon"* su un
Mac Apple Silicon, e disattivava la propria azione principale. La riga di stato
diceva `Sistema rilevato: Darwin x86_64`.

Il servizio macOS LaunchServices avviava l'app tramite Rosetta, quindi come processo
x86_64. I processi avviati dall'app ereditavano la stessa architettura, ma MLX non
è disponibile in versione x86_64. Per questo tutti e tre i modelli locali
risultavano inutilizzabili su un Mac che, eseguendo l'app in modalità nativa, li
supporta.

L'app dichiara ora `LSRequiresNativeExecution` e assegna la priorità
all'architettura `arm64`. macOS deve quindi avviarla in modalità nativa. Il
programma di avvio contiene anche un controllo aggiuntivo per riconoscere una shell
già eseguita tramite Rosetta.

Anche il messaggio di errore era importante. Attribuire il problema all'hardware
poteva far pensare che servisse un altro computer, quando la causa era la
configurazione di avvio. La diagnosi distingue ora un processo eseguito tramite
Rosetta da una piattaforma realmente non supportata e indica il caso rilevato.

> Un messaggio di errore fa parte della sicurezza del prodotto. Una spiegazione
> categorica ma sbagliata può causare più danni di un onesto "causa non
> determinata".

## Cosa può verificare chi legge

La diagnostica di sicurezza è riproducibile senza account, senza accesso di rete e
senza toccare alcuna casella:

```bash
python -m inboxlume.desktop_worker threat-backtest --backend gemma12
```

Il comando valuta in memoria la raccolta inclusa `synthetic-threat-corpus-v1` e
produce soltanto un riepilogo: conteggi dei messaggi riconosciuti correttamente,
mancati o segnalati per errore; metriche raggruppate secondo un elenco prestabilito
di lingue e scenari; numero di risposte incompatibili del modello; impronta SHA-256
della raccolta. Non mostra il testo dei casi o l'identità dei messaggi e non può
autorizzare azioni sulla casella.

## Cosa non possiamo ancora affermare

La raccolta di prova contiene 25 casi. Dopo la correzione delle istruzioni,
l'esecuzione riporta precisione 0,9167, richiamo (*recall*) 0,9167 e zero risposte
incompatibili del modello. La prova continua però a non essere superata: un
messaggio italiano innocuo viene segnalato come minaccia, quindi il tasso di falsi
allarmi osservato è 0,0769 rispetto all'obiettivo di 0,05. Inoltre, un messaggio
italiano malevolo non viene ancora rilevato.

Con questa raccolta, una stima prudente del valore massimo del tasso di falsi
allarmi compatibile con i dati, calcolata con un livello di confidenza del 95%, è
**0,33**. Un campione così piccolo non può certificare nulla; il rapporto mostra
questa stima accanto alle altre misure per evitare che i risultati vengano letti
come una garanzia.

Inoltre, nessun pacchetto è stato ancora costruito e collaudato sulle tre
piattaforme dichiarate. La licenza Apache-2.0 è pubblicata per il codice e la
documentazione del progetto. Il comportamento di Gmail e Yahoo è stato verificato
su un solo account reale, non ancora su più account e configurazioni. Il controllo
automatico continua a impedire la distribuzione installabile. Questo diario è la
prova che il sistema viene misurato, non la prova che sia pronto.

> Il progetto sostiene una promessa precisa e limitata: per ogni azione automatica,
> InboxLume deve indicare perché il messaggio non è più utile, quale prova locale
> legata all'account sostiene la decisione e quale permesso tecnico, limitato e
> reversibile, ha autorizzato l'azione. Le prove descritte in questo diario servono
> a individuare i casi in cui il sistema non è ancora in grado di mantenere questa
> promessa.
