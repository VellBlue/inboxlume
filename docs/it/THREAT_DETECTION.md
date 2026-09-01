# Rilevamento locale di phishing, truffe e frodi

Stato: sono implementati i controlli tecnici basati su regole fisse, l'analisi
mirata del modello locale, il controllo protettivo, gli indicatori visibili e il
registro privato.

`threat-signals-v1` raccoglie elementi tecnici interamente in locale, senza
interrogare servizi di rete. Rileva incoerenze tra mittente e indirizzo di risposta,
marchi dichiarati da domini estranei, Punycode, combinazioni insolite di alfabeti
latino, cirillico e greco, caratteri che cambiano la direzione del testo,
collegamenti verso indirizzi IP o domini Punycode, fallimenti SPF, DKIM e DMARC
provenienti da intestazioni considerate affidabili, richieste urgenti di credenziali,
richieste economiche anomale e falsi costi di consegna.

Errori ortografici o una grammatica imperfetta non bastano: penalizzerebbero
ingiustamente testi legittimi multilingue o scritti da persone non madrelingua. Il
motore richiede invece l'accordo tra gruppi indipendenti di controlli: identità,
autenticazione, collegamenti, Unicode e contenuto. Il resoconto contiene soltanto
codici di motivazione, punteggio, livello e gruppi controllati; mai mittente,
dominio, URL, oggetto o corpo.

`Authentication-Results` viene ignorato finché il componente del fornitore di posta
non lo dichiara affidabile, come richiesto dal modello di fiducia di
[RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html). L’allineamento dei domini
segue [DMARC RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html); le anomalie
Unicode seguono i concetti di
[Unicode UTS #39](https://www.unicode.org/reports/tr39/).

Il sistema di rilevamento non possiede autorizzazioni generiche sulla casella: non
può eliminare, mettere in Quarantena, segnare come spam o scegliere un'azione di
pulizia. Il suo ruolo è soltanto protettivo: un livello di rischio `high` o
`critical` trasforma una proposta ordinaria di pulizia in una richiesta di
Revisione. Quando l'utente ha autorizzato separatamente le azioni protettive, un
componente con permessi limitati può aggiungere soltanto l'indicatore visibile
descritto sotto. Non sposta il messaggio e non rimuove lo stato esistente della
casella. Una decisione `Tieni` già stabilita non viene mai indebolita.

## Analisi semantica indipendente

Gemma 12B/26B, eseguito senza rete tramite MLX, e Qwen, eseguito tramite Ollama con
connessioni limitate al dispositivo, usano lo stesso formato di risposta
obbligatorio. L'utente può scegliere **solo controllo tecnico** per la scansione
più rapida oppure **IA locale mirata**. Nella modalità mirata, una seconda analisi
viene eseguita soltanto dopo che i controlli tecnici hanno trovato almeno un
segnale di avviso, non per ogni messaggio. Restituisce un giudizio e un intento
scelti da elenchi prestabiliti, sei indicatori vero/falso, un punteggio di
affidabilità e da uno a cinque codici di motivazione. Il modello non deve verificare
mittenti, DNS, collegamenti, reputazione o autenticazione e non riceve il punteggio
dei controlli tecnici: le due fonti restano indipendenti.

Il consenso è volutamente asimmetrico:

- il solo modello resta sempre sotto il livello `high`;
- un giudizio malevolo con un punteggio di affidabilità alto e almeno un gruppo di
  controlli tecnici possono raggiungere `high` o `critical`;
- un giudizio benigno non sottrae mai evidenza tecnica;
- ogni risultato resta protettivo con `authorizes_cleanup = false`.

## Controllo operativo e registro privato

Il controllo delle minacce viene eseguito prima di LumeGraph e Proof Of
Obsolescence. Una Revisione protetta non può essere trasformata da Proof Of
Obsolescence in una proposta di Quarantena, recuperata da una scansione precedente,
spostata nel Cestino diretto o finalizzata dalla Quarantena. Se l'analisi del
significato fallisce, restano attivi i controlli tecnici basati su regole fisse e
il filtro ordinario non viene interrotto.

Il registro separato per account e profilo del modello conserva soltanto la chiave
HMAC del messaggio, valori scelti da elenchi prestabiliti, una fascia approssimativa
del punteggio, codici di motivazione e conteggi complessivi. Non salva mittente, ID
del fornitore di posta, dominio, URL, oggetto, corpo o punteggio esatto e non può
autorizzare operazioni di pulizia.

L'interfaccia bilingue mostra risultati complessivi, messaggi ad alto rischio
protetti, analisi mirate del significato, messaggi esclusi perché privi di segnali
tecnici, procedure alternative eseguite in caso di errore e totale del registro
privato. La stima della durata considera la modalità scelta e identifica la
versione del processo usata per ogni misurazione, così dati ottenuti con una
sequenza diversa non possono sottostimare quella attuale.

## Indicatore protettivo visibile

Quando sono autorizzate le azioni protettive, una valutazione `high` o `critical`
riceve un indicatore visibile fornito dal servizio di posta, senza rimuovere gli
indicatori esistenti: non viene mai usata la Quarantena ordinaria o il Cestino.
Gmail aggiunge l'etichetta utente
`InboxLume/Sospetto phishing` senza rimuovere `INBOX` o altre etichette. Yahoo
aggiunge soltanto il contrassegno IMAP `\Flagged`, senza usare `MOVE` e senza
rimuovere il messaggio dalla Posta in arrivo o cancellare altri contrassegni. Yahoo
mostra `\Flagged` come una stella, che non è un
indicatore esclusivo di InboxLume. Nessuna delle due operazioni può eliminare,
svuotare il Cestino, segnare spam, agire sulla Posta inviata o concedere autorità di
pulizia. Gli errori dell'indicatore restano isolati dal filtro ordinario e sono
riportati solo come conteggi complessivi.

Il profilo personale dei mittenti è una funzione futura.
