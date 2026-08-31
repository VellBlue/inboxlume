# Rilevamento locale di phishing, truffe e frodi

Stato: screening deterministico, analisi indipendente del modello locale mirata,
gate protettivo della policy, indicatori visibili additivi e persistenza privata
sono implementati in forma definitiva.

`threat-signals-v1` estrae evidenza controllata interamente in locale, senza
interrogazioni di rete. Rileva incoerenze tra mittente e Reply-To, marchi dichiarati
da domini estranei, Punycode, combinazioni insolite di alfabeti latino/cirillico/
greco, controlli bidirezionali, link verso indirizzi IP o domini Punycode, fallimenti
SPF/DKIM/DMARC provenienti da header fidati, richieste urgenti di credenziali,
richieste economiche anomale e falsi costi di consegna.

Errori ortografici o una grammatica imperfetta non bastano: penalizzerebbero
ingiustamente testi legittimi multilingue o scritti da persone non madrelingua. Il
motore richiede invece accordo tra famiglie indipendenti: identità, autenticazione,
link, Unicode e contenuto. Il resoconto contiene soltanto reason code, punteggio,
livello e famiglie controllate; mai mittente, dominio, URL, oggetto o corpo.

`Authentication-Results` viene ignorato finché l’adattatore del provider non lo
dichiara fidato, come richiesto dal modello di fiducia di
[RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html). L’allineamento dei domini
segue [DMARC RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html); le anomalie
Unicode seguono i concetti di
[Unicode UTS #39](https://www.unicode.org/reports/tr39/).

La policy di rilevamento non possiede autorizzazioni generiche sulla casella: non
può eliminare, mettere in Quarantena, segnare spam o scegliere un’azione di cleanup.
Il suo ruolo è soltanto protettivo: evidenza `high` o `critical` trasforma un
candidato ordinario al cleanup in Revisione. Quando le azioni protette sono state
autorizzate separatamente, un esecutore vincolato può poi aggiungere soltanto
l’indicatore visibile specifico del provider descritto sotto. Non sposta il
messaggio e non rimuove lo stato esistente della casella. Un `keep` già stabilito
non viene mai indebolito.

## Analisi semantica indipendente

Gemma 12B/26B tramite worker MLX offline e Qwen tramite Ollama limitato al loopback
espongono lo stesso contratto rigido. L’utente può scegliere **solo controllo
tecnico** per la scansione più rapida oppure **IA locale mirata**. Nella modalità
mirata una seconda inferenza senza strumenti viene eseguita soltanto dopo che il
livello tecnico ha trovato almeno un segnale di avviso, non per ogni messaggio.
Restituisce verdetto e intento ammessi, sei osservazioni booleane, confidenza e da
uno a cinque reason code controllati. Il modello non deve verificare mittenti, DNS,
link, reputazione o autenticazione e non riceve il punteggio deterministico: le due
fonti restano davvero indipendenti.

Il consenso è volutamente asimmetrico:

- il solo modello resta sempre sotto il livello `high`;
- giudizio malevolo ad alta confidenza e almeno una famiglia deterministica possono
  raggiungere `high` o `critical`;
- un giudizio benigno non sottrae mai evidenza tecnica;
- ogni risultato resta protettivo con `authorizes_cleanup = false`.

## Gate operativo e ledger privato

Il gate minacce viene eseguito prima di LumeGraph e Proof of Obsolescence. Una
Revisione protetta non può essere promossa da Proof, recuperata da un lotto
precedente, spostata nel Cestino diretto o finalizzata dalla Quarantena. Se
l'inferenza semantica fallisce, restano attivi i segnali deterministici e il filtro
ordinario non viene interrotto.

Il ledger separato per account e profilo modello conserva soltanto chiave HMAC del
messaggio, enum controllati, bucket grossolano del punteggio, insiemi di reason code
e conteggi aggregati. Non salva mittente, ID provider, dominio, URL, oggetto, corpo
o punteggio esatto e non possiede autorità di cleanup.

La GUI bilingue mostra valutazioni aggregate, messaggi ad alto rischio protetti,
verifiche semantiche mirate, messaggi senza segnali tecnici esclusi, fallback e
totale del ledger privato. La stima della durata considera la modalità scelta e
versiona i campioni temporali, così misure ottenute con una pipeline diversa non
possono sottostimare silenziosamente quella attuale.

## Indicatore protettivo visibile

Quando sono autorizzate le azioni protette, una valutazione `high` o `critical`
riceve un indicatore visibile, additivo e nativo del provider: mai la Quarantena
ordinaria o il Cestino. Gmail aggiunge l’etichetta utente
`InboxLume/Sospetto phishing` senza rimuovere `INBOX` o altre etichette. Yahoo
aggiunge soltanto il flag IMAP `\Flagged`, senza usare `MOVE` e senza rimuovere la
Inbox o alcun flag esistente. Yahoo mostra `\Flagged` come una stella, che non è un
indicatore esclusivo di InboxLume. Nessuna delle due operazioni può eliminare,
svuotare il Cestino, segnare spam, agire sulla Posta inviata o concedere autorità di
cleanup. Gli errori dell’indicatore restano isolati dal filtro ordinario e sono
riportati solo come conteggi aggregati.

La baseline personale dei mittenti resta un incremento successivo.
