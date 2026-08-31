# Backtest di sicurezza locale e versionato

Il primo componente del Safety Lab di InboxLume rielabora gli esiti già
registrati delle proposte di cleanup automatico. Non si riconnette alla casella,
non riapre messaggi, non carica il modello e non autorizza azioni.

## Snapshot versionato

Ogni snapshot è separato per account, profilo modello-policy e versione del
motore di backtest. La versione `historical-v1` registra soltanto conteggi
aggregati per famiglia semantica:

- conferme `Non tenere`;
- correzioni protettive `Tieni` o ripristino;
- risposte non conclusive;
- proposte non ancora revisionate.

L'input riceve un'impronta SHA-256 deterministica. Una nuova esecuzione con la
stessa evidenza non crea duplicati. Se l'evidenza cambia e in seguito ritorna a uno
stato precedente, il ritorno viene registrato come nuovo snapshot cronologico. Il
backtest non salva oggetti, corpi, indirizzi, ID del provider o identità
reversibili.

## Confronto

Lo snapshot corrente viene confrontato con quello immediatamente precedente dello
stesso account, profilo e motore:

- `baseline`: primo snapshot utilizzabile;
- `unchanged`: evidenza aggregata identica;
- `stable`: evidenza cambiata senza nuove correzioni protettive;
- `improved_evidence`: il limite prudenziale è sceso o un errore è stato rimosso;
- `protective_regression`: sono comparse nuove correzioni `Tieni`/ripristino, con
  indicazione separata delle famiglie interessate.

L'inviluppo statistico resta il limite binomiale esatto unilaterale al 95% usato
dal Safety Governor. Un report di backtest mantiene sempre
`authorizes_actions = false`: non può cambiare le preferenze del Governor, spostare
email, svuotare il Cestino o indebolire un guardrail.

Il momento consigliato è dopo almeno 40 revisioni conclusive e prima di attivare
il Governor operativo. Va ripetuto dopo nuove correzioni, ripristini osservati o
un cambio del profilo modello-policy. È possibile eseguirlo prima, ma produce
soltanto una baseline preliminare con evidenza limitata.

## Confine attuale

Questa prima versione è una rielaborazione storica delle proposte di cleanup
registrate. Non riclassifica email salvate, perché InboxLume non conserva il testo,
e non genera ancora varianti controfattuali dei messaggi. Finestre di deriva
temporale, test di fragilità e confronti tra versioni della policy saranno
componenti successivi del Safety Lab.
