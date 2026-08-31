# Safety Governor personale — gate operativo delle capacità

Il Safety Governor di InboxLume misura l'evidenza locale senza rendere più
aggressivo il classificatore. La GUI mostra un inviluppo separato per account e
profilo modello-policy; un'opzione esplicita per account può usare tale evidenza
come livello adattivo delle capacità.

## Confine dell'evidenza

Il Governor collega evidenza locale indicizzata tramite HMAC:

- le proposte di Quarantena registrate dai controlli conclusi;
- le successive risposte del quiz associate agli stessi hash opachi;
- i ritorni in Posta in arrivo osservati soltanto per messaggi prima spostati da
  InboxLume.

Legge soltanto conteggi aggregati per categoria e risposta. Non si riconnette alla
casella, non legge il corpo di una mail, non recupera indirizzi e non salva testo in
chiaro. Account e profili restano compartimentati.

Su Gmail il ripristino viene rilevato dalla cronologia delle etichette. Su Yahoo
viene fissata una baseline UID e, per i soli nuovi UID presenti in Posta in
arrivo, viene letto esclusivamente l'header `Message-ID`: non si aprono Cestino o
Quarantena e non si legge alcun corpo. Serve una corrispondenza HMAC con una
precedente azione InboxLume riuscita. Alla prima esecuzione o dopo un cambio di
UIDVALIDITY Yahoo, la baseline viene reimpostata senza produrre inferenze.

Una risposta `Tieni` riferita a una proposta di Quarantena conta come falso cleanup;
il ripristino di quella proposta ha lo stesso significato protettivo. `Non tenere`
è una conferma. `Non so` viene mostrato ma non entra nella stima
binomiale; le proposte non revisionate restano visibili come evidenza mancante.

## Limite prudenziale

Il numero mostrato è il limite superiore esatto unilaterale di Clopper–Pearson al
95% per il tasso di falsi cleanup, non la confidenza prodotta dal modello. Con zero
errori osservati si riduce a:

```text
p_superiore = 1 - 0,05^(1/n)
```

Quaranta revisioni comparabili senza errori lasciano ancora un limite di circa
7,2%. Ne servono approssimativamente 299 per scendere sotto l'obiettivo di ricerca
attuale dell'1%, mantenendo le stesse ipotesi.

Gli stati sono volutamente circoscritti:

- `raccolta`: meno di 40 revisioni conclusive corrispondenti;
- `non qualificato`: il campione esiste, ma il limite supera l'obiettivo;
- `qualificato shadow`: la soglia statistica shadow è raggiunta.

Il report statistico mantiene `authorizes_actions = false`: l'evidenza non è una
capacità sulla casella. Il livello operativo separato interseca la policy prudente
senza sostituirla. Se l'evidenza è insufficiente, il filtro ordinario non cambia.
Una famiglia semantica viene limitata soltanto dopo almeno 20 revisioni conclusive,
almeno tre correzioni `Tieni` e un limite inferiore unilaterale al 95% superiore
all'obiettivo di errore dell'1%. Il comportamento è specifico per famiglia:
l'evidenza di una non blocca le altre. Nuove conferme corrette possono abbassare il
limite e rimuovere automaticamente la restrizione.

Il livello è facoltativo e separato per account e modello. Il relativo controllo
operativo resta disabilitato finché l'inviluppo dell'account e del modello non
contiene almeno 40 revisioni conclusive; lo stesso prerequisito viene verificato
dal backend, quindi una preferenza obsoleta o modificata manualmente non può
aggirarlo. Quarantena adattiva e
autorità del Governor sul Cestino sono capacità distinte. La preferenza ordinaria
Cestino diretto resta indipendente: con il
Governor spento, oppure acceso ma non qualificato per il Cestino, continua con i
propri vincoli di modello, calibrazione, policy e conferma. Il Governor stesso
ottiene autorità sul Cestino soltanto con un modello supportato, almeno 299
revisioni conclusive in entrambi gli inviluppi e zero correzioni `Tieni` in
entrambi. Una successiva correzione `Tieni` revoca tale autorità del Governor senza
disabilitare il Cestino diretto ordinario. Le famiglie non qualificate non ricevono
autorità dal Governor anche se un'altra famiglia possiede dati sufficienti.

Cestino diretto significa spostare il messaggio nel normale Cestino del provider.
Il gate non può cancellare permanentemente né svuotare il Cestino e non sposta o
ripristina retroattivamente i messaggi. Il primo componente di
[deriva temporale](TEMPORAL_DRIFT.md) può soltanto restringere l’autorità governata
per la famiglia cambiata. Le perturbazioni controfattuali della policy restano un
milestone successivo.

## Limiti metodologici

Gli esempi del quiz non sono necessariamente indipendenti o rappresentativi.
Interessi, campagne email e comportamento del modello cambiano nel tempo. Il limite
descrive quindi il campione locale osservato sotto ipotesi esplicite: non è una
garanzia sulla correttezza futura né una promessa di “sicurezza al 100%”. Le famiglie
rare o costose richiedono ancora astensione e guardrail deterministici.
