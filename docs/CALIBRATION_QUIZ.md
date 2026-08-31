# Quiz di calibrazione locale

Il quiz presenta email reali esclusivamente dalla Posta in arrivo. Non esegue azioni
sulla casella e offre tre risposte:

- **Tieni**: forte segnale positivo e di protezione.
- **Non tenere**: forte segnale di disinteresse; durante la calibrazione significa
  soltanto futura candidatura alla quarantena.
- **Non so**: la mail non influenza il profilo.

La selezione non è puramente casuale. Dà priorità ai casi incerti e mantiene varietà
tra mittenti e categorie, evitando di chiedere giudizi ripetitivi. Le email già
valutate non vengono riproposte: vengono saltate tramite HMAC prima di scaricare il
corpo e la ricerca continua nell'intera Inbox finché trova il numero richiesto di
esempi nuovi. Il limite massimo di 500 riguarda una singola sessione, non lo storico
complessivo appreso nel tempo.

Nel database vengono conservati soltanto l'HMAC dell'identificativo, feature HMAC,
impronte HMAC del contenuto e la risposta. Le impronte permettono di riconoscere
email molto simili senza conservare il testo. Oggetto, corpo e indirizzo non sono
salvati in chiaro; stesso mittente o stessa categoria non determinano
automaticamente la stessa risposta. Le risposte sono isolate per account.

Partenza consigliata: circa 40–60 email diversificate, poi piccoli richiami sui casi
più incerti. Il numero finale verrà determinato misurando gli errori, non fissato a
priori.

Dopo l'onboarding, InboxLume non deve chiedere quiz a intervalli arbitrari. I
richiami previsti sono micro-quiz di 5–10 esempi selezionati solo quando esiste un
guadagno informativo concreto: una famiglia nuova o poco coperta, un conflitto tra
segnali, deriva recente oppure evidenza mancante per una funzione avanzata. Gli
inviti devono essere ignorabili e limitati nel tempo. Quando le risposte si sono
stabilizzate e un altro campione cambierebbe poco la stima, il sistema smette di
sollecitare l'utente. I ripristini di messaggi precedentemente spostati da
InboxLume forniscono inoltre correzioni passive forti, riducendo la necessità di
quiz continui.

## Avvio manuale

Si parte con lotti piccoli, per esempio 12 domande selezionate da 60 email Inbox:

```bash
PYTHONPATH=src python3 -m inboxlume.cli gmail-quiz \
  --config config/accounts.example.json \
  --account gmail_personale \
  --backend ollama \
  --ollama-model qwen3-vl:8b \
  --limit 12 \
  --sample-limit 60 \
  --confirm-read-bodies
```

Il comando è esclusivamente interattivo e non è previsto per la schedulazione.
Premendo `q` termina senza perdere le risposte già date. Rispondere due volte alla
stessa email non duplica il suo peso.

Conclusa la calibrazione iniziale, `Launch InboxLume.command` viene riutilizzato
per la revisione mirata delle proposte shadow. Non avvia un server web e comunica con
il backend tramite pipe; anche questa revisione non modifica la casella.

Qwen 8B è provvisorio: le etichette del quiz serviranno anche a confrontarlo con
Gemma su email rappresentative prima della scelta definitiva.
