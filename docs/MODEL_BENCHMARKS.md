# Benchmark preliminari dei modelli locali

Misure già effettuate sul Mac, comprensive di caricamento e scaricamento per cinque
messaggi sintetici:

| Modello | Tempo a freddo | Picco memoria | Nota iniziale |
|---|---:|---:|---|
| Qwen 8B | circa 5,4 s | non annotato | più rapido; confonde talvolta pubblicità legittima e spam |
| Gemma 4 12B | circa 8,7 s | 11,2 GB | candidato MLX più equilibrato |
| Gemma 4 26B-A4B | circa 9,7 s | 14,7 GB | profilo provvisoriamente consigliato |

Questi numeri misurano prestazioni, non accuratezza. La scelta definitiva verrà
presa dopo il quiz e un confronto sugli stessi tipi di email reali, mantenendo i
contenuti sul Mac.

Il confronto di accuratezza è implementato dal comando `gmail-model-eval`. Recupera
le etichette tramite HMAC, non salva il corpus in chiaro e riporta soltanto conteggi
aggregati. `false_cleanup_on_keep` e `policy_quarantine_on_keep` sono le metriche di
sicurezza prioritarie: un modello con falsi positivi non può essere scelto per una
fase operativa.

## Primo confronto su 48 email reali etichettate

Tutte le 48 etichette sono state recuperate tramite HMAC: 3 `Tieni`, 39
`Non tenere` e 6 `Non so`. Nessun modello ha provocato una proposta di quarantena
su un messaggio `Tieni`, grazie anche alle regole deterministiche.

| Modello | Falso “non interessa” su Tieni | Richiamo Non tenere | Accuratezza interesse | Fallimenti |
|---|---:|---:|---:|---:|
| Qwen 8B | 1 | 51,28% | 52,38% | 0 |
| Gemma 12B | 0 | 48,72% | 52,38% | 0 |
| Gemma 26B-A4B | 0 | 51,28% | 54,76% | 0 |

Gemma 26B-A4B è quindi il modello provvisorio per lo shadow mode. La selezione non
autorizza ancora modifiche alla casella: tre soli esempi `Tieni` non bastano per
stimare in modo affidabile il rischio sulle email importanti.

## Verifica successiva su un campione più ampio

Dopo ulteriori quiz, Gemma 26B-A4B è stato rivalutato su 78 esempi utilizzabili:
4 `Tieni` e 74 `Non tenere`; 7 risposte `Non so` sono state escluse dalla metrica.
Il modello non ha prodotto falsi cleanup sui quattro `Tieni`, ha riconosciuto il
66,22% dei `Non tenere` come candidati di contenuto e ha raggiunto il 67,95% sulla
preferenza binaria. La policy finale ha comunque autorizzato soltanto 7 quarantene
e nessuna sui `Tieni`.

Il risultato supporta la scelta provvisoria di Gemma 26B-A4B, ma quattro esempi da
proteggere restano troppo pochi per stimare un tasso di errore raro. Per questo
Quarantena, categorie protette, astensione e calibrazione rimangono obbligatorie;
Qwen 8B e Gemma 12B applicano inoltre soglie più severe e non possono usare il
Cestino diretto. Il contratto corrente è in [LOCAL_MODELS.md](LOCAL_MODELS.md).
