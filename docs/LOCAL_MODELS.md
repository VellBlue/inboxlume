# Modelli AI locali

InboxLume usa profili controllati: l'utente sceglie il livello di risorse, mentre
l'app conserva nomi, runtime e policy in una allowlist. La selezione non accetta
comandi, URL o percorsi arbitrari e non avvia download automatici.

## Profili della prima release

| Profilo | Runtime iniziale | RAM consigliata | Policy operativa |
|---|---|---:|---|
| Qwen 8B · Leggero | Ollama, tre sistemi | 12 GB | soglia 0,97; solo Quarantena |
| Gemma 12B · Bilanciato | MLX, Apple Silicon | 16 GB | soglia 0,95; solo Quarantena |
| Gemma 26B-A4B · Consigliato | MLX, Apple Silicon | 24 GB | soglia 0,93; Quarantena o Cestino calibrato |

Le soglie sono limiti minimi applicati dal worker anche se la GUI venisse aggirata.
Non trasformano la confidenza del modello in una probabilità garantita. Guardrail
deterministici, categorie protette, feedback esplicito e astensione rimangono
obbligatori per tutti i profili.

Qwen 8B serve a rendere InboxLume accessibile su computer meno potenti, ma nei test
iniziali ha confuso più facilmente pubblicità legittima e spam. Gemma 12B è un
compromesso; Gemma 26B-A4B è la scelta consigliata sui computer compatibili. Il
Cestino diretto resta riservato al profilo consigliato finché benchmark più ampi non
dimostreranno un rischio sufficientemente basso per gli altri.

## Rilevamento passivo

All'apertura la GUI controlla soltanto:

- sistema operativo, architettura e RAM fisica totale;
- presenza dell'eseguibile Ollama e del manifest locale del modello consentito;
- presenza del runtime MLX e di un singolo snapshot Hugging Face esatto.

Il controllo non legge email, non carica pesi, non interroga Internet e non scarica
modelli. Una cache assente, ambigua o esterna al percorso atteso viene rifiutata. Un
profilo con RAM inferiore al valore consigliato resta visibile con un avviso; un
runtime incompatibile blocca quiz, scansione e nuova pianificazione.

## Esecuzione one-shot

Il profilo viene salvato separatamente per account. Quiz, scansioni manuali e job
pianificati usano tutti il medesimo valore. Cambiare modello su un account con job
attivo richiede di applicare nuovamente la pianificazione.

- Con MLX, InboxLume avvia un processo figlio offline sulla sola cache locale e lo
  termina alla fine dell'operazione.
- Con Ollama, l'endpoint è limitato a loopback e il modello viene scaricato dalla
  RAM con `keep_alive=0` al termine. Il servizio Ollama può restare inattivo o
  leggero; i pesi non devono restare residenti.
- Se il modello fallisce o restituisce JSON non valido, il fallback non autorizza
  automaticamente un cleanup.

La futura distribuzione comune privilegerà Ollama/llama.cpp per macOS, Windows e
Linux. MLX rimarrà un'accelerazione opzionale per Apple Silicon. Prima della release
pubblica occorrono istruzioni di installazione e pacchetti verificati per ciascun
sistema; il programma non deve nascondere download o dipendenze.

## Benchmark

Le misure note sono in [MODEL_BENCHMARKS.md](MODEL_BENCHMARKS.md). Ogni risultato
pubblico deve indicare modello, quantizzazione, runtime, hardware, prompt, policy,
campione, falsi cleanup, copertura, astensioni, RAM e latenza. I benchmark costosi
si ripetono soltanto quando cambia una di queste variabili.
