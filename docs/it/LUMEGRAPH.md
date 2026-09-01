# LumeGraph: grafo temporale privato dell’utilità

Stato: il nucleo completo del grafo è operativo. Le osservazioni da sole non
autorizzano alcuna azione. Soltanto il controllo separato Proof Of Obsolescence,
basato su regole fisse, può trasformare una proposta di Revisione idonea in uno
spostamento verso la Quarantena reversibile.

## Che cosa rappresenta

Una categoria tradizionale dice a che cosa assomiglia un’email. LumeGraph descrive
separatamente a che cosa serve ancora quel messaggio. Il primo motore riconosce in
inglese, italiano e contenuti misti:

- codici monouso;
- ordini e spedizioni;
- prenotazioni e variazioni di viaggio o evento;
- fatture, pagamenti e ricevute di operazioni;
- reimpostazione password e recupero dell’account.
- offerte pubblicitarie con una data di scadenza esplicita.

Ogni nodo contiene soltanto campi controllati:

- stato `active`, `pending`, `completed`, `replaced`, `expired` o `uncertain`;
- utilità operativa, probatoria, personale e di sicurezza indipendenti;
- relazione temporale e settimana di ricezione, mai la data esatta persistita;
- condizione residua controllata: azione dell’utente, azione esterna, limite di
  tempo, condizione conclusa, nessuna o incerta;
- punteggio di affidabilità raggruppato per fasce e codici di motivazione ammessi.

La separazione è essenziale. Una ricevuta di pagamento può non richiedere più
azioni, ma conservare valore probatorio. LumeGraph registra quel valore: lo stato
`completed` non diventa un permesso di pulizia.

## Collegamenti senza conservare riferimenti

Numeri d’ordine, tracking, prenotazione, fattura e transazione esistono soltanto
temporaneamente in memoria. InboxLume ne calcola un HMAC separato per account e
salva l’HMAC, non il riferimento. Un messaggio può avere più relazioni rappresentate
da impronte non leggibili: in questo modo ordine → spedizione → consegna può essere
collegato anche se cambia il mittente.

Nel database SQLite non vengono salvati mittente, oggetto, corpo, ID reale del
fornitore di posta, codice estratto, numero d’ordine, riferimento di prenotazione o
data esatta. I dati di ogni account e di ogni configurazione di modello e regole
restano separati; non esistono collegamenti tra account diversi.

## Due inferenze indipendenti

La classificazione operativa esistente non viene modificata. Solo per i messaggi
che sembrano appartenere a un ciclo di utilità, il modello locale già caricato
esegue una seconda analisi con un formato di risposta obbligatorio. L'analisi del
ciclo di vita non può quindi cambiare la classificazione usata dalle regole
ordinarie. In caso di errore interviene una procedura alternativa prudente, basata
su regole fisse.

La seconda analisi riusa il corpo del messaggio già preparato in RAM e non interroga
di nuovo la casella. Ollama accetta connessioni soltanto dal dispositivo; Gemma usa
il processo MLX senza accesso alla rete. Al termine della scansione avviata su
richiesta, il modello viene rimosso dalla memoria.

## Confine operativo

Ogni risultato LumeGraph dichiara:

```text
shadow_only = false
authorizes_policy = verified_closure_witness_exists
authorizes_actions = reversible_quarantine_only
changes_mailbox = false
```

Un errore di LumeGraph non interrompe né amplia il filtro ordinario. La GUI mostra
soltanto conteggi aggregati di nodi, transizioni e testimoni di chiusura. Il
contratto operativo e le classi di utilità protette sono descritti in
[PROOF_OF_OBSOLESCENCE.md](PROOF_OF_OBSOLESCENCE.md). Eliminazione permanente e
svuotamento del Cestino restano non disponibili.

## Stima della durata

Le stime di riferimento includono l'analisi locale aggiuntiva prevista per la
quota osservata di cicli. Quando esistono sessioni locali comparabili, i tempi
misurati dall'inizio alla fine includono già LumeGraph e sostituiscono la stima
aggiuntiva. Nessun contenuto email viene conservato nei dati temporali.
