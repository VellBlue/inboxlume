# InboxLume Innovation Lab

Stato: direzione di ricerca approvata. LumeGraph e il gate operativo Proof of
Obsolescence sono implementati senza indebolire i guardrail correnti; i livelli
successivi restano ricerca.

Eccezione verificata: il Safety Governor misura evidenza aggregata locale e dispone
di un primo livello operativo facoltativo e adattivo per account, modello e
famiglia. La scarsità di dati non blocca il filtro ordinario; errori ripetuti
possono limitare soltanto la famiglia interessata. Il backtest storico versionato
e il primo rilevatore di deriva sono informativi/protettivi; le perturbazioni
controfattuali restano ricerca.

## Tesi di prodotto

Un LLM locale che divide posta importante e rumore non basta più per distinguere
InboxLume: esistono già prodotti che filtrano localmente, apprendono preferenze o
costruiscono baseline comportamentali. Il nucleo pionieristico proposto è invece:

> InboxLume non agisce perché una mail *sembra poco importante*. Agisce soltanto
> quando può produrre una prova locale che la sua utilità è conclusa, che il rischio
> personale osservato è entro il limite scelto e che tutti i vincoli operativi sono
> stati rispettati.

Ogni parte è replicabile; la loro integrazione e lo stato personale accumulato nel
tempo costituiscono il vantaggio difficile da replicare.

## LumeGraph: grafo temporale dell'utilità

Stato verificato: nucleo completo `lumegraph-v2`; dettagli e confine
operativo in [LUMEGRAPH.md](LUMEGRAPH.md).

La posta non viene rappresentata soltanto come categoria. Il modello estrae piccoli
oggetti di utilità e le loro transizioni:

- evento o bisogno a cui la mail serve;
- stato `attivo`, `in attesa`, `completato`, `sostituito`, `scaduto` o `incerto`;
- date e condizioni esplicite;
- messaggio successore che modifica o chiude il precedente;
- utilità operativa, probatoria, affettiva e di sicurezza mantenute separate.

Esempi: ordine -> spedizione -> consegna; fattura -> pagamento -> ricevuta;
prenotazione -> variazione -> cancellazione o data trascorsa; reset password ->
conferma di sicurezza; codice monouso -> scadenza. Una ricevuta può aver concluso
l'utilità operativa ma conservare utilità fiscale o di garanzia e restare protetta.

Il grafo usa riferimenti opachi/HMAC e feature minimizzate. Non conserva testo utile
a ricostruire la mail, non legge Posta inviata e non collega account distinti senza
consenso esplicito.

## Proof of Obsolescence

Stato: implementata come gate operativo locale. È il criterio derivato da
LumeGraph. Una promozione aggiuntiva deve avere
un *closure witness*, cioè una prova osservabile che giustifichi la fine dell'utilità:

- un messaggio successivo ha sostituito o completato il precedente;
- una data di scadenza esplicita estratta e verificata è trascorsa;
- un token è scaduto secondo una regola deterministica;
- il contenuto è molto simile a esempi `Non tenere` confermati nello stesso regime
  temporale e non esiste alcun segnale protetto;
- più segnali indipendenti concordano sullo stato concluso.

L'assenza di una prova non equivale a una prova di assenza: produce `Revisione`, non
un'azione. Una possibile rappresentazione è:

```text
u(e, t) = [utilità operativa, probatoria, personale, sicurezza]
```

La promozione da Revisione a Quarantena è ammissibile soltanto se nessuna componente
protetta rimane attiva e se esiste una prova di chiusura verificabile. Il modello
propone lo stato; la policy deterministica decide se la prova è sufficiente. Con
Cestino diretto la prova non amplia la selezione ordinaria.

## Safety Governor personale

La generica `confidence` del modello non deve essere trattata come probabilità di
sicurezza. InboxLume costruisce un inviluppo di automazione per account, modello e
famiglia semantica:

- misura falsi cleanup, copertura e astensioni su correzioni locali;
- calcola un limite superiore prudenziale del rischio;
- autorizza soltanto la regione per cui esistono dati sufficienti;
- riduce automaticamente l'autonomia se il comportamento cambia o un aggiornamento
  peggiora il backtest;
- mantiene categorie rare o costose in shadow mode.

Con `n` casi indipendenti e zero errori osservati, un limite superiore unilaterale
elementare al 95% del tasso di errore è:

```text
p_upper = 1 - 0.05^(1/n)
```

Con 40 casi è ancora circa 7,2%; per scendere sotto l'1% con zero errori servono
circa 299 casi comparabili. Sono stime soggette a ipotesi e deriva, non garanzie, ma
impediscono di confondere un piccolo quiz con una certificazione.

## Counterfactual Safety Lab

Prima di attivare un modello, una policy o una soglia, InboxLume esegue un backtest
interamente locale:

- riproduce le decisioni su esempi confermati e quarantene poi annullate;
- misura il rischio per categoria, periodo e tipo di prova di chiusura;
- verifica la stabilità con varianti controllate vicine al confine;
- blocca regressioni sulle mail protette;
- mostra quante email verrebbero automatizzate o lasciate in revisione.

Le varianti controfattuali sono test di fragilità, non nuove etichette corrette. Se
una piccola modifica fa oscillare la decisione, il risultato deve essere astensione.

## Preference Weather

Il gemello privato mantiene scale temporali distinte: preferenze stabili, periodi di
interesse, segnali recenti con decadimento e correzioni esplicite durature. Può
riconoscere che viaggio, università o un acquisto sono temporaneamente rilevanti.

Aprire una mail è un segnale debole; stella, ripristino dalla quarantena e quiz hanno
pesi diversi. Un cambio improvviso non autorizza più azioni: apre un nuovo regime e
aumenta temporaneamente l'astensione.

## Negative-Space Sentinel

Usando soltanto lo storico della Posta in arrivo, InboxLume può apprendere ricorrenze
importanti e segnalare localmente:

- un estratto o avviso periodico non arrivato nella finestra abituale;
- una catena operativa ferma in uno stato intermedio;
- una conferma attesa dopo un evento precedente;
- un cambiamento anomalo nella cadenza di una relazione importante.

Esistono strumenti a regole per monitorare email attese; il differenziatore è
l'inferenza non supervisionata della ricorrenza e del suo significato in LumeGraph.
La funzione è informativa: non invia messaggi e non modifica la casella.

## Personal Phishing Immune System

La baseline comportamentale esiste già in ambito enterprise. InboxLume può renderla
personale, locale e verificabile:

- modella dominio, `From`, `Reply-To`, autenticazione, tono, tempi e tipo di richiesta;
- distingue un messaggio insolito da uno genericamente scritto male;
- genera offline perturbazioni difensive controllate, come dominio simile, nuovo
  conto di pagamento, urgenza inattesa o cambio di `Reply-To`;
- usa le perturbazioni per testare i guardrail, mai per spedirle o visitare contenuti;
- se il test personale fallisce, riduce l'autonomia e segnala la lacuna.

Nessun link viene visitato e nessun allegato viene aperto automaticamente.

## LumeReply: consigliere locale di risposta

Mostrare una semplice risposta generata dentro Gmail o Yahoo non sarebbe unico:
Gmail offre già risposte AI e altri prodotti dichiarano generazione locale. Il
differenziatore candidato è un consigliere che, soltanto dopo un clic dell'utente:

1. identifica tutte le domande, scadenze e richieste presenti nella mail aperta;
2. propone varianti brevi, formali o di rifiuto senza spedire nulla;
3. indica quali punti della mail sono coperti e quali restano senza risposta;
4. evidenzia le promesse che il testo farebbe nascere, per esempio una data, un
   pagamento, una disponibilità o la condivisione di un dato;
5. mostra l'origine locale delle affermazioni e non inventa dettagli mancanti;
6. si astiene se il contesto è insufficiente o il Personal Phishing Immune System
   rileva un'anomalia.

L'integrazione più coerente è un'estensione browser con Native Messaging verso
l'app desktop. L'estensione trasmette un ID opaco; InboxLume recupera la sola mail
Inbox con le credenziali locali e avvia il modello one-shot. La risposta torna al
pannello nella pagina, ma non viene inserita né inviata automaticamente. Il primo
rilascio dovrebbe offrire solo `Copia`, lasciando all'utente l'atto di incollare e
spedire.

Profili di risorse candidati:

- `Eco`: modello avviato per una richiesta e scaricato subito;
- `Sessione breve`: dopo un clic esplicito resta caldo per pochi minuti, poi termina;
- `Qualità`: modello più grande, latenza maggiore, sempre su richiesta.

Il comportamento predefinito deve essere `Eco`. Nessuna analisi continua quando
l'utente apre una mail. Imparare lo stile storico richiederebbe leggere Posta inviata
e resta quindi fuori dallo scope attuale; il tono può essere configurato manualmente.

## Proof-Carrying Cleanup

Un log spiega dopo l'evento; una capability limita prima. Per ogni azione automatica
il decision engine crea una ricevuta locale con HMAC di ID/account, hash di modello
e policy, tipo di closure witness, risultato del Safety Governor, guardrail,
destinazione esatta e scadenza del permesso.

L'esecutore con permessi email accetta soltanto ricevute valide, recenti e riferite a
una singola azione ammessa. Le ricevute sono concatenate e firmate localmente, così
modifiche o riordini diventano rilevabili. La firma prova l'integrità della ricevuta,
non la correttezza del modello e non, da sola, l'assenza di traffico di rete.

## Verifiable Locality e Capability Firewall

```text
provider bridge        modello locale             action executor
rete allowlist         nessuna rete               rete allowlist
credenziali lettura     nessuna credenziale        token azioni ristretto
ID + testo Inbox        testo sanitizzato          solo ID opaco + ricevuta
nessuna azione          nessun tool                azioni enumerate
```

Il classificatore usa cache modello in sola lettura, filesystem minimo e rete negata
dal sistema operativo. Se l'isolamento non può essere applicato, l'automazione
fallisce chiusa. Una `Privacy Flight Recorder` mostra quali processi hanno avuto
rete, credenziali e scrittura durante la sessione, senza registrare contenuto.

## Causal Correction

Quando l'utente ripristina una mail, InboxLume non mette semplicemente il mittente in
whitelist. Cerca la minima ragione che separa il caso errato da quelli corretti, per
esempio data futura, valore probatorio, richiesta concreta o tema riattivato. Simula
la correzione sullo storico: se protegge il caso ma distrugge molte decisioni valide,
resta un'eccezione locale.

## Flagship proposto

```text
LumeGraph
  -> Proof of Obsolescence
  -> Safety Governor
  -> Counterfactual Safety Lab
  -> capability firmata
  -> esecutore ristretto
  -> quarantena reversibile
  -> correzione causale
```

Promessa verificabile proposta:

> Ogni cleanup automatico deve mostrare che cosa ha concluso l'utilità della mail,
> entro quale rischio personale misurato e con quale permesso tecnico limitato e
> reversibile è stato eseguito.

## Ordine di ricerca

1. Validare LumeGraph e Proof of Obsolescence su corpus sintetici e correzioni
   locali aggregate.
2. Estendere il backtest versionato alle ricevute di prova.
3. Rendere la ricevuta un requisito dell'esecutore, non un semplice log.
4. Aggiungere Preference Weather e correzione causale.
5. Sperimentare poi Negative Space, immune system e LumeReply.
6. Completare l'isolamento OS multipiattaforma prima di dichiararlo verificato.

## Criteri di onestà scientifica

- Non dichiarare `prima al mondo` senza ricerca brevettuale professionale.
- Non chiamare una ricevuta crittografica `prova di correttezza`.
- Non chiamare una confidenza LLM `probabilità` senza calibrazione.
- Non promettere sicurezza al 100%.
- Pubblicare falsi cleanup, copertura, astensioni, campione e deriva.
- Valutare il rischio delle azioni, non soltanto l'accuracy della categoria.

## Riferimenti di partenza

- Google Research, *Anatomy of a Privacy-Safe Large-Scale Information Extraction
  System Over Email*: https://research.google/pubs/anatomy-of-a-privacy-safe-large-scale-information-extraction-system-over-email/
- Srivastava et al., *MAILEX*: https://aclanthology.org/2023.emnlp-main.801/
- Fisch et al., *Conformal Prediction Sets with Limited False Positives*:
  https://proceedings.mlr.press/v162/fisch22a.html
- Tayebati et al., *Conformalized Abstention Policies*:
  https://proceedings.mlr.press/v304/tayebati26a.html
- Microsoft, *Create Process in Sandbox APIs*:
  https://learn.microsoft.com/windows/win32/secauthz/createprocessinsandbox
- Whittaker e Sidner, *Email Overload*:
  https://chi1996.acm.org/proceedings/papers/Whittaker/sw_txt.html
