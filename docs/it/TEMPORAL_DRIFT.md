# Deriva temporale delle preferenze

Il motore `preference-drift-v1` di InboxLume confronta l’evidenza locale con data
in due finestre, separatamente per account, profilo modello-policy e famiglia
semantica:

- **recente:** ultimi 45 giorni;
- **storica:** periodo precedente, fino a 180 giorni dal momento attuale.

Questo primo componente appartiene al Safety Governor. È volutamente più limitato
del futuro sistema Preference Weather: rileva variazioni sostanziali nell’evidenza
osservata, ma non crea ancora regimi personali multipli e non prevede l’interesse
futuro.

## Evidenza e pesi

Il report usa soltanto eventi già registrati localmente per messaggi noti a
InboxLume. Le osservazioni hanno forza diversa:

| Segnale | Peso positivo | Peso negativo |
|---|---:|---:|
| Apertura | 1 | 0 |
| Stella / importante | 3 | 0 |
| Ripristino dopo un cleanup di InboxLume | 5 | 0 |
| Quiz `Tieni` | 4 | 0 |
| Quiz `Non tenere` | 0 | 3 |
| Lasciata non letta | 0 | 0,15 |

L’apertura è quindi debole; ripristino e correzione esplicita sono evidenza
protettiva durevole. In entrambe le finestre viene calcolato uno score smussato:

`score = (2 + peso_positivo) / (4 + peso_positivo + peso_negativo)`.

Il confronto richiede almeno cinque messaggi distinti e otto unità di peso
effettivo in ciascuna finestra. Una deriva protettiva richiede un aumento dello
score di almeno 0,20 e almeno due eventi protettivi recenti. Segnali espliciti
recenti in conflitto sono anch’essi protettivi. Un calo viene soltanto segnalato e
non sblocca mai più cleanup.

## Effetto operativo

Con il Governor spento, la deriva è informativa e il filtro ordinario non cambia.
Con il Governor operativo:

- una deriva protettiva qualificata limita soltanto la famiglia interessata nella
  Quarantena governata;
- rimuove l’autorità aggiuntiva del Governor sul Cestino per quella famiglia;
- il Cestino diretto ordinario conserva i propri vincoli indipendenti di modello,
  calibrazione, policy e conferma, come già stabilito;
- evidenza stabile, debole, in calo o insufficiente non amplia mai l’autorità.

Il report non può eliminare definitivamente email, svuotare il Cestino,
ripristinare messaggi o spostarli retroattivamente.

## Privacy ed evidenza precedente

Il calcolo non interroga la casella, non riapre corpi e non carica il modello. Nel
database restano identità HMAC, categoria semantica, tipo di evento, data e conteggi
aggregati: non oggetto, corpo, mittente o ID del provider.

Le nuove risposte del quiz ricevono una data esplicita. Le risposte locali più
vecchie, create prima di questo aggiornamento, non hanno la data della risposta:
InboxLume le indica internamente come approssimazioni legacy e usa la data nota del
controllo. Possono contribuire alle finestre iniziali, ma l’interfaccia resta
prudente finché l’evidenza non è sufficiente.

Gmail può attualmente contribuire aperture, stelle, cambi di importanza, ripristini
e risposte del quiz già osservati da InboxLume. Yahoo contribuisce ripristini e
risposte del quiz; i normali cambiamenti letto/non letto di Yahoo non vengono
ancora importati come evidenza comportamentale. Questo limite viene dichiarato,
senza interpretare silenziosamente come disinteresse i segnali mancanti del
provider.
