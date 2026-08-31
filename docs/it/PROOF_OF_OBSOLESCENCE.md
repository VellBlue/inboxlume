# Proof of Obsolescence

Stato: operativa, interamente locale e separata per account e modello.

Proof of Obsolescence è il livello di policy tra le osservazioni di LumeGraph e una
proposta aggiuntiva di pulizia reversibile. Un semplice stato `completed` non basta
mai: InboxLume richiede un **testimone di chiusura** controllato e verifica che non
resti utilità operativa, probatoria, personale o di sicurezza.

## Testimoni verificati

Il motore usa cinque forme di evidenza complementari:

1. un codice monouso già letto supera la soglia OTP configurata per l’account e il
   ciclo deterministico risulta scaduto;
2. un’offerta pubblicitaria contiene una data non ambigua legata direttamente a
   una formula di scadenza italiana o inglese, e quella data è trascorsa;
3. un messaggio successivo con lo stesso riferimento di tracking HMAC completa o
   sostituisce uno stato di spedizione precedente; questo testimone richiede due
   osservazioni del ciclo ad alta confidenza eseguite con Gemma 26B;
4. più messaggi molto simili sono stati corretti esplicitamente come `Non tenere`,
   senza esempi `Tieni` in conflitto;
5. modello locale, correzioni ripetute e regime comportamentale recente concordano
   indipendentemente sulla perdita di utilità di un modello pubblicitario, social o
   spam.

Somiglianza e comportamento usano feature HMAC e valori aggregati, non il testo. Il
grafo salva soltanto la settimana di ricezione per ordinare gli eventi, mai la data
esatta. Relazioni tra messaggi della stessa settimana restano ambigue.

## Contratto operativo

- Una prova verificata può confermare un candidato del filtro ordinario.
- Con **Quarantena** può promuovere `Revisione` a Quarantena reversibile.
- Con **Cestino diretto** può rafforzare un candidato già scelto dalla policy
  ordinaria, ma non può promuovere direttamente `Revisione` al Cestino.
- Non può eliminare definitivamente, svuotare il Cestino, leggere Posta inviata o
  ampliare i permessi del provider.
- Un `Tieni` della policy deterministica prevale sempre.
- Mancanza della prova non significa prova di inutilità: questo livello si astiene
  e il filtro ordinario prosegue invariato.

## Utilità sempre protetta

La prova non può autorizzare pulizia per email inviate a se stessi, allegati da
rivedere, relazioni note, mittenti o parole protetti, documenti bancari, ricevute di
operazioni, pagamenti, bonifici, ricariche, tasse universitarie, accessi ad alto
rischio o messaggi con utilità probatoria, personale o di sicurezza. Nodi di
fatture, pagamenti, prenotazioni e flussi di sicurezza aiutano la protezione e il
contesto, ma non diventano autorizzazioni alla pulizia.

## Registro privato e gestione degli errori

SQLite conserva soltanto chiavi HMAC per messaggi e relazioni, enum controllate,
flag di utilità, fasce di confidenza, reason code ammessi e la settimana di
ricezione. Non salva mittente, oggetto, corpo, ID del provider, token, tracking o
data esatta.

Gli errori restano isolati: se ciclo o prova non sono disponibili, il filtro
ordinario termina senza promozioni basate sul grafo. La GUI mostra solo conteggi
aggregati dei testimoni.

