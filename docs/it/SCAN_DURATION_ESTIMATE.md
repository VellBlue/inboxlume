# Stima locale della durata del controllo

InboxLume può stimare la durata del controllo one-shot configurato prima di
caricare il modello locale. Il comando è esplicito: non viene eseguito
automaticamente all'apertura dell'applicazione.

## Confine di privacy

Lo stimatore chiede a Gmail o Yahoo soltanto gli identificatori dei messaggi che
corrispondono alle regole di età configurate. Esclude gli identificatori già
presenti nel registro locale protetto con HMAC, poi elimina dalla memoria gli ID
temporanei. Non:

- recupera oggetto, mittente, corpo, allegati o messaggi inviati;
- carica o scarica un modello;
- sposta, etichetta, cancella o elimina definitivamente email;
- salva in chiaro ID del provider o dettagli dell'hardware.

Un controllo concluso aggiunge soltanto una coppia aggregata: numero di messaggi
elaborati e secondi impiegati. I campioni restano separati per account, profilo
modello-policy, provider, destinazione, stato del Governor e una chiave
unidirezionale del profilo hardware.

## Stima e affidabilità

In assenza di campioni locali corrispondenti, InboxLume parte dal benchmark
preliminare a freddo del modello controllato e aggiunge una maggiorazione prudente
per provider e azioni. Include anche la seconda inferenza più breve di LumeGraph
sulla quota di cicli osservata localmente. Il risultato è indicato come
**affidabilità bassa** e usa un intervallo volutamente ampio.

Per ogni sessione locale corrispondente, il tasso osservato è

`r_i = secondi_impiegati_i / messaggi_elaborati_i`.

La stima centrale usa la mediana dei tassi. L'intervallo copre minimo e massimo
osservati con ulteriori margini di sicurezza. Almeno tre sessioni abbastanza
stabili portano l'indicazione ad **affidabilità alta**; campioni meno numerosi o
dispersi restano ad **affidabilità media**. È una stima operativa, non una promessa:
latenza di rete, dimensione dei messaggi, temperatura e carico del computer possono
cambiare la durata reale.
I campioni end-to-end corrispondenti includono già LumeGraph e non ricevono una
seconda maggiorazione.

Con un limite finito per sessione, il conteggio si ferma a quel limite e la GUI
segnala che potrebbero restare altre email idonee. Con **Tutte le idonee**, il
conteggio degli ID è esaustivo e termina naturalmente quando il provider non
restituisce più corrispondenze.
