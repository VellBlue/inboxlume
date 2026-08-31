# Pianificazione nativa

InboxLume può installare una pianificazione indipendente per ogni account dalla GUI.
È disattivata per impostazione predefinita e non viene creata durante installazione,
collegamento dell'account, quiz o scansioni manuali.

## Requisiti di attivazione

Il pulsante `Applica / aggiorna` è disponibile soltanto quando l'account ha:

- accesso in lettura alla sola Inbox;
- permesso operativo separato già configurato;
- calibrazione iniziale completa: almeno 40 risposte, incluse 3 `Tieni` e 20
  `Non tenere`;
- orario, frequenza, lotto e destinazione salvati e validi.

L'utente deve confermare esplicitamente l'installazione. Il worker pianificato
ricontrolla lo stato `enabled` e la calibrazione sul disco: non si affida soltanto
allo stato dei pulsanti della GUI.

## Backend per sistema operativo

- macOS: un LaunchAgent `launchd` per account in `~/Library/LaunchAgents`;
- Windows: un'attività per account in Utilità di pianificazione, eseguita con
  `InteractiveToken` e `LeastPrivilege`;
- Linux: un service `oneshot` e un timer utente `systemd` per account.

La GUI rileva automaticamente il sistema. Ogni backend crea, verifica, aggiorna o
rimuove soltanto risorse con un nome derivato dall'ID opaco dell'account. Non usa
shell, PowerShell, cron generico o comandi forniti dall'utente.

## Esecuzione

L'attività può avviarsi ogni giorno, dal lunedì al venerdì o in un giorno della
settimana scelto. Esegue esclusivamente:

```text
<python assoluto> -m inboxlume.scheduled_run \
  --account <id opaco> --settings <percorso assoluto>
```

L'entry point carica le regole salvate, acquisisce un lock per impedire
sovrapposizioni, elabora il lotto scelto oppure tutti i lotti interni necessari,
chiude connessioni e modello e termina. Non
accetta un comando arbitrario, un prompt, un percorso di input email o nuovi permessi.

Il consiglio mostrato nella GUI è di scegliere un orario in cui il computer è acceso
ma non sotto sforzo. Il modello usa temporaneamente RAM e CPU/GPU e viene scaricato
al termine. InboxLume non tenta di svegliare il computer.

## Azioni e recupero

La destinazione resta indipendente per account. `Quarantena` è la scelta consigliata;
il `Cestino diretto` mantiene i guardrail ma salta la finestra reversibile della
quarantena e dipende dalla conservazione del provider. InboxLume non implementa
svuotamento del Cestino o cancellazione permanente.

`Disattiva` rimuove soltanto l'attività nativa dell'account. Non cancella email,
credenziali, storico o preferenze. Un account con pianificazione attiva non può
essere disconnesso o rimosso finché l'attività non è stata disattivata.

## Limiti correnti

- l'utente deve essere connesso alla propria sessione sui sistemi che lo richiedono;
- il computer deve essere acceso;
- credenziali e cache del modello devono essere ancora disponibili;
- la pianificazione non rende il modello residente;
- nessuna pianificazione è attiva automaticamente dopo l'aggiornamento del software.
