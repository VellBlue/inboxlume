# Configurazione Yahoo separata

Yahoo usa un collegamento distinto da Gmail. InboxLume accetta soltanto
`imap.mail.yahoo.com:993` con TLS e non contiene alcun client SMTP.

## 1. Crea una password per app

Nella Sicurezza account Yahoo, crea una password per applicazioni di terze parti con
nome `InboxLume`. Non usare la password principale dell'account. Yahoo documenta
la procedura qui:

- <https://help.yahoo.com/kb/account/confirm-delete-password-sln15241.html>
- <https://help.yahoo.com/kb/imap-internet-message-access-protocol-sln4075.html>

## 2. Salvala nel gestore credenziali

La nuova GUI usa il gestore nativo di macOS, Windows o Linux. Il seguente comando
del prototipo usa invece direttamente il Portachiavi macOS:

Da Terminale, nella cartella del progetto:

```bash
PYTHONPATH=src python3 -m inboxlume.cli yahoo-authorize \
  --config config/accounts.example.json \
  --account yahoo_personale
```

Il comando chiede l'indirizzo completo e la password per app senza mostrarla. Li
salva nella voce tecnica separata `it.local.mail-guardian.yahoo.imap.v1`; il nome
resta invariato per rendere compatibili le credenziali create dal prototipo e non
apre ancora la
casella.

## 3. Probe senza corpi

```bash
PYTHONPATH=src python3 -m inboxlume.cli yahoo-probe \
  --config config/accounts.example.json \
  --account yahoo_personale
```

Il probe seleziona esclusivamente `INBOX` in sola lettura, conta i messaggi e cerca
al massimo un UID. Non legge oggetto, mittente o corpo e non modifica nulla.

## 4. Uso dalla GUI

Dopo il probe, riapri InboxLume, seleziona `Yahoo` e avvia un lotto piccolo. Il
modello Gemma è lo stesso, ma stato e credenziali sono separati da Gmail. Le proposte
sicure vengono spostate con il comando IMAP `UID MOVE` nella cartella esatta
`InboxLume-Quarantena`.

La precedente cartella `MailGuardian-Quarantena`, se presente, resta intatta. Il
rebranding non sposta retroattivamente le email e le nuove scansioni usano soltanto
la cartella InboxLume.

La GUI offre anche la spunta Yahoo indipendente `Invia direttamente al Cestino
(salta Quarantena)`. Quando è attiva, solo le nuove proposte sicure vengono spostate
con `UID MOVE` nella cartella Yahoo esatta `Trash`. La cartella deve già esistere:
InboxLume non la crea e fallisce senza modifiche se non è accessibile. Yahoo
svuota automaticamente il Cestino dopo 7 giorni, quindi questa modalità offre una
finestra di recupero molto più breve della quarantena personalizzata.

Il codice rifiuta qualsiasi fallback basato su `STORE \\Deleted` o `EXPUNGE`. Se il
server Yahoo non dichiara la capacità `MOVE`, la quarantena fallisce senza modificare
la casella. `Speciale` e `Importante` sono protette.

Non esistono comandi `STORE \\Deleted`, `EXPUNGE`, eliminazione permanente o
svuotamento del Cestino. Le email già presenti in quarantena non vengono toccate
quando si cambia la spunta. Nessuna pianificazione viene installata automaticamente;
quella opzionale per account richiede conferma e calibrazione completa nella GUI.
