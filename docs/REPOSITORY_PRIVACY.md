# Privacy del repository

Il repository pubblico contiene soltanto codice, configurazioni di esempio, test e
documentazione. Non deve mai contenere dati provenienti da una casella reale.

## Dati esclusi

- file OAuth scaricati da Google, refresh token e password per app Yahoo;
- preferenze personali e nomi scelti per gli account;
- database SQLite, file WAL/SHM, HMAC e storico delle scansioni;
- log locali, file `.env`, cartelle `data/`, `secrets/`, build e ambienti virtuali;
- schermate o benchmark che mostrino indirizzi, oggetti o contenuti reali.

Le credenziali sono nel gestore nativo del sistema e non nella cartella del progetto.
Le preferenze della GUI sono salvate nella directory applicativa dell'utente:

- macOS: `~/Library/Application Support/InboxLume/`;
- Windows: `%APPDATA%\InboxLume\`;
- Linux: `$XDG_CONFIG_HOME/inboxlume/` oppure `~/.config/inboxlume/`.

Se esistono già le preferenze del prototipo, InboxLume continua a utilizzare in
locale `Mail Guardian`/`mail-guardian` finché l'utente non sceglierà una migrazione
esplicita. Anche gli identificatori opachi nel gestore credenziali restano invariati,
così il cambio di nome non richiede di esportare o duplicare segreti. Questi percorsi
sono ignorati e non possono entrare nel repository.

I due database del prototipo macOS restano temporaneamente in `data/`, che è ignorata
integralmente da Git. I nuovi account usano una sottocartella separata accanto alle
preferenze del sistema.

## Prima di pubblicare

Eseguire i test e controllare i file candidati al commit:

```bash
git status --short
git ls-files
python3 scripts/audit_repository_privacy.py
PYTHONPATH=src python3 -m unittest tests.test_repository_privacy -q
```

L'audit controlla esattamente i file tracciati o non ignorati che potrebbero entrare
nel commit. Rifiuta formati di posta e database, nomi tipici di credenziali, percorsi
home personali, indirizzi non fittizi e firme note di token/chiavi. In caso di errore
stampa soltanto percorso e regola violata, mai il contenuto rilevato. Controlla
anche autore, committer e messaggi dell'intera cronologia Git: sono ammessi soltanto
indirizzi `noreply` pubblici esplicitamente previsti.

GitHub Pages viene generato esclusivamente da `main/docs`, con documentazione e
asset sanificati. Il sito non richiede né riceve credenziali o dati delle email.
