# Contribuire a InboxLume

InboxLume tratta dati estremamente sensibili. Una modifica utile non è accettabile
se amplia implicitamente i permessi o rende meno verificabile il confine locale.

## Prima di iniziare

Per correzioni piccole è sufficiente una pull request. Per nuove capacità, provider,
modelli o azioni sulla casella, aprire prima una proposta che descriva:

- problema e comportamento desiderato;
- dati letti, conservati e trasmessi;
- processi che ricevono rete, credenziali o capacità di scrittura;
- comportamento in caso di errore o incertezza;
- strategia di test e migrazione.

Non inviare mai email reali, token, file OAuth, password per app, database, log
completi o screenshot privati. Gli esempi devono usare esclusivamente dati sintetici.

## Ambiente di sviluppo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[desktop]'
python -m unittest discover -s tests -t .
python scripts/audit_repository_privacy.py
```

Su Windows l'attivazione è `.venv\Scripts\activate`. I test automatici non devono
collegarsi a caselle reali: provider, keyring e rete vanno sostituiti con fake locali.

## Criteri per una pull request

- preservare il confine Inbox-only;
- nessun SMTP, invio, bozza, cancellazione permanente, `EXPUNGE` o empty-trash;
- trattare il testo email come dato non attendibile;
- fallire chiuso quando il modello o il runtime non sono disponibili;
- aggiungere test proporzionati al rischio;
- aggiornare `docs/PRODUCT_MEMORY.md` se cambia una decisione di prodotto;
- eseguire suite e audit privacy prima del commit.

La licenza pubblica non è ancora stata scelta. Prima di accettare contributi esterni
verranno pubblicati licenza e termini coerenti; fino ad allora il repository resta in
preparazione e non deve essere presentato come progetto aperto ai contributi.
