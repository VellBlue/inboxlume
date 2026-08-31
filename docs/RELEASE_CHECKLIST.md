# Checklist di pubblicazione

Stato corrente: **pubblicazione bloccata intenzionalmente**.

Il file `release/release-gate.json` contiene tutti i gate impostati su `false` e la
versione è di sviluppo. Non esistono workflow di release, upload o deploy Pages.

## Prima di aprire il repository

- [ ] completare il perimetro funzionale deciso per la prima release;
- [ ] scegliere nome utente/organizzazione e namespace definitivi;
- [ ] scegliere consapevolmente la licenza del codice;
- [ ] sostituire tutti i segnaposto `REPLACE_` nei template di packaging;
- [ ] verificare nome, marchi e domini con una ricerca finale;
- [ ] approvare screenshot e benchmark esclusivamente sanificati;
- [ ] eseguire audit privacy su tutti i candidati al commit;
- [ ] riesaminare README, changelog, limiti e funzioni future;
- [ ] attivare GitHub Security Advisories prima di accettare segnalazioni.

## Qualità multipiattaforma

- [ ] suite completa con PySide su macOS, Windows e Linux;
- [ ] autenticazione Gmail testata con un account di prova dedicato;
- [ ] Yahoo testato con un account di prova dedicato;
- [ ] Quarantena, annullamento, ripresa e schedule testati su ogni sistema;
- [ ] installazione, aggiornamento e disinstallazione su macchine pulite;
- [ ] pacchetti firmati/notarizzati e firme verificate dopo il download;
- [ ] hash SHA-256 pubblicati per ogni pacchetto;
- [ ] nessuna credenziale, preferenza o cronologia inclusa nei bundle.

## Sicurezza

- [ ] threat model aggiornato e revisione dei permessi completata;
- [ ] nessuna regressione su Inbox-only, Sent, SMTP, delete ed empty-trash;
- [ ] test di prompt injection, output malformato, timeout e runtime assente;
- [ ] test di isolamento tra più account;
- [ ] backtest sulle categorie protette e report di falsi cleanup;
- [ ] dipendenze bloccate con hash/SBOM e GitHub Actions fissate a SHA immutabili;
- [ ] verifica delle licenze di dipendenze, modelli e asset;
- [ ] piano di rollback e revoca di una release difettosa.

## Sito e dichiarazioni

- [ ] inglese primario e italiano naturale completi per GUI e superfici pubbliche;
- [ ] prova con email sintetiche inglesi, italiane e miste nello stesso lotto;
- [ ] distinguere chiaramente funzioni disponibili, sperimentali e future;
- [ ] non promettere sicurezza al 100% o unicità mondiale non dimostrabile;
- [ ] spiegare differenze tra locale, provider email e servizi AI cloud;
- [ ] dichiarare campione, hardware, prompt, policy e limiti dei benchmark;
- [ ] nessun analytics, font remoto, cookie o risorsa di terze parti nel sito;
- [ ] controllo accessibilità, responsive layout e link locali;
- [ ] configurare Pages soltanto dopo autorizzazione esplicita.

## Apertura del gate

Soltanto al termine aggiornare versione stabile e gate, poi eseguire:

```bash
python scripts/check_release_gate.py --require-ready
python scripts/audit_repository_privacy.py
python -m unittest discover -s tests -t .
```

L'apertura del gate non pubblica nulla da sola: autorizza soltanto l'eventuale
aggiunta futura di un workflow di release, che dovrà essere revisionato separatamente.
