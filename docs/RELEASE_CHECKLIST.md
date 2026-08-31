# Checklist di pubblicazione

Stato corrente: **repository e Pages autorizzati come anteprima pubblica di
sviluppo; release dell'app bloccata intenzionalmente**.

Il file `release/release-gate.json` registra l'autorizzazione alla pubblicazione,
la licenza Apache-2.0, la superficie bilingue e gli asset sanificati. Perimetro
finale, pacchetti multipiattaforma, revisione di sicurezza e versione stabile
restano bloccanti. Non esistono workflow di release o upload di artefatti; Pages
usa direttamente `main/docs`.

## Prima di aprire il repository

- [ ] completare il perimetro funzionale deciso per la prima release;
- [x] scegliere nome utente/organizzazione e namespace definitivi;
- [x] scegliere consapevolmente la licenza del codice;
- [ ] sostituire tutti i segnaposto `REPLACE_` nei template di packaging;
- [ ] verificare nome, marchi e domini con una ricerca finale;
- [x] approvare screenshot e benchmark esclusivamente sanificati;
- [x] eseguire audit privacy su tutti i candidati al commit e sulla cronologia Git;
- [x] riesaminare README, changelog, limiti e funzioni future;
- [x] attivare GitHub Security Advisories prima di accettare segnalazioni.

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

- [x] inglese primario e italiano naturale completi per GUI e superfici pubbliche;
- [x] prova con email sintetiche inglesi, italiane e miste nello stesso lotto;
- [x] distinguere chiaramente funzioni disponibili, sperimentali e future;
- [x] non promettere sicurezza al 100% o unicità mondiale non dimostrabile;
- [x] spiegare differenze tra locale, provider email e servizi AI cloud;
- [x] dichiarare campione, hardware, prompt, policy e limiti dei benchmark;
- [x] nessun analytics, font remoto, cookie o risorsa di terze parti nel sito;
- [x] controllo accessibilità, responsive layout e link locali;
- [x] configurare Pages soltanto dopo autorizzazione esplicita.

## Apertura del gate

Soltanto al termine aggiornare versione stabile e gate, poi eseguire:

```bash
python scripts/check_release_gate.py --require-ready
python scripts/audit_repository_privacy.py
python -m unittest discover -s tests -t .
```

La pubblicazione del repository e del sito non apre questo gate. L'apertura
autorizzerà soltanto l'eventuale aggiunta futura di un workflow di release, che
dovrà essere revisionato separatamente.
