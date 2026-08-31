# Backtest sintetico locale delle minacce

Stato: corpus versionato, motore di valutazione aggregata, worker desktop isolato
e integrazione bilingue nella GUI implementati.

`synthetic-threat-corpus-v1` è incluso in InboxLume e contiene 25 casi interamente
sintetici in inglese, italiano e lingua mista. Copre furto di credenziali,
imitazione di marchi, falsi costi di consegna, frodi economiche, inganni Unicode,
esche malware e casi benigni difficili: reimpostazioni password richieste, avvisi
di sicurezza, ricevute, consegne, scuola, newsletter e scrittura non madrelingua.

Il backtest non si collega mai a Gmail o Yahoo. Elabora in memoria il corpus con lo
stesso motore deterministico, analizzatore semantico locale e consenso usati dalla
scansione. L’output contiene soltanto matrice di confusione aggregata, metriche per
lingua/scenario controllati, numero di fallimenti del modello e impronta SHA-256
del corpus. Non contiene testo o identità dei casi.

L’obiettivo diagnostico preliminare richiede almeno 20 casi bilanciati, analisi
semantica locale, precisione almeno 0,90, richiamo almeno 0,80, tasso osservato di
falsi positivi non superiore a 0,05 e zero fallimenti del modello. Il resoconto
mostra anche il limite superiore di Wilson al 95% sui falsi positivi benigni.
Superare questo piccolo test sintetico non dimostra statisticamente la sicurezza
in produzione e non autorizza mai azioni sulla casella.

Il riquadro Protezione dalle minacce esegue la diagnostica con il modello locale
selezionato in un processo separato. Mostra precisione, richiamo, falsi positivi
benigni con limite superiore al 95% e fallimenti del modello. L’interfaccia resta
reattiva, offre Interrompi, non richiede autenticazione email e scarica il modello
al termine.
