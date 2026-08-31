# Packaging di predisposizione

Questi file preparano build locali non firmate per macOS, Windows e Linux. Non
esiste alcun comando di upload, release o deploy.

```bash
python -m pip install -e '.[desktop,packaging]'
python scripts/prepare_release_assets.py
python scripts/package_desktop.py          # sola validazione
python scripts/package_desktop.py --build  # build unsigned del sistema corrente
```

PyInstaller produce una GUI `onedir` sotto `release/staging/<sistema>`, esclusa
da Git, e un worker console `InboxLumeWorker` dedicato dentro lo stesso bundle.
Il worker è il solo processo usato per scansioni e attività native pianificate;
include anche lo script MLX offline. Il prototipo `dist/Mail Guardian.app` e il
bundle di sviluppo macOS non vengono usati né sovrascritti.

I template Windows e Linux contengono segnaposto deliberati per editore, GUID,
licenza e namespace. Devono essere sostituiti soltanto dopo le relative decisioni.
Su macOS il template degli entitlement è vuoto: ogni capacità aggiunta richiederà
una motivazione nella revisione dei permessi.

Prima di una release serviranno inoltre:

- firma Developer ID e notarizzazione su macOS;
- firma Authenticode e installer verificato su Windows;
- scelta tra AppImage/Flatpak e verifica dei backend keyring su Linux;
- test di installazione, aggiornamento e disinstallazione su macchine pulite;
- hash SHA-256 pubblici generati dai pacchetti definitivi.
