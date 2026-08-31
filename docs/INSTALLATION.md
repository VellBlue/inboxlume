# Installazione e compatibilità

Stato: documentazione di predisposizione, non ancora una release supportata.

## Requisiti comuni

- Python 3.11–3.13 per lo sviluppo; le build di release useranno Python 3.12;
- almeno 12 GB di RAM per il profilo più leggero;
- Ollama con `qwen3-vl:8b` già locale, oppure MLX e una cache Gemma consentita su
  Apple Silicon;
- keyring nativo disponibile e sbloccato;
- accesso Internet soltanto dall'integrazione email verso gli endpoint dichiarati.

InboxLume non scarica automaticamente modelli. Il contenuto delle email non viene
inviato a provider AI o servizi di telemetria.

## Avvio da sorgente

### macOS e Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[desktop]'
inboxlume-desktop
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[desktop]"
inboxlume-desktop
```

Linux richiede un servizio Secret Service/KWallet funzionante. Se il keyring sicuro
non è disponibile, InboxLume rifiuta di memorizzare le credenziali.

## Configurazione account

- [Gmail: OAuth per applicazione desktop](GMAIL_SETUP.md)
- [Yahoo: password per app e IMAP](YAHOO_SETUP.md)
- [Modelli locali e requisiti hardware](LOCAL_MODELS.md)
- [Pianificazione nativa](SCHEDULING.md)

Collegare prima un solo account, completare il quiz iniziale e provare piccoli lotti
in Quarantena. Il Cestino diretto non è la configurazione consigliata.

## Pacchetti futuri

I template locali sono in `packaging/`, ma non sono ancora distribuiti:

- macOS: app firmata Developer ID e notarizzata;
- Windows: cartella PyInstaller firmata e installer Inno Setup Authenticode;
- Linux: formato da scegliere tra AppImage e Flatpak dopo i test keyring.

Non installare pacchetti che dichiarano di essere InboxLume finché nel repository
ufficiale non saranno pubblicati hash e firme verificabili.
