import Foundation
import SwiftUI

private struct BridgeEvent: Decodable {
    let type: String
    let position: Int?
    let total: Int?
    let sender: String?
    let subject: String?
    let received_at: String?
    let unread: Bool?
    let category: String?
    let confidence: Double?
    let preview: String?
    let message: String?
    let presented: Int?
    let keep: Int?
    let dont_keep: Int?
    let unsure: Int?
    let newly_processed: Int?
    let ledger: ScanLedger?
    let changes_mailbox: Bool?
    let automatic_quarantine: AutomaticQuarantine?
}

private struct ScanLedger: Decodable {
    let processed_total: Int?
}

private struct AutomaticQuarantine: Decodable {
    let selected: Int?
    let applied: Int?
    let destination: String?
}

private enum MailAccount: String, CaseIterable, Identifiable {
    case gmail
    case yahoo

    var id: String { rawValue }
    var title: String { self == .gmail ? "Gmail" : "Yahoo" }
    var accountID: String { self == .gmail ? "gmail_personale" : "yahoo_personale" }
    var stateDatabase: String {
        self == .gmail ? "data/preferences.sqlite3" : "data/yahoo_preferences.sqlite3"
    }
}

@MainActor
private final class QuizController: ObservableObject {
    private enum Operation {
        case scan
        case review
    }

    @Published var event: BridgeEvent?
    @Published var status = "Quiz non avviato"
    @Published var running = false
    @Published var waitingForAnswer = false

    private var process: Process?
    private var input: FileHandle?
    private var outputBuffer = Data()
    private var operation: Operation?

    var scanning: Bool { running && operation == .scan }
    var reviewing: Bool { running && operation == .review }

    private var projectRoot: URL {
        if let configured = ProcessInfo.processInfo.environment["MAIL_GUARDIAN_PROJECT_ROOT"] {
            return URL(fileURLWithPath: configured, isDirectory: true)
        }
        if let bundled = Bundle.main.object(forInfoDictionaryKey: "MailGuardianProjectRoot") as? String {
            return URL(fileURLWithPath: bundled, isDirectory: true)
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    }

    func startReview(limit: Int, account: MailAccount) {
        guard !running else { return }
        let safeLimit = min(max(limit, 1), 500)
        let sampleLimit = min(max(safeLimit * 2, 20), 500)
        launch(
            arguments: [
                "-m", "inboxlume.gui_bridge",
                "--config", projectRoot.appendingPathComponent("config/accounts.example.json").path,
                "--account", account.accountID,
                "--mode", account == .gmail ? "shadow-review" : "quiz",
                "--scan-profile", "gemma26-policy-v2",
                "--search-limit", "500",
                "--backend", account == .yahoo ? "gemma26" : "ollama",
                "--ollama-model", "qwen3-vl:8b",
                "--limit", String(safeLimit),
                "--sample-limit", String(sampleLimit),
                "--state-db", projectRoot.appendingPathComponent(account.stateDatabase).path,
                "--confirm-read-bodies",
            ],
            operation: .review,
            initialStatus: account == .gmail
                ? "Preparazione di massimo \(safeLimit) proposte Gmail…"
                : "Preparazione del quiz opzionale Yahoo…"
        )
    }

    func startScan(limit: Int, account: MailAccount, directToTrash: Bool) {
        guard !running else { return }
        let safeLimit = min(max(limit, 1), 500)
        let command = account == .gmail ? "gmail-shadow-run" : "yahoo-shadow-run"
        let mutationFlag = account == .gmail
            ? "--apply-shadow-labels"
            : "--apply-shadow-quarantine"
        var arguments = [
            "-m", "inboxlume.cli", command,
            "--config", projectRoot.appendingPathComponent("config/accounts.example.json").path,
            "--account", account.accountID,
            "--backend", "gemma26",
            "--limit", String(safeLimit),
            "--search-limit", "0",
            "--state-db", projectRoot.appendingPathComponent(account.stateDatabase).path,
            "--confirm-read-bodies",
            mutationFlag,
        ]
        if directToTrash {
            arguments.append("--direct-to-trash")
        }
        launch(
            arguments: arguments,
            operation: .scan,
            initialStatus: directToTrash
                ? "Gemma controlla fino a \(safeLimit) email \(account.title); le proposte sicure andranno nel Cestino…"
                : "Gemma controlla fino a \(safeLimit) email \(account.title) e mette in quarantena le proposte sicure…"
        )
    }

    private func launch(
        arguments: [String],
        operation: Operation,
        initialStatus: String
    ) {
        let python = URL(fileURLWithPath: "/opt/homebrew/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: python.path) else {
            status = "Python locale non trovato in /opt/homebrew/bin/python3"
            return
        }

        let task = Process()
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        task.executableURL = python
        task.currentDirectoryURL = projectRoot
        task.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = projectRoot.appendingPathComponent("src").path
        environment["HF_HUB_OFFLINE"] = "1"
        environment["TRANSFORMERS_OFFLINE"] = "1"
        task.environment = environment
        task.standardInput = stdinPipe
        task.standardOutput = stdoutPipe
        task.standardError = stderrPipe

        stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            DispatchQueue.main.async { self?.consume(data) }
        }
        stderrPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if !data.isEmpty {
                DispatchQueue.main.async {
                    self?.status = "Errore tecnico nel processo locale."
                }
            }
        }
        task.terminationHandler = { [weak self] task in
            DispatchQueue.main.async {
                self?.running = false
                self?.waitingForAnswer = false
                if task.terminationStatus != 0 && task.terminationStatus != 130 {
                    self?.status = "Il processo locale si è interrotto."
                }
                self?.process = nil
                self?.input = nil
            }
        }

        do {
            try task.run()
            process = task
            input = stdinPipe.fileHandleForWriting
            outputBuffer.removeAll(keepingCapacity: true)
            self.operation = operation
            event = nil
            running = true
            waitingForAnswer = false
            status = initialStatus
        } catch {
            status = "Impossibile avviare il processo locale."
        }
    }

    private func consume(_ data: Data) {
        outputBuffer.append(data)
        while let newline = outputBuffer.firstIndex(of: 0x0A) {
            let line = outputBuffer.prefix(upTo: newline)
            outputBuffer.removeSubrange(...newline)
            guard let decoded = try? JSONDecoder().decode(BridgeEvent.self, from: line) else {
                continue
            }
            handle(decoded)
        }
    }

    private func handle(_ newEvent: BridgeEvent) {
        event = newEvent
        switch newEvent.type {
        case "candidate":
            waitingForAnswer = true
            status = "Controlla la proposta: la mail non verrà modificata."
        case "summary":
            waitingForAnswer = false
            running = false
            status = "\(newEvent.presented ?? 0) risposte: \(newEvent.keep ?? 0) tieni, "
                + "\(newEvent.dont_keep ?? 0) non tenere, \(newEvent.unsure ?? 0) non so."
        case "shadow_run_summary":
            waitingForAnswer = false
            running = false
            let current = newEvent.newly_processed ?? 0
            let total = newEvent.ledger?.processed_total ?? current
            let applied = newEvent.automatic_quarantine?.applied ?? 0
            let destination = newEvent.automatic_quarantine?.destination == "trash"
                ? "spostate nel Cestino"
                : "messe in quarantena"
            status = "Concluso: \(current) nuove analizzate, \(applied) \(destination), \(total) totali registrate."
        case "error":
            waitingForAnswer = false
            running = false
            status = newEvent.message ?? "Errore locale"
        default:
            break
        }
    }

    func answer(_ value: String) {
        guard reviewing, waitingForAnswer, let input else { return }
        guard let data = "{\"answer\":\"\(value)\"}\n".data(using: .utf8) else { return }
        do {
            try input.write(contentsOf: data)
            waitingForAnswer = false
            status = "Preferenza salvata localmente…"
        } catch {
            status = "Il processo locale non risponde."
        }
    }

    func stop() {
        if running {
            if reviewing && waitingForAnswer {
                answer("quit")
            }
            process?.terminate()
        }
        running = false
        waitingForAnswer = false
        operation = nil
    }
}

private struct ContentView: View {
    @StateObject private var controller = QuizController()
    @State private var scanLimit = 50
    @State private var selectedAccount: MailAccount = .gmail
    @AppStorage("mailGuardian.gmail.directToTrash") private var gmailDirectToTrash = false
    @AppStorage("mailGuardian.yahoo.directToTrash") private var yahooDirectToTrash = false

    private var directToTrash: Bool {
        selectedAccount == .gmail ? gmailDirectToTrash : yahooDirectToTrash
    }

    private var directToTrashBinding: Binding<Bool> {
        Binding(
            get: { directToTrash },
            set: { newValue in
                if selectedAccount == .gmail {
                    gmailDirectToTrash = newValue
                } else {
                    yahooDirectToTrash = newValue
                }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Mail Guardian")
                .font(.largeTitle.bold())
            Text("Account separati • modello locale • nessuna eliminazione permanente")
                .foregroundStyle(.green)

            Picker("Account", selection: $selectedAccount) {
                ForEach(MailAccount.allCases) { account in
                    Text(account.title).tag(account)
                }
            }
            .pickerStyle(.segmented)
            .disabled(controller.running)

            if selectedAccount == .yahoo && !controller.running {
                Text("Yahoo usa credenziali e storico separati. Prima del primo uso occorre configurare la password per app dal Terminale.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if controller.scanning {
                Spacer()
                ProgressView()
                    .controlSize(.large)
                Text(selectedAccount == .gmail
                    ? (directToTrash
                        ? "Gemma viene chiusa alla fine; le proposte sicure vanno nel Cestino Gmail."
                        : "Gemma viene chiusa alla fine; le quarantene restano nella Inbox.")
                    : (directToTrash
                        ? "Gemma viene chiusa alla fine; le proposte sicure vanno nel Cestino Yahoo."
                        : "Gemma viene chiusa alla fine; le proposte vanno nella cartella Quarantena Yahoo."))
                    .foregroundStyle(.secondary)
                Button("Interrompi") { controller.stop() }
                Spacer()
            } else if let event = controller.event, event.type == "candidate" {
                Text("Email \(event.position ?? 0)/\(event.total ?? 0)")
                    .font(.headline)
                Text("Da: \(event.sender?.isEmpty == false ? event.sender! : "(mittente assente)")")
                    .textSelection(.enabled)
                Text(event.subject?.isEmpty == false ? event.subject! : "(senza oggetto)")
                    .font(.title2.bold())
                    .textSelection(.enabled)
                Text(metadata(event))
                    .foregroundStyle(.secondary)

                ScrollView {
                    Text(event.preview?.isEmpty == false ? event.preview! : "(corpo vuoto)")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(12)
                }
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.3)))

                HStack {
                    Button("Proteggi") { controller.answer("keep") }
                    Button("Non so") { controller.answer("unsure") }
                    Button("Conferma non tenere") { controller.answer("dont_keep") }
                }
                .disabled(!controller.waitingForAnswer)
            } else {
                Spacer()
                GroupBox("Controllo delle email vecchie") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Non lette da almeno 30 giorni e codici monouso letti da almeno 7 giorni.")
                            .foregroundStyle(.secondary)
                        HStack {
                            Text("Massimo per questa sessione:")
                            TextField("500", value: $scanLimit, format: .number)
                                .frame(width: 80)
                            Stepper("", value: $scanLimit, in: 1...500, step: 50)
                                .labelsHidden()
                        }
                        Toggle(
                            "Invia direttamente al Cestino (salta Quarantena)",
                            isOn: directToTrashBinding
                        )
                        .disabled(controller.running)
                        if directToTrash {
                            Text(selectedAccount == .gmail
                                ? "Gmail elimina automaticamente dal Cestino dopo 30 giorni."
                                : "Attenzione: Yahoo elimina automaticamente dal Cestino dopo 7 giorni.")
                                .font(.caption)
                                .foregroundStyle(selectedAccount == .yahoo ? .orange : .secondary)
                        }
                        Button("Avvia controllo con Gemma") {
                            scanLimit = min(max(scanLimit, 1), 500)
                            controller.startScan(
                                limit: scanLimit,
                                account: selectedAccount,
                                directToTrash: directToTrash
                            )
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(controller.running)
                    }
                    .padding(6)
                }

                Button(controller.reviewing ? "Preparazione…" : "Quiz opzionale: correggi proposte") {
                    scanLimit = min(max(scanLimit, 1), 500)
                    controller.startReview(limit: scanLimit, account: selectedAccount)
                }
                .disabled(controller.running)

                Spacer()
            }

            Text(controller.status)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Esci") {
                    controller.stop()
                    NSApplication.shared.terminate(nil)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 680, minHeight: 560)
        .preferredColorScheme(.light)
        .onDisappear { controller.stop() }
    }

    private func metadata(_ event: BridgeEvent) -> String {
        let state = event.unread == true ? "non letta" : "letta"
        if let rawConfidence = event.confidence {
            let confidence = Int((rawConfidence * 100).rounded())
            return "\(event.received_at ?? "") • \(state) • \(event.category ?? "incerta") (\(confidence)%)"
        }
        return "\(event.received_at ?? "") • \(state) • \(event.category ?? "incerta")"
    }
}

@main
private struct MailGuardianGUI: App {
    var body: some Scene {
        WindowGroup("Mail Guardian — Revisione locale") {
            ContentView()
        }
        .defaultSize(width: 760, height: 620)
    }
}
