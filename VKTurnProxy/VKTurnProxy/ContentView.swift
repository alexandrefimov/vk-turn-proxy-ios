import SwiftUI
import NetworkExtension
import WebKit
import UniformTypeIdentifiers
import os.log

private let captchaLog = OSLog(subsystem: "com.vkturnproxy.app", category: "Captcha")

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()

    // All config stored in AppStorage, edited on SettingsView
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("useWrap") private var useWrap = false
    @AppStorage("wrapKeyHex") private var wrapKeyHex = ""
    @AppStorage("numConnections") private var numConnections = 30
    @AppStorage("credPoolCooldownSeconds") private var credPoolCooldownSeconds = 150

    var body: some View {
        NavigationView {
            // ScrollView is the safety net for very small screens
            // (iPhone SE etc.). When the stats grid grows enough that
            // it would push Logs/Settings below the visible area, the
            // user can scroll instead of losing access to them. On
            // larger screens the content fits without scrolling.
            ScrollView {
                VStack(spacing: 16) {
                    // Status indicator — compact size so the rest of the
                    // controls stay visible on small screens.
                    Circle()
                        .fill(statusColor)
                        .frame(width: 44, height: 44)
                        .shadow(color: statusColor.opacity(0.5), radius: 8)
                        .padding(.top, 8)

                    Text(statusText)
                        .font(.headline)

                    if let error = tunnel.errorMessage {
                        Text(error)
                            .font(.caption)
                            .foregroundColor(.red)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }

                    // Stats (shown when connected)
                    if tunnel.status == .connected {
                        StatsView(tunnel: tunnel)
                            .padding(.horizontal)
                    }

                    // Connect / Disconnect button
                    Button(action: {
                        if tunnel.status == .connected || tunnel.status == .connecting {
                            tunnel.disconnect()
                        } else {
                            let config = TunnelConfig(
                                privateKey: privateKey,
                                peerPublicKey: peerPublicKey,
                                presharedKey: presharedKey.isEmpty ? nil : presharedKey,
                                tunnelAddress: tunnelAddress,
                                dnsServers: dnsServers,
                                allowedIPs: allowedIPs,
                                vkLink: vkLink,
                                peerAddress: peerAddress,
                                useDTLS: useDTLS,
                                useWrap: useWrap,
                                wrapKeyHex: wrapKeyHex,
                                numConnections: numConnections,
                                credPoolCooldownSeconds: credPoolCooldownSeconds
                            )
                            Task {
                                await tunnel.connect(config: config)
                            }
                        }
                    }) {
                        Text(buttonText)
                            .font(.headline)
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(buttonColor)
                            .cornerRadius(12)
                    }
                    .padding(.horizontal)
                    .padding(.top, 8)

                    // Logs & Settings links
                    HStack(spacing: 24) {
                        NavigationLink(destination: LogsView(tunnel: tunnel)) {
                            Label("Logs", systemImage: "doc.text")
                        }
                        NavigationLink(destination: SettingsView()) {
                            Label("Settings", systemImage: "gear")
                        }
                    }
                    .padding(.bottom, 8)
                }
                .frame(maxWidth: .infinity)
                .padding(.top, 8)
            }
            .navigationTitle("VK Turn Proxy")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $tunnel.captchaPending) {
                if let urlStr = tunnel.captchaImageURL, let url = URL(string: urlStr) {
                    CaptchaWebView(
                        url: url,
                        captchaSID: tunnel.captchaSID ?? "",
                        onSolved: { token in
                            NSLog("[Captcha] Token received (%d chars), sending to tunnel", token.count)
                            tunnel.solveCaptcha(answer: token)
                        },
                        onDismiss: {
                            // Don't send fake answer — just dismiss the sheet.
                            // The captcha will re-appear on next poll if not actually solved.
                            NSLog("[Captcha] Sheet dismissed without token")
                            tunnel.onCaptchaSheetDismissed()
                            tunnel.captchaPending = false
                            tunnel.captchaImageURL = nil
                        },
                        onLimitDetected: { tunnel.onCaptchaLimitDetected() },
                        onCaptchaReady: { tunnel.onCaptchaReady() },
                        onLog: { tunnel.logFromCaptchaView($0) },
                        tunnel: tunnel
                    )
                }
            }
        }
    }

    // MARK: - Helpers

    private var statusColor: Color {
        // pre-bootstrap captcha probe runs while NEVPNStatus is still
        // .disconnected — show the "connecting" color so the UI reflects
        // that connect() is actually working. See TunnelManager.connect.
        if tunnel.preBootstrapInProgress { return .yellow }
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting: return .orange
        default: return .gray
        }
    }

    private var statusText: String {
        if tunnel.preBootstrapInProgress { return "Preparing..." }
        switch tunnel.status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .reasserting: return "Reconnecting..."
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        @unknown default: return "Unknown"
        }
    }

    private var buttonText: String {
        if tunnel.preBootstrapInProgress { return "Disconnect" }
        switch tunnel.status {
        case .connected, .connecting: return "Disconnect"
        default: return "Connect"
        }
    }

    private var buttonColor: Color {
        if tunnel.preBootstrapInProgress { return .red }
        switch tunnel.status {
        case .connected, .connecting: return .red
        default: return .blue
        }
    }
}

// MARK: - Settings Screen

struct SettingsView: View {
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("useWrap") private var useWrap = false
    @AppStorage("wrapKeyHex") private var wrapKeyHex = ""
    @AppStorage("numConnections") private var numConnections = 30
    @AppStorage("credPoolCooldownSeconds") private var credPoolCooldownSeconds = 150

    // Backup & Restore state. exportURL drives the share sheet; the
    // sheet only appears when this is non-nil so the URL is guaranteed
    // valid by the time UIActivityViewController is constructed. Each
    // confirm alert and the document picker are gated by their own
    // `show*` flag — keeping them independent prevents any one of them
    // from blocking the others if the user rapid-taps.
    //
    // Wrapped in IdentifiableURL because sheet(item:) requires the bound
    // type to be Identifiable, and we deliberately avoid extending URL
    // itself — Apple may ship that conformance in a future Foundation
    // and the resulting silent override would be a debugging trap.
    @State private var exportURL: IdentifiableURL? = nil
    @State private var showImportPicker = false
    @State private var pendingImportConfig: AppConfig? = nil
    @State private var showImportConfirm = false
    @State private var showResetConfirm = false
    @State private var alertMessage: String? = nil
    @State private var alertTitle: String = ""

    var body: some View {
        Form {
            Section("VK TURN Proxy") {
                TextField("VK Call Link", text: $vkLink)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Proxy Server (host:port)", text: $peerAddress)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                Toggle("DTLS Obfuscation", isOn: $useDTLS)

                // WRAP layer: ChaCha20-XOR every UDP packet between DTLS
                // and TURN ChannelData so VK's TURN-relay payload classifier
                // can't recognise DTLS+WG and tag the destination endpoint.
                // The endpoint configured above (Proxy Server) MUST be a
                // server running with matching -wrap and -wrap-key from the
                // upstream cacggghp/vk-turn-proxy WRAP-aware build —
                // without that, the DTLS handshake fails because the
                // server-side raw bytes get XOR'd by our wrapping.
                Toggle("Use WRAP (peer must be WRAP-aware)", isOn: $useWrap)

                if useWrap {
                    SecureField("WRAP key (64 hex chars)", text: $wrapKeyHex)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        // Strip whitespace as the user types / pastes — paste
                        // from clipboard often picks up leading/trailing
                        // spaces or newlines, and a hex key has no legitimate
                        // use for spaces inside, so silently cleaning is
                        // safe. Without this, a stray space caused the Go
                        // bridge to fail decoding with
                        // "encoding/hex: invalid byte: U+0020 ' '" and
                        // disable WRAP for the session — observed in user
                        // report 2026-05-07. The Go bridge also strips
                        // whitespace defensively as a backstop, but doing
                        // it here keeps the stored value clean and avoids
                        // a confusing reopen-Settings experience where
                        // the SecureField has hidden whitespace inside.
                        .onChange(of: wrapKeyHex) { newValue in
                            let cleaned = newValue.filter { !$0.isWhitespace }
                            if cleaned != newValue {
                                wrapKeyHex = cleaned
                            }
                        }
                }

                Stepper("Connections: \(numConnections)", value: $numConnections, in: 1...64)

                Stepper("Cred pool cooldown: \(credPoolCooldownSeconds) s", value: $credPoolCooldownSeconds, in: 30...600, step: 30)
            }

            Section("WireGuard") {
                SecureField("Private Key (base64)", text: $privateKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Peer Public Key (base64)", text: $peerPublicKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                SecureField("Preshared Key (base64)", text: $presharedKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Tunnel Address", text: $tunnelAddress)
                    .autocapitalization(.none)

                TextField("DNS Servers", text: $dnsServers)
                    .autocapitalization(.none)

                TextField("Allowed IPs", text: $allowedIPs)
                    .autocapitalization(.none)
            }

            Section {
                Button(action: handleExport) {
                    Label("Export Full Backup…", systemImage: "square.and.arrow.up")
                }

                Button(action: { showImportPicker = true }) {
                    Label("Import Full Backup…", systemImage: "square.and.arrow.down")
                }

                Button(role: .destructive, action: { showResetConfirm = true }) {
                    Label("Reset TURN Cache", systemImage: "trash")
                }
            } header: {
                Text("Backup & Restore")
            } footer: {
                // Make the sensitivity explicit. Settings + WireGuard
                // private/preshared keys + cached VK TURN credentials
                // give whoever holds the file the same VPN access the
                // user has — there's no encryption layer.
                Text("Backup contains all settings, WireGuard keys, and TURN credentials. Treat the exported file as a secret.")
            }
        }
        .navigationTitle("Settings")
        // Share sheet for the freshly-exported temp file. Bound to a
        // sheet(item:) so the file is in scope while the sheet is open
        // and gets cleaned up implicitly when SwiftUI sets the binding
        // back to nil after dismissal.
        .sheet(item: $exportURL) { wrapped in
            ShareSheet(activityItems: [wrapped.url])
        }
        // Document picker for Import. Filtering on .json keeps random
        // unrelated files out of the picker — the AppConfig decode would
        // reject them anyway, but the friendly hint is nicer.
        .sheet(isPresented: $showImportPicker) {
            DocumentPicker(contentTypes: [.json]) { url in
                handleImportPicked(url: url)
            }
        }
        // Import confirm — shown after the picker hands us a valid file
        // we successfully parsed. pendingImportConfig is the parsed
        // AppConfig waiting to be applied; the alert's primary button
        // does the apply.
        .alert("Import Backup?", isPresented: $showImportConfirm, presenting: pendingImportConfig) { config in
            Button("Import", role: .destructive) {
                applyPendingImport(config)
            }
            Button("Cancel", role: .cancel) {
                pendingImportConfig = nil
            }
        } message: { config in
            let date = Date(timeIntervalSince1970: TimeInterval(config.exportedAt))
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .short
            let credCount = config.turnPool?.creds.count ?? 0
            return Text("Backup from \(formatter.string(from: date)) with \(credCount) cached TURN cred(s). This will overwrite all current settings.")
        }
        // Reset confirm — destructive button on the alert removes the
        // creds-pool.json. UserDefaults are untouched.
        .alert("Reset TURN Cache?", isPresented: $showResetConfirm) {
            Button("Reset", role: .destructive) {
                handleReset()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Deletes the cached TURN credentials. The pool will be rebuilt on next connect via the regular VK API + captcha flow.")
        }
        // Result alert — shared across export/import/reset success and
        // error paths since the message is what differs, not the
        // presentation. Dismiss is just OK.
        .alert(alertTitle, isPresented: Binding(
            get: { alertMessage != nil },
            set: { if !$0 { alertMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            if let msg = alertMessage {
                Text(msg)
            }
        }
    }

    // MARK: - Backup actions

    private func handleExport() {
        do {
            let url = try BackupManager.exportToTempFile()
            exportURL = IdentifiableURL(url: url)
        } catch {
            alertTitle = "Export Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func handleImportPicked(url: URL) {
        do {
            let config = try BackupManager.importFromFileURL(url)
            pendingImportConfig = config
            showImportConfirm = true
        } catch {
            alertTitle = "Import Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func applyPendingImport(_ config: AppConfig) {
        do {
            try BackupManager.applyConfig(config)
            pendingImportConfig = nil
            alertTitle = "Import Complete"
            let credCount = config.turnPool?.creds.count ?? 0
            alertMessage = "Settings restored. TURN cache: \(credCount) slot(s)."
        } catch {
            alertTitle = "Import Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func handleReset() {
        do {
            try BackupManager.resetTurnCache()
            alertTitle = "TURN Cache Cleared"
            alertMessage = "creds-pool.json deleted. The pool will be rebuilt on next connect."
        } catch {
            alertTitle = "Reset Failed"
            alertMessage = error.localizedDescription
        }
    }
}

/// Wraps a URL so sheet(item:) can use it without us conforming URL itself
/// to Identifiable — see exportURL's comment for why we avoid the
/// retroactive conformance.
struct IdentifiableURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

// MARK: - Document Picker (Import file)

/// UIDocumentPickerViewController wrapper for picking a JSON backup file.
/// The picker hands back a security-scoped URL that the caller must
/// access via startAccessingSecurityScopedResource — BackupManager.importFromFileURL
/// handles that internally so this wrapper just forwards the URL.
///
/// contentTypes is `[UTType]` rather than `[String]` so callers pass the
/// type-safe `UTType.json` (or similar) directly — earlier code took a
/// `[String]` of UTI identifiers and converted via the failable
/// `UTType(_:)` init. When that init returned nil for any reason, the
/// resulting empty filter let the picker show every file as selectable
/// AND failed to highlight the genuine JSON ones — observed empirically
/// during the schema migration test where vkturnproxy-backup-*.json sat
/// un-highlighted in Files.app's Downloads view and had to be located by
/// search instead of by browsing.
struct DocumentPicker: UIViewControllerRepresentable {
    let contentTypes: [UTType]
    let onPicked: (URL) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPicked: onPicked)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: contentTypes
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPicked: (URL) -> Void
        init(onPicked: @escaping (URL) -> Void) {
            self.onPicked = onPicked
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            onPicked(url)
        }
    }
}

// MARK: - Stats View

struct StatsView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        VStack(spacing: 6) {
            HStack {
                StatBox(title: "↑ TX", value: formatBytes(tunnel.stats.txBytes), sub: formatRate(tunnel.txRate))
                StatBox(title: "↓ RX", value: formatBytes(tunnel.stats.rxBytes), sub: formatRate(tunnel.rxRate))
            }

            HStack {
                StatBox(title: "TURN RTT", value: String(format: "%.0f ms", tunnel.stats.turnRTTms), sub: nil)
                StatBox(title: "DTLS HS", value: String(format: "%.0f ms", tunnel.stats.dtlsHandshakeMs), sub: nil)
                StatBox(title: "Internet", value: tunnel.internetRTTms > 0 ? String(format: "%.0f ms", tunnel.internetRTTms) : "—", sub: nil)
            }

            HStack {
                StatBox(title: "Conns", value: "\(tunnel.stats.activeConns)/\(tunnel.stats.totalConns)", sub: nil)
                StatBox(title: "Reconnects", value: "\(tunnel.stats.reconnects)", sub: nil)
            }

            HStack {
                // Uptime updates live via TimelineView ticking once a second.
                // Falls back to "—" if the tunnel hasn't reached .connected
                // yet (briefly visible during the .connecting → .connected
                // transition since StatsView is gated on .connected).
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    StatBox(
                        title: "Uptime",
                        value: formatUptime(tunnel.connectedAt.map { context.date.timeIntervalSince($0) }),
                        sub: nil
                    )
                }
                StatBox(
                    // Three numbers: fresh / with-creds / total.
                    //   fresh: slots usable for new conn allocations.
                    //   with-creds: slots physically holding a cred,
                    //               including stale (past expiry buffer)
                    //               or pending ones — existing conns on
                    //               those slots are still alive.
                    //   total: configured pool capacity.
                    // fresh ≤ with-creds ≤ total. They diverge after
                    // ~7.5h+ of uptime when slot creds approach their
                    // VK-side 8-hour expiry.
                    title: "Pool",
                    value: "\(tunnel.stats.credPoolFilled)/\(tunnel.stats.credPoolWithCreds)/\(tunnel.stats.credPoolSize)",
                    sub: nil
                )
            }
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        let b = Double(bytes)
        if b >= 1_073_741_824 { return String(format: "%.1f GB", b / 1_073_741_824) }
        if b >= 1_048_576 { return String(format: "%.1f MB", b / 1_048_576) }
        if b >= 1024 { return String(format: "%.1f KB", b / 1024) }
        return "\(bytes) B"
    }

    private func formatRate(_ bytesPerSec: Double) -> String {
        if bytesPerSec >= 1_048_576 { return String(format: "%.1f MB/s", bytesPerSec / 1_048_576) }
        if bytesPerSec >= 1024 { return String(format: "%.1f KB/s", bytesPerSec / 1024) }
        if bytesPerSec > 0 { return String(format: "%.0f B/s", bytesPerSec) }
        return "0 B/s"
    }

    private func formatUptime(_ seconds: TimeInterval?) -> String {
        guard let s = seconds, s >= 0 else { return "—" }
        let total = Int(s)
        let h = total / 3600
        let m = (total % 3600) / 60
        let sec = total % 60
        if h > 0 {
            return String(format: "%d:%02d:%02d", h, m, sec)
        }
        return String(format: "%d:%02d", m, sec)
    }
}

struct StatBox: View {
    let title: String
    let value: String
    let sub: String?

    var body: some View {
        VStack(spacing: 2) {
            Text(title)
                .font(.caption2)
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.medium)
            if let sub = sub {
                Text(sub)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

// MARK: - Captcha WebView (captures token via JS interception)

struct CaptchaWebView: View {
    let url: URL
    let captchaSID: String
    let onSolved: (String) -> Void
    let onDismiss: () -> Void
    let onLimitDetected: () -> Void
    let onCaptchaReady: () -> Void
    let onLog: (String) -> Void
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Solve Captcha")
                    .font(.headline)
                Spacer()
                Button("Done") { onDismiss() }
                    .font(.headline)
            }
            .padding()

            ZStack {
                CaptchaWKWebView(
                    url: url,
                    onTokenCaptured: onSolved,
                    onLimitDetected: onLimitDetected,
                    onCaptchaReady: onCaptchaReady,
                    onLog: onLog
                )

                // Overlay shown ONLY while auto-refresh is hunting for a fresh
                // captcha after JS detected "Attempt limit reached". Goes away
                // as soon as the WebView reloads to a working captcha (JS
                // posts state:ready → tunnel.onCaptchaReady → captchaLimitReached=false).
                if tunnel.captchaLimitReached {
                    VStack(spacing: 16) {
                        ProgressView().scaleEffect(1.3)
                        Text("VK временно не отдаёт капчу")
                            .font(.headline)
                        Text("Ищем рабочую — попытка \(tunnel.captchaRefreshAttempt) из \(tunnel.maxCaptchaRefreshAttempts)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(32)
                    .background(Color(.systemBackground).opacity(0.97))
                    .cornerRadius(16)
                    .shadow(radius: 12)
                }
            }
        }
    }
}

struct CaptchaWKWebView: UIViewRepresentable {
    let url: URL
    let onTokenCaptured: (String) -> Void
    // Called when JS detector concludes the loaded page is in "Attempt limit
    // reached" state (no interactive element + error text). TunnelManager
    // uses this to start the auto-refresh timer.
    let onLimitDetected: () -> Void
    // Called when JS detector sees a normal interactive captcha. TunnelManager
    // uses this to stop any running auto-refresh timer.
    let onCaptchaReady: () -> Void
    // Routes log lines from the WKWebView coordinator (which lives in the
    // main-app process) into vpn.log — so raw JS bridge messages and
    // state-transition diagnostics land in the same log file as the
    // extension's output instead of only in os_log / Console.app.
    let onLog: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            onTokenCaptured: onTokenCaptured,
            onLimitDetected: onLimitDetected,
            onCaptchaReady: onCaptchaReady,
            onLog: onLog
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true

        // Use an ephemeral data store so every CaptchaWKWebView instance starts
        // with a clean cookie jar. VK's anti-abuse cookies otherwise persist
        // across WebView recreations and cause the captcha page to return a
        // pre-solved state ("green checkmark on open"), which leaves the user
        // stuck — JS hooks never fire because the solve flow never runs.
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()

        let contentController = WKUserContentController()
        contentController.add(context.coordinator, name: "captchaToken")

        // Approach based on https://github.com/cacggghp/vk-turn-proxy/pull/97:
        // Load the captcha page directly (top-level, no iframe needed).
        // Intercept fetch/XHR to captchaNotRobot.check — the response contains
        // success_token which is what VK needs for the retry.
        // No need for postMessage interception or iframe wrapper.
        let js = """
        (function() {
            var h = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.captchaToken;
            if (!h) return;

            // Hook fetch to intercept captchaNotRobot.check response
            var origFetch = window.fetch;
            window.fetch = function() {
                var url = arguments[0];
                if (typeof url === 'object' && url.url) url = url.url;
                var urlStr = String(url);
                var p = origFetch.apply(this, arguments);
                if (urlStr.indexOf('captchaNotRobot.check') !== -1) {
                    p.then(function(response) {
                        return response.clone().json();
                    }).then(function(data) {
                        h.postMessage('check:' + JSON.stringify(data).substring(0, 1000));
                        if (data.response && data.response.success_token) {
                            h.postMessage('token:' + data.response.success_token);
                        } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                            // VK explicitly said "rate limited". Trigger auto-refresh
                            // immediately — don't wait for the 2.5s DOM heuristic
                            // (which would miss the limit state that only appears
                            // AFTER the user clicks the checkbox and the page
                            // dynamically switches to the error screen).
                            h.postMessage('state:limit:api_error_limit');
                        }
                    }).catch(function(e) {
                        h.postMessage('check-err:' + e.message);
                    });
                }
                return p;
            };

            // Hook XMLHttpRequest as fallback
            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._url = url;
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                if (this._url && String(this._url).indexOf('captchaNotRobot.check') !== -1) {
                    xhr.addEventListener('load', function() {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            h.postMessage('xhr-check:' + JSON.stringify(data).substring(0, 1000));
                            if (data.response && data.response.success_token) {
                                h.postMessage('token:' + data.response.success_token);
                            } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                                // Same as fetch path: VK hard-rate-limited us,
                                // trigger auto-refresh without waiting for the
                                // DOM heuristic.
                                h.postMessage('state:limit:api_error_limit');
                            }
                        } catch(e) {}
                    });
                }
                return origSend.apply(this, arguments);
            };

            h.postMessage('init:hooks installed');

            // Page-state detector: 2.5s after first render, look at whether
            // VK showed us an interactive captcha or an "Attempt limit reached"
            // (or equivalent) error. Post state:limit / state:ready to Swift —
            // TunnelManager runs the auto-refresh timer only on state:limit.
            function checkCaptchaState(source) {
                try {
                    var text = (document.body && document.body.innerText) || '';
                    var hasLimitText = /limit.*reached|лимит.*исчерп|превышен|try\\s*again\\s*later|attempt\\s*limit/i.test(text);
                    var hasInteractive = !!document.querySelector(
                        '[role="checkbox"], input[type="checkbox"], .VkIdNotRobotButton, [data-test-id*="captcha"], .vkuiCheckbox'
                    );
                    var state;
                    if (hasLimitText) {
                        state = 'limit';
                    } else if (hasInteractive) {
                        state = 'ready';
                    } else {
                        state = 'unknown';
                    }
                    h.postMessage('state:' + state + ':' + source);
                } catch (e) {
                    h.postMessage('state-err:' + e.message);
                }
            }

            // Run initial detection once DOM is ready + a 2.5s settle.
            function scheduleInitialDetection() {
                setTimeout(function() { checkCaptchaState('initial'); }, 2500);
            }
            if (document.readyState === 'complete' || document.readyState === 'interactive') {
                scheduleInitialDetection();
            } else {
                window.addEventListener('DOMContentLoaded', scheduleInitialDetection);
            }

            // Diagnostic heartbeat: every 1s while page hasn't reached
            // 'complete', post readyState + content sizes. Diagnoses the
            // "white captcha" symptom from issue #5 — when WKWebView
            // navigates but no didFinish/didFail fires, we need to know
            // whether DOM is stuck in 'loading', sitting empty in
            // 'interactive', or what. Stops itself on 'complete' or after
            // 60s (whichever first) so it can't spam the log indefinitely.
            (function() {
                var startTime = Date.now();
                var heartbeatId = setInterval(function() {
                    var elapsed = Date.now() - startTime;
                    var ready = document.readyState || 'null';
                    var bodyLen = (document.body && document.body.innerHTML.length) || 0;
                    var titleLen = (document.title || '').length;
                    var url = (location && location.href || '').substring(0, 80);
                    h.postMessage('heartbeat:elapsed=' + elapsed + 'ms readyState=' + ready
                        + ' body=' + bodyLen + ' title=' + titleLen + ' url=' + url);
                    if (ready === 'complete' || elapsed > 60000) {
                        clearInterval(heartbeatId);
                    }
                }, 1000);
            })();

            // Catch JS errors and unhandled promise rejections so we can
            // see if the page is failing on its own scripts (e.g. a
            // sub-resource referenced by VK's captcha JS that the
            // network blocks).
            window.addEventListener('error', function(e) {
                var src = (e.filename || '?');
                if (src.length > 80) src = src.substring(0, 80) + '…';
                h.postMessage('js-error:' + (e.message || 'unknown')
                    + ' at ' + src + ':' + (e.lineno || '?'));
            });
            window.addEventListener('unhandledrejection', function(e) {
                var reason = e.reason ? String(e.reason).substring(0, 200) : 'unknown';
                h.postMessage('js-rejection:' + reason);
            });
        })();
        """
        let userScript = WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        contentController.addUserScript(userScript)
        config.userContentController = contentController

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView
        webView.customUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"

        // Load captcha URL directly — no iframe needed
        context.coordinator.lastLoadedURL = url.absoluteString
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // When VK rejects a success_token and the Go side fetches a fresh
        // captcha URL, SwiftUI rebinds this view with a new `url` but keeps
        // the same underlying WKWebView alive. Without an explicit reload the
        // user sees the stale page (still showing the green checkmark from
        // the previous solve) and has no way to interact — the only escape
        // is pressing Done. Detect the URL change and reload so the new
        // captcha appears automatically.
        let newURLStr = url.absoluteString
        if context.coordinator.lastLoadedURL != newURLStr {
            context.coordinator.log("URL changed, reloading WebView (\(String(newURLStr.prefix(80))))")
            context.coordinator.lastLoadedURL = newURLStr
            context.coordinator.resetForNewCaptcha()
            uiView.load(URLRequest(url: url))
        }
    }

    class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        let onTokenCaptured: (String) -> Void
        let onLimitDetected: () -> Void
        let onCaptchaReady: () -> Void
        let onLog: (String) -> Void
        private var solved = false
        weak var webView: WKWebView?
        // Tracks which URL we last handed to `webView.load(...)`. Used by
        // updateUIView to detect real URL changes vs. SwiftUI re-renders with
        // the same state — avoids redundant reloads.
        var lastLoadedURL: String?

        init(
            onTokenCaptured: @escaping (String) -> Void,
            onLimitDetected: @escaping () -> Void,
            onCaptchaReady: @escaping () -> Void,
            onLog: @escaping (String) -> Void
        ) {
            self.onTokenCaptured = onTokenCaptured
            self.onLimitDetected = onLimitDetected
            self.onCaptchaReady = onCaptchaReady
            self.onLog = onLog
        }

        func log(_ msg: String) {
            // os_log / NSLog visible in Console.app when device is connected
            // to a Mac (useful for live debugging). onLog tunnels the same
            // message through TunnelManager → extension → vpn.log so
            // post-mortem analysis from a vpn.log dump is possible too.
            os_log("%{public}s", log: captchaLog, type: .default, msg)
            NSLog("[Captcha] %@", msg)
            onLog(msg)
        }

        // Called by updateUIView when the captcha URL changes mid-flight
        // (VK rejected a success_token and Go fetched a fresh captcha).
        // Resets the one-shot `solved` guard so the next success_token from
        // the new page is forwarded to the tunnel — otherwise the guard would
        // silently swallow every token after the first.
        func resetForNewCaptcha() {
            solved = false
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let body = message.body as? String else { return }
            log("JS: \(String(body.prefix(400)))")

            if body.hasPrefix("token:") {
                let token = String(body.dropFirst(6))
                log("SUCCESS_TOKEN (\(token.count) chars)")
                captureToken(token)
                return
            }

            // State detector posts `state:<kind>:<source>` — e.g.
            // "state:limit:initial" or "state:ready:initial". We react to
            // `limit` and `ready` kinds; `unknown` is logged for diagnostics
            // but no action taken (auto-refresh doesn't start on unknown to
            // avoid refresh loops on unrecognised layouts).
            if body.hasPrefix("state:") {
                let parts = body.split(separator: ":", maxSplits: 2).map(String.init)
                let kind = parts.count >= 2 ? parts[1] : ""
                switch kind {
                case "limit":
                    log("state=limit — delegating to auto-refresh handler")
                    DispatchQueue.main.async { self.onLimitDetected() }
                case "ready":
                    log("state=ready — delegating to stop-auto-refresh handler")
                    DispatchQueue.main.async { self.onCaptchaReady() }
                case "unknown":
                    log("state=unknown — no action (no interactive element and no known limit text)")
                default:
                    log("state=<unrecognised kind \(kind)>")
                }
                return
            }
        }

        private func captureToken(_ token: String) {
            guard !solved else { return }
            solved = true
            log("TOKEN CAPTURED (\(token.count) chars), sending to tunnel")
            DispatchQueue.main.async {
                self.onTokenCaptured(token)
            }
        }

        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            if let url = navigationAction.request.url {
                log("Nav: \(String(url.absoluteString.prefix(200)))")
            }
            decisionHandler(.allow)
        }

        // Diagnostic: confirms the request was actually sent to the server
        // (between Nav (decision) and didStartProvisional (sent on the wire)
        // there's a window where iOS could drop the request without firing
        // any other event). Added 2026-05-07 for issue #5 "white captcha"
        // diagnosis — vpn.from.github.1.log on build 48 had Nav fire then
        // 7.4s of silence with no Loaded / didFail. Need to know which
        // network-layer stage hangs.
        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            log("StartProvisional: request sent on wire")
        }

        // Diagnostic: HTTP redirect mid-navigation. Logged so we can see if
        // VK is sending us through some redirect chain that hangs.
        func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
            log("Redirect: \(String((webView.url?.absoluteString ?? "nil").prefix(200)))")
        }

        // Diagnostic: response headers received, body about to start. If
        // didCommit fires but didFinish doesn't, the body load is hanging
        // (server stops sending / TLS issue / sub-resource block). If
        // didCommit doesn't fire at all, the request is stuck before
        // headers arrived (TCP / TLS handshake / server unresponsive).
        func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
            log("Commit: response headers received")
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            let nsErr = error as NSError
            log("FAIL: \(error.localizedDescription) (domain=\(nsErr.domain) code=\(nsErr.code))")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            let nsErr = error as NSError
            log("FAIL provisional: \(error.localizedDescription) (domain=\(nsErr.domain) code=\(nsErr.code))")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            log("Loaded: \(String((webView.url?.absoluteString ?? "nil").prefix(150)))")
        }
    }
}

// MARK: - Logs View

struct LogsView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var logText = ""
    @State private var autoScroll = true
    @State private var showShareSheet = false
    @State private var usingOSLogFallback = false
    // Cached fallback content + last-fetch timestamp + in-flight guard.
    // Without these the fallback path (OSLogReader.readOwnLogs +
    // sendProviderMessage) ran on EVERY 2-second timer tick whenever the
    // file was empty, blocking the main thread on the synchronous
    // OSLogStore query for hundreds of milliseconds-to-seconds depending
    // on ring-buffer size. Symptom: tapping "Clear" emptied the file,
    // then the UI lagged badly because every tick re-ran the heavy
    // fallback query. With caching: query runs at most once per
    // fallbackTTL seconds, off the main thread.
    @State private var fallbackText: String = ""
    @State private var fallbackFetchedAt: Date = .distantPast
    @State private var fallbackInFlight = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()
    private let fallbackTTL: TimeInterval = 4.0

    /// Maximum characters to display — keeps UI responsive.
    /// The full file is still available via Share.
    private let maxDisplayChars = 100_000

    var body: some View {
        VStack(spacing: 0) {
            LogTextView(text: logText, autoScroll: autoScroll)

            Divider()

            HStack {
                Toggle("Auto-scroll", isOn: $autoScroll)
                    .font(.caption)
                    .toggleStyle(.switch)
                    .fixedSize()

                Spacer()

                Button(action: {
                    SharedLogger.shared.clearLogs()
                    // Wipe the fallback cache too — otherwise after
                    // clearing the on-disk log the next loadLogs() tick
                    // would still show the stale cached fallback content
                    // until the TTL elapses, which looks like Clear
                    // didn't work.
                    fallbackText = ""
                    fallbackFetchedAt = .distantPast
                    logText = ""
                }) {
                    Label("Clear", systemImage: "trash")
                        .font(.caption)
                }

                Button(action: { showShareSheet = true }) {
                    Label("Share", systemImage: "square.and.arrow.up")
                        .font(.caption)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .navigationTitle("Logs")
        .onAppear { loadLogs() }
        .onReceive(timer) { _ in loadLogs() }
        .sheet(isPresented: $showShareSheet) {
            // Export the COMBINED log (archive .1 + current) as a single
            // temp file so the user gets the full history, not just the
            // tail since the last rotation. If SharedLogger is empty
            // (App Group unavailable), Share the os_log fallback text
            // by writing it to a temp file first so the user can still
            // attach a log file to a bug report.
            if let url = exportShareableLogURL(),
               FileManager.default.fileExists(atPath: url.path) {
                ShareSheet(activityItems: [url])
            }
        }
    }

    private func loadLogs() {
        let fileText = SharedLogger.shared.readLogs()
        if !fileText.isEmpty {
            usingOSLogFallback = false
            logText = truncated(fileText)
            return
        }
        // SharedLogger empty — App Group container is probably unreachable
        // (this happens on improperly-resigned sideloaded IPAs and has
        // also been reported on TestFlight builds, github issues #7/#8).
        // Fall back to per-process os_log: main app reads its own ring
        // buffer, then we ask the extension to read its own and ferry the
        // text back via providerMessage. Surface a banner so the user
        // understands the source and limitations.
        //
        // Both the OSLogStore query and the providerMessage round-trip
        // can take hundreds of milliseconds each — running them on every
        // 2-second timer tick on the main thread caused noticeable UI
        // lag (especially after Clear, which keeps the file empty and
        // forces this path). So: cache the result for `fallbackTTL`
        // seconds, refresh in a background task, and only one fetch may
        // be in flight at a time.
        usingOSLogFallback = true

        // Show last-cached content immediately if we have any; otherwise
        // a minimal placeholder so the user knows fetching is in progress.
        if !fallbackText.isEmpty {
            logText = truncated(fallbackText)
        } else if logText.isEmpty {
            logText = "Loading os_log fallback…"
        }

        let cacheStale = Date().timeIntervalSince(fallbackFetchedAt) > fallbackTTL
        guard !fallbackInFlight && cacheStale else { return }
        fallbackInFlight = true

        Task.detached(priority: .userInitiated) {
            // OSLogReader.readOwnLogs is the heavy synchronous call —
            // running it on a detached task moves it off the main thread.
            // Subsequent awaits (providerMessage, MainActor.run) come
            // back to MainActor naturally because tunnel is @MainActor.
            let mainAppLogs = OSLogReader.readOwnLogs(maxAge: 1800)
            let extensionLogs = await tunnel.fetchExtensionOSLogs() ?? ""

            var combined = mainAppLogs + extensionLogs
            if combined.isEmpty {
                combined = "No logs available.\n\n" +
                    "The on-disk log file is empty (App Group container " +
                    "unreachable) and the os_log fallback also returned " +
                    "nothing — likely the extension was just (re)started " +
                    "and hasn't logged anything since. Try again in a few " +
                    "seconds, or reconnect the tunnel."
            } else {
                combined = "⚠️ App Group container unavailable — showing " +
                    "os_log fallback (recent ~30 min only, " +
                    "may be incomplete and out of order).\n\n" +
                    combined
            }

            await MainActor.run {
                fallbackText = combined
                fallbackFetchedAt = Date()
                fallbackInFlight = false
                if usingOSLogFallback {
                    logText = truncated(combined)
                }
            }
        }
    }

    private func truncated(_ text: String) -> String {
        guard text.count > maxDisplayChars else { return text }
        let startIndex = text.index(text.endIndex, offsetBy: -maxDisplayChars)
        return "… (truncated)\n" + String(text[startIndex...])
    }

    /// Decide what URL to hand to the Share sheet. Default path: the
    /// file-backed export (archive + current). Fallback path: write
    /// the current `logText` (which is the os_log fallback view) to
    /// a temp file so the user can still attach a log to a bug report
    /// even when the App Group file is empty.
    private func exportShareableLogURL() -> URL? {
        if let url = SharedLogger.shared.exportSnapshotURL(),
           let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? Int, size > 0 {
            return url
        }
        // SharedLogger empty — write the on-screen fallback text to a
        // temp file so Share has something to attach.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("vpn-export-oslog.log")
        try? logText.write(to: tmp, atomically: true, encoding: .utf8)
        return FileManager.default.fileExists(atPath: tmp.path) ? tmp : nil
    }
}

/// UITextView wrapper — handles large text without SwiftUI layout explosion.
struct LogTextView: UIViewRepresentable {
    let text: String
    let autoScroll: Bool

    func makeUIView(context: Context) -> UITextView {
        let tv = UITextView()
        tv.isEditable = false
        tv.isSelectable = true
        tv.font = UIFont.monospacedSystemFont(ofSize: 10, weight: .regular)
        tv.textColor = .label
        tv.backgroundColor = .systemBackground
        tv.textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
        return tv
    }

    func updateUIView(_ tv: UITextView, context: Context) {
        // Only update if text actually changed to avoid unnecessary work
        if tv.text != text {
            tv.text = text
            if autoScroll && !text.isEmpty {
                let bottom = NSRange(location: text.count - 1, length: 1)
                tv.scrollRangeToVisible(bottom)
            }
        }
    }
}

/// UIActivityViewController wrapper for sharing the log file.
struct ShareSheet: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    ContentView()
}
