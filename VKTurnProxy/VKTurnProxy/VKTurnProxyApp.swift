import SwiftUI

/// Tiny inbox that forwards an incoming `vkturnproxy://import?data=…`
/// URL from the App's `.onOpenURL` (which fires reliably on cold and
/// warm launches at the WindowGroup level) into SettingsView, where
/// the parse + confirm + apply flow lives. SettingsView observes
/// `pendingURL` via @StateObject and consumes it on .onAppear AND
/// .onChange, so the URL is acted on whether SettingsView was already
/// mounted at the moment of delivery or only mounted later when the
/// user navigates to it.
@MainActor
final class ConnectionLinkInbox: ObservableObject {
    static let shared = ConnectionLinkInbox()
    @Published var pendingURL: URL?
    private init() {}
}

@main
struct VKTurnProxyApp: App {
    init() {
        SharedLogger.shared.log("[App] VKTurnProxy launched")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                // Capture vkturnproxy:// URLs at the WindowGroup level
                // so cold-launch via URL-tap works regardless of which
                // page SettingsView is currently on. Other URL schemes
                // (none registered today) would also land here; we
                // filter by scheme inside the inbox so non-matching
                // ones are ignored safely.
                .onOpenURL { url in
                    if url.scheme?.lowercased() == "vkturnproxy" {
                        ConnectionLinkInbox.shared.pendingURL = url
                    }
                }
        }
    }
}
