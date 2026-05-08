// SPDX-License-Identifier: MIT
//
// VKProfileCache — persists captured-from-real-browser VK fingerprint
// to App Group container so the Go-side auto-PoW solver can substitute
// the user's actual browser_fp + device for the canned generated values.
//
// Background: VK's anti-bot scoring on captchaNotRobot.check labels our
// generated browser_fp as BOT in 94% of attempts (vpn.wifi.0.log analysis
// 2026-05-08: 62/66 fresh-fetch attempts). When the user solves a captcha
// in CaptchaWKWebView, the page's own JS computes a real browser_fp +
// device descriptor and POSTs them to captchaNotRobot.componentDone. Our
// JS hook in ContentView.swift intercepts that request body, extracts the
// values, and calls VKProfileCache.save() with them. Subsequent
// solveCaptchaPoW calls in either main app or extension load
// vk_profile.json via Go-side proxy.loadSavedVKProfile() and substitute
// these captured values, dramatically improving auto-solve success rate.
//
// Captured values are valid as long as VK doesn't rotate the underlying
// fingerprint format — empirically that's weeks-to-months. No expiry
// enforced here; if the captured profile stops working, user solves a
// new captcha manually and the freshest values overwrite. Adapted from
// cacggghp PR #162 commit b9642c6 (Moroka8) — implemented for our
// WKWebView+App Group architecture rather than their HTTP-proxy one.

import Foundation

struct VKProfileEntry: Codable {
    let device: String       // form-encoded device JSON, as VK's JS sent it
    let browser_fp: String   // VK's encoded fingerprint string
    let user_agent: String   // navigator.userAgent at capture time
    let captured_at: TimeInterval
}

enum VKProfileCache {
    private static let appGroupID = "group.com.vkturnproxy.app"
    private static let filename = "vk_profile.json"

    /// File URL inside the shared App Group container. Returns nil if
    /// the App Group entitlement isn't granted (shouldn't happen in
    /// production builds; defensive against misconfigured dev profiles).
    private static var fileURL: URL? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            return nil
        }
        return container.appendingPathComponent(filename)
    }

    /// Persist a captured profile. Atomic write — readers (Go side in the
    /// extension or in the main app's wgProbeVKCreds path) never observe
    /// a half-written file. Overwrites unconditionally; the freshest
    /// captured values are always preferred over older ones.
    static func save(device: String, browserFp: String, userAgent: String) {
        guard !device.isEmpty, !browserFp.isEmpty else {
            SharedLogger.shared.log("[AppDebug] VKProfileCache.save: empty fields, skipping (device=\(device.count)c, browser_fp=\(browserFp.count)c)")
            return
        }
        guard let url = fileURL else {
            SharedLogger.shared.log("[AppDebug] VKProfileCache.save: no App Group container — entitlement missing?")
            return
        }
        let entry = VKProfileEntry(
            device: device,
            browser_fp: browserFp,
            user_agent: userAgent,
            captured_at: Date().timeIntervalSince1970
        )
        do {
            let data = try JSONEncoder().encode(entry)
            try data.write(to: url, options: .atomic)
            SharedLogger.shared.log("[AppDebug] VKProfileCache.save: ok (device=\(device.count)c, browser_fp=\(browserFp.count)c, ua=\(userAgent.count)c) → \(url.path)")
        } catch {
            SharedLogger.shared.log("[AppDebug] VKProfileCache.save: write failed: \(error)")
        }
    }

    /// Read the captured profile. Used only for diagnostics from Swift —
    /// the actual consumer is Go-side proxy.loadSavedVKProfile() which
    /// reads the same file directly. Returns nil if missing or invalid.
    static func load() -> VKProfileEntry? {
        guard let url = fileURL else { return nil }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(VKProfileEntry.self, from: data)
    }

    /// Returns true if a captured profile exists and is non-empty. Used
    /// by UI / debug surfaces that want to indicate "profile captured"
    /// state without loading the full content.
    static var hasProfile: Bool {
        guard let entry = load() else { return false }
        return !entry.device.isEmpty && !entry.browser_fp.isEmpty
    }
}
