import Foundation
import XCTest
@testable import VKTurnProxy

final class BackupManagerValidationTests: XCTestCase {
    private var temporaryFiles: [URL] = []

    override func tearDownWithError() throws {
        for url in temporaryFiles {
            try? FileManager.default.removeItem(at: url)
        }
        temporaryFiles.removeAll()
        try super.tearDownWithError()
    }

    func testConnectionLinkAcceptsValidBase64URLPayload() throws {
        let raw = try encodedConnectionLink()

        let link = try BackupManager.parseConnectionLinkString(raw)

        XCTAssertEqual(link.version, BackupManager.supportedConfigVersion)
        XCTAssertEqual(link.type, "connection")
        XCTAssertEqual(link.settings.allowedIPs, "192.168.102.0/24")
        XCTAssertEqual(link.settings.dnsServers, "1.1.1.1")
        XCTAssertEqual(link.settings.numConnections, 4)
        XCTAssertFalse(link.settings.useWrap)
    }

    func testConnectionLinkAcceptsURLForm() throws {
        let raw = try encodedConnectionLink()
        let urlString = "vkturnproxy://import?data=\(raw)"

        let link = try BackupManager.parseConnectionLinkString(urlString)

        XCTAssertEqual(link.type, "connection")
        XCTAssertEqual(link.settings.peerAddress, "relay.example.invalid:3478")
    }

    func testConnectionLinkRejectsOversizedInput() {
        let raw = String(repeating: "A", count: 65 * 1024)

        XCTAssertThrowsError(try BackupManager.parseConnectionLinkString(raw)) { error in
            XCTAssertTrue(error.localizedDescription.contains("too large"))
        }
    }

    func testConnectionLinkRejectsUnsupportedRootField() throws {
        let raw = try encodedConnectionLink(rootOverrides: [
            "turn_pool": ["creds": []]
        ])

        XCTAssertThrowsError(try BackupManager.parseConnectionLinkString(raw)) { error in
            XCTAssertTrue(error.localizedDescription.contains("unsupported connection link field"))
        }
    }

    func testConnectionLinkRejectsAllowedIPsWithoutCIDR() throws {
        let raw = try encodedConnectionLink(settingsOverrides: [
            "allowedIPs": "0.0.0.0"
        ])

        XCTAssertThrowsError(try BackupManager.parseConnectionLinkString(raw)) { error in
            XCTAssertTrue(error.localizedDescription.contains("CIDR"))
        }
    }

    func testSettingsBackupImportDoesNotPopulateSecrets() throws {
        let url = try writeTemporaryJSON(settingsBackup())

        let config = try BackupManager.importFromFileURL(url)

        XCTAssertTrue(BackupManager.isSettingsOnly(config))
        XCTAssertEqual(config.settings.privateKey, "")
        XCTAssertEqual(config.settings.presharedKey, "")
        XCTAssertEqual(config.settings.vkLink, "")
        XCTAssertEqual(config.settings.peerAddress, "")
        XCTAssertNil(config.turnPool)
        XCTAssertNil(config.vkProfile)
    }

    func testSettingsBackupRejectsSecretFields() throws {
        var backup = settingsBackup()
        var settings = try XCTUnwrap(backup["settings"] as? [String: Any])
        settings["privateKey"] = dummyWireGuardKey
        backup["settings"] = settings
        let url = try writeTemporaryJSON(backup)

        XCTAssertThrowsError(try BackupManager.importFromFileURL(url)) { error in
            XCTAssertTrue(error.localizedDescription.contains("unsupported settings backup settings field"))
        }
    }

    private var dummyWireGuardKey: String {
        Data(repeating: 0, count: 32).base64EncodedString()
    }

    private func settingsBackup() -> [String: Any] {
        [
            "version": BackupManager.supportedConfigVersion,
            "type": "settings",
            "exported_at": 1_700_000_000,
            "settings": [
                "tunnelAddress": "192.168.102.3/24",
                "dnsServers": "1.1.1.1",
                "allowedIPs": "192.168.102.0/24",
                "useDTLS": true,
                "numConnections": 4,
                "credPoolCooldownSeconds": 150,
                "useWrap": false
            ]
        ]
    }

    private func encodedConnectionLink(
        settingsOverrides: [String: Any] = [:],
        rootOverrides: [String: Any] = [:]
    ) throws -> String {
        var settings: [String: Any] = [
            "privateKey": dummyWireGuardKey,
            "peerPublicKey": dummyWireGuardKey,
            "presharedKey": "",
            "tunnelAddress": "192.168.102.3/24",
            "allowedIPs": "192.168.102.0/24",
            "vkLink": "https://example.invalid/call/test",
            "peerAddress": "relay.example.invalid:3478",
            "useDTLS": true,
            "useWrap": false,
            "wrapKeyHex": "",
            "dnsServers": "1.1.1.1",
            "numConnections": 4
        ]
        for (key, value) in settingsOverrides {
            settings[key] = value
        }

        var root: [String: Any] = [
            "version": BackupManager.supportedConfigVersion,
            "type": "connection",
            "settings": settings
        ]
        for (key, value) in rootOverrides {
            root[key] = value
        }

        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func writeTemporaryJSON(_ object: [String: Any]) throws -> URL {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("json")
        try data.write(to: url, options: .atomic)
        temporaryFiles.append(url)
        return url
    }
}
