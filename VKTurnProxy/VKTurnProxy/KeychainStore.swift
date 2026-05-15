import Foundation
import Security

enum KeychainSecret: String, CaseIterable {
    case privateKey
    case presharedKey
    case vkLink
    case wrapKeyHex
}

enum KeychainStoreError: Error, LocalizedError {
    case unexpectedData
    case unhandledStatus(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unexpectedData:
            return "Keychain returned unexpected data."
        case .unhandledStatus(let status):
            return "Keychain operation failed with status \(status)."
        }
    }
}

enum KeychainStore {
    private static let service = "com.vkturnproxy.app.secrets"
    private static let legacyMigrationMarker = "keychainSecretsMigrated.v1"

    static func string(for secret: KeychainSecret) throws -> String {
        var query = baseQuery(for: secret)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = kCFBooleanTrue

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return ""
        }
        guard status == errSecSuccess else {
            throw KeychainStoreError.unhandledStatus(status)
        }
        guard let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            throw KeychainStoreError.unexpectedData
        }
        return value
    }

    static func set(_ value: String, for secret: KeychainSecret) throws {
        if value.isEmpty {
            try delete(secret)
            return
        }

        let data = Data(value.utf8)
        var query = baseQuery(for: secret)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainStoreError.unhandledStatus(updateStatus)
        }

        for (key, value) in attributes {
            query[key] = value
        }
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainStoreError.unhandledStatus(addStatus)
        }
    }

    static func delete(_ secret: KeychainSecret) throws {
        let status = SecItemDelete(baseQuery(for: secret) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.unhandledStatus(status)
        }
    }

    static func deleteAllSecrets() throws {
        for secret in KeychainSecret.allCases {
            try delete(secret)
        }
        clearLegacyUserDefaultsSecrets()
    }

    static func migrateLegacySecretsFromUserDefaults() {
        let defaults = UserDefaults.standard
        guard defaults.bool(forKey: legacyMigrationMarker) == false else {
            return
        }

        var migrated = 0
        var failed = 0
        for secret in KeychainSecret.allCases {
            guard let value = defaults.string(forKey: secret.rawValue),
                  !value.isEmpty else {
                defaults.removeObject(forKey: secret.rawValue)
                continue
            }
            do {
                try set(value, for: secret)
                defaults.removeObject(forKey: secret.rawValue)
                migrated += 1
            } catch {
                failed += 1
                SharedLogger.shared.log("[AppDebug] Keychain migration: failed for \(secret.rawValue): \(error.localizedDescription)")
            }
        }

        if failed == 0 {
            defaults.set(true, forKey: legacyMigrationMarker)
        }
        SharedLogger.shared.log("[AppDebug] Keychain migration: moved \(migrated) legacy secret value(s)")
    }

    static func clearLegacyUserDefaultsSecrets() {
        let defaults = UserDefaults.standard
        for secret in KeychainSecret.allCases {
            defaults.removeObject(forKey: secret.rawValue)
        }
    }

    private static func baseQuery(for secret: KeychainSecret) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: secret.rawValue
        ]
    }
}
