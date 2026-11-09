// Per-service SystemConfiguration snapshots. Never print proxy credentials.
import Foundation
import SystemConfiguration
import Security

enum ProxyError: Error { case invalidInput, authorization, unavailable, applyFailed }
let maximumInput = 64 * 1024

func input() throws -> [String: String] {
    let data = FileHandle.standardInput.readData(ofLength: maximumInput + 1)
    guard data.count <= maximumInput,
          let result = try JSONSerialization.jsonObject(with: data) as? [String: String] else { throw ProxyError.invalidInput }
    return result
}

func emit(_ value: [String: String]) throws {
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
}

func encode(_ settings: [String: Any]) throws -> String {
    try JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys]).base64EncodedString()
}

func decode(_ value: String) throws -> [String: Any] {
    guard let data = Data(base64Encoded: value),
          let settings = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ProxyError.invalidInput }
    return settings
}

func preferences(writable: Bool) throws -> (SCPreferences, AuthorizationRef?) {
    if !writable {
        guard let prefs = SCPreferencesCreate(nil, "TOPNODE proxy snapshot" as CFString, nil) else { throw ProxyError.unavailable }
        return (prefs, nil)
    }
    var authorization: AuthorizationRef?
    guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
          let auth = authorization else { throw ProxyError.authorization }
    let status = "system.preferences.network".withCString { name -> OSStatus in
        var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { item in
            var rights = AuthorizationRights(count: 1, items: item)
            return AuthorizationCopyRights(auth, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
        }
    }
    guard status == errAuthorizationSuccess else { AuthorizationFree(auth, []); throw ProxyError.authorization }
    guard
          let prefs = SCPreferencesCreateWithAuthorization(nil, "TOPNODE proxy lease" as CFString, nil, auth) else { AuthorizationFree(auth, []); throw ProxyError.authorization }
    return (prefs, auth)
}

func services(_ prefs: SCPreferences) throws -> [SCNetworkService] {
    guard let values = SCNetworkServiceCopyAll(prefs) as? [SCNetworkService] else { throw ProxyError.unavailable }
    return values
}

func capture() throws {
    let (prefs, _) = try preferences(writable: false)
    var result: [String: String] = [:]
    for service in try services(prefs) {
        guard let id = SCNetworkServiceGetServiceID(service),
              let proxy = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else { continue }
        let settings = SCNetworkProtocolGetConfiguration(proxy) as? [String: Any] ?? [:]
        result[id as String] = try encode(settings)
    }
    try emit(result)
}

func local(port: Int) throws {
    guard (1...65535).contains(port) else { throw ProxyError.invalidInput }
    var snapshot = try input()
    for (id, original) in snapshot {
        var settings = try decode(original)
        for kind in ["HTTP", "HTTPS", "SOCKS"] {
            settings[kind + "Enable"] = 1
            settings[kind + "Proxy"] = "127.0.0.1"
            settings[kind + "Port"] = port
        }
        settings["ProxyAutoConfigEnable"] = 0
        settings["ProxyAutoDiscoveryEnable"] = 0
        snapshot[id] = try encode(settings)
    }
    try emit(snapshot)
}

func install() throws {
    let snapshot = try input()
    // Decode every service before acquiring authorization or changing anything.
    let desired = try snapshot.mapValues(decode)
    let (prefs, authorization) = try preferences(writable: true)
    defer { if let authorization { AuthorizationFree(authorization, []) } }
    guard SCPreferencesLock(prefs, true) else { throw ProxyError.authorization }
    defer { SCPreferencesUnlock(prefs) }
    let current = try services(prefs)
    for service in current {
        guard let id = SCNetworkServiceGetServiceID(service) as String?, let settings = desired[id],
              let proxy = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else { continue }
        guard SCNetworkProtocolSetConfiguration(proxy, settings as CFDictionary) else { throw ProxyError.applyFailed }
    }
    guard SCPreferencesCommitChanges(prefs), SCPreferencesApplyChanges(prefs) else { throw ProxyError.authorization }
}

do {
    let arguments = CommandLine.arguments
    guard arguments.count >= 2 else { throw ProxyError.invalidInput }
    switch arguments[1] {
    case "capture" where arguments.count == 2: try capture()
    case "local" where arguments.count == 3:
        guard let port = Int(arguments[2]) else { throw ProxyError.invalidInput }
        try local(port: port)
    case "install" where arguments.count == 2: try install()
    default: throw ProxyError.invalidInput
    }
} catch {
    FileHandle.standardError.write(Data("macOS proxy operation failed (authorization, network service or input).\n".utf8))
    exit(1)
}
