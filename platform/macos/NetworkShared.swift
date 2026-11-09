import Foundation
import Security
import CryptoKit

let networkServiceName = "cc.topnode.network"
let fixedAppRoot = "/Applications/TOPNODE Desktop.app/Contents/MacOS"
let maximumConfiguration = 8 * 1024 * 1024

@objc protocol NetworkServiceProtocol {
    func ping(reply: @escaping (Bool) -> Void)
    func start(configuration: Data, reply: @escaping (String?) -> Void)
    func stop(reply: @escaping () -> Void)
}
@objc protocol NetworkStatusProtocol { func stopped() }
enum NetworkFailure: Error { case identity, artifact, configuration }

func ownTeam() throws -> String {
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dictionary = info as? [String: Any],
          let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
          team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { throw NetworkFailure.identity }
    return team
}
func requirement(identifier: String) throws -> String {
    "anchor apple generic and certificate leaf[subject.OU] = \"\(try ownTeam())\" and identifier \"\(identifier)\""
}

func protectedFile(_ path: String) throws {
    var url = URL(fileURLWithPath: path)
    while true {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        // /Applications is normally root:admin 0775. Require the installed
        // bundle and all files below it to be root-owned and non-writable,
        // and independently verify the core's designated signing requirement.
        let forbiddenWrites = url.path == "/Applications" ? 0o002 : 0o022
        guard (attributes[.ownerAccountID] as? NSNumber)?.intValue == 0,
              let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & forbiddenWrites == 0,
              attributes[.type] as? FileAttributeType != .typeSymbolicLink else { throw NetworkFailure.artifact }
        if url.path == "/" { break }
        url.deleteLastPathComponent()
    }
}
func digest(_ path: String) throws -> String {
    try protectedFile(path)
    let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? input.close() }
    var digest = SHA256()
    while let data = try input.read(upToCount: 65536), !data.isEmpty { digest.update(data: data) }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}
func verifiedCore() throws -> URL {
    let directory = fixedAppRoot + "/runtime/core"
    let manifest = directory + "/source.json"
    try protectedFile(manifest)
    let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: manifest))
    defer { try? input.close() }
    let data = input.readData(ofLength: 65537)
    guard data.count <= 65536,
          let metadata = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          metadata["commit"] as? String == CoreLock.commit,
          metadata["version"] as? String == CoreLock.version,
          metadata["binarySha256"] as? String == (try digest(directory + "/sing-box-acp")),
          let libraries = metadata["libraries"] as? [[String: String]] else { throw NetworkFailure.artifact }
    for library in libraries {
        guard let name = library["file"], !name.isEmpty, !name.hasPrefix("."), !name.contains("/"), !name.contains("\\"), !name.contains(":"),
              library["sha256"] == (try digest(directory + "/" + name)) else { throw NetworkFailure.artifact }
    }
    let core = URL(fileURLWithPath: directory + "/sing-box-acp")
    var code: SecStaticCode?
    var rule: SecRequirement?
    let signing = try requirement(identifier: "cc.topnode.core")
    guard SecStaticCodeCreateWithPath(core as CFURL, [], &code) == errSecSuccess, let code,
          SecRequirementCreateWithString(signing as CFString, [], &rule) == errSecSuccess, let rule,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), rule) == errSecSuccess else { throw NetworkFailure.artifact }
    return core
}

func validateConfiguration(_ data: Data) throws {
    guard data.count <= maximumConfiguration,
          let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          root.keys.allSatisfy({ ["log", "dns", "inbounds", "outbounds", "route", "experimental"].contains($0) }),
          let inbounds = root["inbounds"] as? [[String: Any]],
          inbounds.filter({ $0["type"] as? String == "tun" }).count == 1 else { throw NetworkFailure.configuration }
    func check(_ value: Any) throws {
        if let object = value as? [String: Any] {
            for (key, value) in object {
                guard !key.hasSuffix("_path"), !(key.hasSuffix("_file") && key != "cache_file"),
                      !["path", "external_ui", "external_ui_download_url", "command", "script", "working_directory"].contains(key),
                      key != "output" || value as? String == "" else { throw NetworkFailure.configuration }
                try check(value)
            }
        } else if let array = value as? [Any] { for value in array { try check(value) } }
    }
    try check(root)
    for inbound in inbounds {
        let kind = inbound["type"] as? String
        if kind == "tun" {
            if let name = inbound["interface_name"] as? String,
               name.range(of: "^utun[0-9]{0,4}$", options: .regularExpression) == nil { throw NetworkFailure.configuration }
        } else if !["mixed", "http", "socks"].contains(kind ?? "") || !["127.0.0.1", "::1"].contains(inbound["listen"] as? String ?? "") { throw NetworkFailure.configuration }
    }
    for outbound in root["outbounds"] as? [[String: Any]] ?? [] {
        guard ["direct", "block", "selector", "urltest", "naive", "vless", "anytls", "hysteria2", "juicity", "mieru"].contains(outbound["type"] as? String ?? "") else { throw NetworkFailure.configuration }
    }
    if let experimental = root["experimental"] as? [String: Any] {
        if let cache = experimental["cache_file"] as? [String: Any], cache["enabled"] as? Bool == true { throw NetworkFailure.configuration }
        if let clash = experimental["clash_api"] as? [String: Any], let address = clash["external_controller"] as? String,
           address.range(of: "^(127\\.0\\.0\\.1|\\[::1\\]):[0-9]{1,5}$", options: .regularExpression) == nil { throw NetworkFailure.configuration }
    }
}
