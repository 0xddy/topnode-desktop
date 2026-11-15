import Foundation
import Darwin

// The administrator authorizes this fixed, root-owned executable. No caller paths,
// command strings, environment values or runtime configuration cross this boundary.
enum LegacyService {
    static let plist = "/Library/LaunchDaemons/cc.topnode.network.plist"
    static let bridge = fixedAppRoot + "/topnode-network-bridge"
    static var isInstalled: Bool { FileManager.default.fileExists(atPath: plist) }

    private static func isInstalledBridge() -> Bool {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var buffer = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else { return false }
        return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path == bridge
    }

    static func authorize(install: Bool) -> Bool {
        guard (try? protectedFile(bridge)) != nil,
              isInstalledBridge(),
              (try? ownTeam()) != nil else { return false }
        let operation = install ? "install-legacy" : "remove-legacy"
        let script = "do shell script \"'/Applications/TOPNODE Desktop.app/Contents/MacOS/topnode-network-bridge' \(operation)\" with administrator privileges"
        return (try? run("/usr/bin/osascript", ["-e", script])) == 0
    }

    static func manage(install: Bool) throws {
        guard geteuid() == 0, isInstalledBridge() else { throw NetworkFailure.identity }
        try protectedFile(bridge)
        _ = try ownTeam()
        if install {
            _ = try verifiedCore()
            let source = URL(fileURLWithPath: fixedAppRoot + "/../Library/LaunchDaemons/cc.topnode.network.plist").standardized
            try protectedFile(source.path)
            let data = try Data(contentsOf: source)
            guard var job = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  job["Label"] as? String == networkServiceName else { throw NetworkFailure.artifact }
            job.removeValue(forKey: "BundleProgram")
            job["ProgramArguments"] = [fixedAppRoot + "/topnode-network-daemon"]
            let payload = try PropertyListSerialization.data(fromPropertyList: job, format: .xml, options: 0)
            try protectedFile("/Library/LaunchDaemons")
            try payload.write(to: URL(fileURLWithPath: plist), options: .atomic)
            guard chown(plist, 0, 0) == 0, chmod(plist, 0o644) == 0 else { throw NetworkFailure.artifact }
            try unload()
            guard try run("/bin/launchctl", ["enable", "system/" + networkServiceName]) == 0,
                  try run("/bin/launchctl", ["bootstrap", "system", plist]) == 0 else { throw NetworkFailure.artifact }
        } else {
            try protectedFile("/Library/LaunchDaemons")
            try unload()
            if isInstalled { try FileManager.default.removeItem(atPath: plist) }
        }
    }

    private static func unload() throws {
        let service = "system/" + networkServiceName
        if try run("/bin/launchctl", ["bootout", service]) != 0 {
            // An absent job is already stopped; a still-loaded job is a failure.
            guard try run("/bin/launchctl", ["print", service]) != 0 else { throw NetworkFailure.artifact }
        }
    }

    private static func run(_ executable: String, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}
