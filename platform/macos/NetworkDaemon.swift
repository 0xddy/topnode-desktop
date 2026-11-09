import Foundation
import Darwin

private enum Owner {
    static let lock = NSLock()
    static weak var active: NetworkSession?
    static func take(_ session: NetworkSession) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active == nil else { return false }
        active = session; return true
    }
    static func release(_ session: NetworkSession) {
        lock.lock(); defer { lock.unlock() }
        if active === session { active = nil }
    }
}

private final class NetworkSession: NSObject, NetworkServiceProtocol {
    weak var connection: NSXPCConnection?
    private let lock = NSLock()
    private var process: Process?
    private var invalidated = false
    func ping(reply: @escaping (Bool) -> Void) { reply(geteuid() == 0) }
    func start(configuration: Data, reply: @escaping (String?) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard !invalidated, process == nil, Owner.take(self) else { reply("TUN session already owned"); return }
        do {
            try validateConfiguration(configuration)
            let core = try verifiedCore()
            let child = Process()
            child.executableURL = core
            child.arguments = ["run", "-c", "stdin"]
            child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
            child.currentDirectoryURL = URL(fileURLWithPath: fixedAppRoot)
            let input = Pipe()
            child.standardInput = input
            child.standardOutput = FileHandle.nullDevice
            child.standardError = FileHandle.nullDevice
            child.terminationHandler = { [weak self] _ in self?.finished() }
            try child.run()
            process = child
            try input.fileHandleForWriting.write(contentsOf: configuration)
            try input.fileHandleForWriting.close()
            reply(nil)
        } catch {
            if let process { kill(process.processIdentifier, SIGKILL) } else { Owner.release(self) }
            reply("TUN configuration or installed core verification failed")
        }
    }
    private func finished() {
        lock.lock(); process = nil; lock.unlock()
        Owner.release(self)
        (connection?.remoteObjectProxy as? NetworkStatusProtocol)?.stopped()
    }
    func stop(reply: @escaping () -> Void) {
        lock.lock(); invalidated = true; let child = process; lock.unlock()
        DispatchQueue.global().async {
            if let child, child.isRunning {
                child.terminate()
                let deadline = Date().addingTimeInterval(2)
                while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
                child.waitUntilExit()
            }
            reply()
        }
    }
}

private final class Listener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0,
              let requirement = try? requirement(identifier: "cc.topnode.network.bridge") else { return false }
        connection.setCodeSigningRequirement(requirement)
        let session = NetworkSession()
        session.connection = connection
        connection.exportedInterface = NSXPCInterface(with: NetworkServiceProtocol.self)
        connection.exportedObject = session
        connection.remoteObjectInterface = NSXPCInterface(with: NetworkStatusProtocol.self)
        connection.invalidationHandler = { session.stop {} }
        connection.interruptionHandler = { session.stop {} }
        connection.resume()
        return true
    }
}

@main struct Daemon {
    static func main() {
        guard geteuid() == 0, (try? verifiedCore()) != nil else { exit(1) }
        let delegate = Listener()
        let listener = NSXPCListener(machServiceName: networkServiceName)
        listener.delegate = delegate
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler { if let session = Owner.active { session.stop { exit(0) } } else { exit(0) } }
        termination.resume()
        listener.resume()
        withExtendedLifetime((delegate, termination)) { RunLoop.main.run() }
    }
}
