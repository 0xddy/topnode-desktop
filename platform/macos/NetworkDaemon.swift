import Foundation
import Darwin
import XPC

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
    static func current() -> NetworkSession? {
        lock.lock(); defer { lock.unlock() }
        return active
    }
}

private final class NetworkSession {
    weak var connection: xpc_connection_t?
    private let lock = NSLock()
    private var process: Process?
    private var invalidated = false
    func receive(_ request: xpc_object_t) {
        guard xpc_get_type(request) == XPC_TYPE_DICTIONARY,
              xpc_dictionary_get_uint64(request, "version") == 1,
              let connection, xpc_connection_get_euid(connection) != 0,
              let operation = xpc_dictionary_get_string(request, "operation"),
              let reply = xpc_dictionary_create_reply(request) else {
            stop {}
            if let connection { xpc_connection_cancel(connection) }
            return
        }
        let respond: (Bool) -> Void = { ok in
            xpc_dictionary_set_uint64(reply, "version", 1)
            xpc_dictionary_set_bool(reply, "ok", ok)
            xpc_connection_send_message(connection, reply)
        }
        switch String(cString: operation) {
        case "ping": respond(geteuid() == 0)
        case "start":
            var length = 0
            guard let bytes = xpc_dictionary_get_data(request, "configuration", &length),
                  length <= maximumConfiguration else { respond(false); return }
            start(configuration: Data(bytes: bytes, count: length)) { error in respond(error == nil) }
        case "stop": stop { respond(true) }
        default: respond(false)
        }
    }
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
        if let connection { xpc_connection_cancel(connection) }
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

@main struct Daemon {
    static func main() {
        guard geteuid() == 0, (try? verifiedCore()) != nil else { exit(1) }
        let listener = xpc_connection_create_mach_service(networkServiceName, .main, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(listener) { peer in
            guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
            guard (try? authenticate(peer, identifier: "cc.topnode.network.bridge")) != nil else {
                xpc_connection_cancel(peer)
                return
            }
            let session = NetworkSession()
            session.connection = peer
            xpc_connection_set_event_handler(peer) { request in
                if xpc_get_type(request) == XPC_TYPE_ERROR {
                    session.stop {}
                    xpc_connection_cancel(peer)
                    xpc_connection_set_event_handler(peer) { _ in }
                } else {
                    session.receive(request)
                }
            }
            xpc_connection_resume(peer)
        }
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler { if let session = Owner.current() { session.stop { exit(0) } } else { exit(0) } }
        termination.resume()
        xpc_connection_resume(listener)
        withExtendedLifetime((listener, termination)) { RunLoop.main.run() }
    }
}
