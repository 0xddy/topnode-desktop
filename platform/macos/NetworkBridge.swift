import Foundation
import ServiceManagement
import Darwin
import XPC

private func probeService() -> Bool {
    let queue = DispatchQueue(label: "cc.topnode.network.probe")
    let connection = xpc_connection_create_mach_service(networkServiceName, queue, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
    guard (try? authenticate(connection, identifier: "cc.topnode.network.daemon")) != nil else { return false }
    let completed = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var trusted = false
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_resume(connection)
    xpc_connection_send_message_with_reply(connection, message("ping"), queue) { reply in
        lock.lock()
        trusted = succeeded(reply) && xpc_connection_get_euid(connection) == 0
        lock.unlock()
        completed.signal()
    }
    let received = completed.wait(timeout: .now() + 5) == .success
    xpc_connection_cancel(connection)
    lock.lock(); defer { lock.unlock() }
    return received && trusted
}

@main struct Bridge {
    static func main() {
        guard CommandLine.arguments.count == 2 else { exit(1) }
        let operation = CommandLine.arguments[1]
        if operation == "install-legacy" || operation == "remove-legacy" {
            do { try LegacyService.manage(install: operation == "install-legacy"); exit(0) }
            catch { exit(2) }
        }
        if operation != "connect" { manageService(operation) }
        let configuration = FileHandle.standardInput.readData(ofLength: maximumConfiguration + 1)
        guard (try? validateConfiguration(configuration)) != nil else { exit(1) }
        let connection = xpc_connection_create_mach_service(networkServiceName, .main, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        guard (try? authenticate(connection, identifier: "cc.topnode.network.daemon")) != nil else { exit(1) }
        xpc_connection_set_event_handler(connection) { _ in exit(1) }
        xpc_connection_resume(connection)
        // Only a signed root peer's response authorizes sending the opaque configuration.
        xpc_connection_send_message_with_reply(connection, message("ping"), .main) { reply in
            guard succeeded(reply), xpc_connection_get_euid(connection) == 0 else { exit(1) }
            let request = message("start")
            configuration.withUnsafeBytes { bytes in
                xpc_dictionary_set_data(request, "configuration", bytes.baseAddress, bytes.count)
            }
            xpc_connection_send_message_with_reply(connection, request, .main) { reply in
                guard succeeded(reply) else {
                    FileHandle.standardError.write(Data("TUN helper rejected the configuration or installed core.\n".utf8))
                    exit(1)
                }
            }
        }
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler {
            xpc_connection_send_message_with_reply(connection, message("stop"), .main) { _ in exit(0) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { exit(1) }
        }
        termination.resume()
        withExtendedLifetime((connection, termination)) { RunLoop.main.run() }
    }

    private static func manageService(_ operation: String) -> Never {
        // An OS upgrade may leave the previously authorized legacy job installed.
        if #available(macOS 13.0, *), !LegacyService.isInstalled {
            let service = SMAppService.daemon(plistName: "cc.topnode.network.plist")
            switch operation {
            case "status": exit(service.status == .enabled ? 0 : 2)
            case "register":
                do { try service.register() } catch { exit(2) }
                if service.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems(); exit(2) }
                exit(service.status == .enabled ? 0 : 2)
            case "unregister": do { try service.unregister(); exit(0) } catch { exit(1) }
            default: exit(1)
            }
        }
        switch operation {
        case "status": exit(probeService() ? 0 : 2)
        case "register":
            if probeService() { exit(0) }
            guard LegacyService.authorize(install: true) else { exit(2) }
            exit(probeService() ? 0 : 2)
        case "unregister": exit(LegacyService.authorize(install: false) ? 0 : 2)
        default: exit(1)
        }
    }
}
