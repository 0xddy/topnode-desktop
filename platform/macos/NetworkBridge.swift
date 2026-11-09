import Foundation
import ServiceManagement
import Darwin

private final class Status: NSObject, NetworkStatusProtocol {
    func stopped() { exit(1) }
}

@main struct Bridge {
    static func main() {
        let service = SMAppService.daemon(plistName: "cc.topnode.network.plist")
        guard CommandLine.arguments.count == 2 else { exit(1) }
        switch CommandLine.arguments[1] {
        case "status": exit(service.status == .enabled ? 0 : 2)
        case "register":
            do { try service.register() } catch { exit(2) }
            if service.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems(); exit(2) }
            exit(service.status == .enabled ? 0 : 2)
        case "unregister": do { try service.unregister(); exit(0) } catch { exit(1) }
        case "connect": break
        default: exit(1)
        }
        let configuration = FileHandle.standardInput.readData(ofLength: maximumConfiguration + 1)
        guard (try? validateConfiguration(configuration)) != nil,
              let signing = try? requirement(identifier: "cc.topnode.network.daemon") else { exit(1) }
        let connection = NSXPCConnection(machServiceName: networkServiceName, options: .privileged)
        connection.setCodeSigningRequirement(signing)
        connection.remoteObjectInterface = NSXPCInterface(with: NetworkServiceProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: NetworkStatusProtocol.self)
        connection.exportedObject = Status()
        connection.invalidationHandler = { exit(1) }
        connection.interruptionHandler = { exit(1) }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in exit(1) }) as? NetworkServiceProtocol else { exit(1) }
        // Authenticate a response before sending credentials to the peer.
        proxy.ping { trusted in
            guard trusted, connection.effectiveUserIdentifier == 0 else { exit(1) }
            proxy.start(configuration: configuration) { error in
                if error != nil { FileHandle.standardError.write(Data("TUN helper rejected the configuration or installed core.\n".utf8)); exit(1) }
            }
        }
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler { proxy.stop { exit(0) } }
        termination.resume()
        withExtendedLifetime((connection, termination)) { RunLoop.main.run() }
    }
}
