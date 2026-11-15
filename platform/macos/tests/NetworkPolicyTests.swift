import Foundation
import XPC

@main struct NetworkPolicyTests {
    static func main() throws {
        let valid = Data(#"{"inbounds":[{"type":"tun","interface_name":"utun7"}],"outbounds":[{"type":"naive","server":"localhost"}]}"#.utf8)
        try validateConfiguration(valid)
        let invalid = [
            Data(#"{"inbounds":[{"type":"tun"}],"outbounds":[{"type":"naive","tls":{"certificate_path":"/etc/passwd"}}]}"#.utf8),
            Data(#"{"inbounds":[{"type":"tun"},{"type":"mixed","listen":"0.0.0.0"}]}"#.utf8),
            Data(#"{"inbounds":[{"type":"tun","interface_name":"en0"}]}"#.utf8),
            Data(#"{"inbounds":[{"type":"tun"}],"experimental":{"cache_file":{"enabled":true}}}"#.utf8),
            Data(repeating: 0, count: maximumConfiguration + 1)
        ]
        for input in invalid {
            do {
                try validateConfiguration(input)
                fatalError("Privileged configuration boundary accepted invalid input")
            } catch NetworkFailure.configuration {}
        }
        let reply = message("ping")
        precondition(!succeeded(reply))
        xpc_dictionary_set_bool(reply, "ok", true)
        precondition(succeeded(reply))
        xpc_dictionary_set_uint64(reply, "version", 2)
        precondition(!succeeded(reply))
        precondition(!succeeded(xpc_string_create("ok")))
        // A test binary outside the fixed, root-owned installation cannot manage a job.
        for install in [false, true] {
            do {
                try LegacyService.manage(install: install)
                fatalError("Service management accepted an uninstalled caller")
            } catch NetworkFailure.identity {}
        }
        print("macOS network configuration, XPC reply and installation boundary tests passed")
    }
}
