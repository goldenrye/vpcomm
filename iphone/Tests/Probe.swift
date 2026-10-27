import Foundation

/// Compiled with Core/*.swift on macOS to exercise the same transport without a microphone.
@main
struct Probe {
    struct Input: Decodable {
        let address: String
        let token: String
        let invitation: String
        let root: String?
        let cancel: Bool?
    }

    @MainActor static func main() async {
        do {
            let input = try JSONDecoder().decode(
                Input.self, from: FileHandle.standardInput.readDataToEndOfFile()
            )
            let root = try input.root.map {
                try RelaySettings.certificate(Data(contentsOf: URL(fileURLWithPath: $0)))
            }
            let relay = Relay(try RelaySettings(
                address: input.address, token: input.token, root: root, testLoopback: true
            ))
            defer { relay.stop() }
            let cancellation = Task { @MainActor in
                if input.cancel == true {
                    try await Task.sleep(nanoseconds: 100_000_000)
                    relay.stop()
                }
            }
            defer { cancellation.cancel() }
            let code = try await relay.connect(CallInvitation(input.invitation), waiting: {})
            for _ in 0..<10 {
                try await relay.transmit(Data((0..<320).flatMap { _ in [UInt8(0x12), 0x34] }))
                let frame = try await relay.listen()
                guard frame == Data((0..<320).flatMap { _ in [UInt8(0x56), 0x78] }) else {
                    throw VoiceError.packet
                }
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            print("PASS \(code)")
        } catch {
            print("FAIL \(String(describing: type(of: error)))")
            exit(1)
        }
    }
}
