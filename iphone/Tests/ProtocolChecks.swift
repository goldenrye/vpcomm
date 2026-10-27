import Foundation

@main
struct ProtocolChecks {
    static func rejects(_ body: () throws -> Void) throws {
        do { try body() } catch { return }
        throw NSError(domain: "Expected rejection", code: 1)
    }

    static func main() throws {
        let invite = try CallInvitation.generate()
        let parsed = try CallInvitation(invite.text)
        precondition(parsed.text == invite.text)
        for value in ["", "vp1.a.b", invite.text + "."] {
            try rejects { _ = try CallInvitation(value) }
        }
        let a = KeyExchange(invite), b = KeyExchange(invite)
        var alice = try a.authenticate(b.hello())
        var bob = try b.authenticate(a.hello())
        precondition(alice.code == bob.code)
        try rejects { _ = try a.authenticate(a.hello()) }
        try rejects { _ = try a.authenticate(KeyExchange(CallInvitation.generate()).hello()) }
        let packet = try alice.seal(VoiceProtocol.confirmation)
        var tampered = packet
        tampered[tampered.count - 1] ^= 1
        try rejects { _ = try bob.open(tampered) }
        let confirmation = try bob.open(packet)
        precondition(confirmation == VoiceProtocol.confirmation)
        try rejects { _ = try bob.open(packet) }
        try rejects { _ = try alice.open(packet) }
        let first = try alice.seal(Data([1]) + VoiceProtocol.silence)
        let second = try alice.seal(Data([1]) + VoiceProtocol.silence)
        try rejects { _ = try bob.open(second) }
        _ = try bob.open(first)
        _ = try bob.open(second)
        try rejects { _ = try bob.open(Data(repeating: 0, count: 666)) }
        try rejects { _ = try alice.seal(Data(repeating: 0, count: 642)) }
        for url in ["ws://example.com/relay", "wss://a:b@example.com/relay",
                    "wss://example.com/relay?", "wss://example.com/relay#",
                    "wss://example.com/%72elay", "wss://example.com:0/relay"] {
            try rejects { _ = try RelaySettings(address: url, token: String(repeating: "a", count: 40)) }
        }
        try rejects { _ = try RelaySettings.certificate(Data("invalid".utf8)) }
        print("PASS: invitation, authentication, tampering, replay, ordering, limits, endpoint policy")
    }
}
