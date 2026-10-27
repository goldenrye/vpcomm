import CryptoKit
import Foundation
import Security

enum VoiceError: Error, LocalizedError {
    case invitation, peer, packet, order, endpoint, token, certificate
    case timeout, ended, microphone, audio

    var errorDescription: String? {
        switch self {
        case .invitation: return "Enter a valid vp1 invitation."
        case .peer: return "Peer authentication failed. Check the invitation."
        case .packet: return "Invalid or tampered audio. The call was ended."
        case .order: return "Replayed or out-of-order audio. The call was ended."
        case .endpoint: return "Use wss://your-server/relay with no credentials, query, or fragment."
        case .token: return "Enter a relay token with at least 32 printable ASCII characters."
        case .certificate: return "The TLS certificate is invalid or not trusted."
        case .timeout: return "Connection timed out. Start a new call."
        case .ended: return "The call ended or the relay disconnected."
        case .microphone: return "Allow microphone access in iPhone Settings to make a call."
        case .audio: return "Audio was interrupted or could not start. Check your audio route."
        }
    }
}

enum VoiceProtocol {
    static let context = Data("vpcomm/v1/x25519-hkdf-sha256-aes256gcm/pcm16le-16000-320".utf8)
    static let confirmation = Data([0]) + Data("vpcomm/v1/confirmed".utf8)
    static let frameSize = 640
    static let silence = Data(repeating: 0, count: frameSize)

    static func base64(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String, size: Int) throws -> Data {
        guard text.utf8.count == (size * 8 + 5) / 6 else { throw VoiceError.invitation }
        let padded = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - text.utf8.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded), bytes.count == size,
              base64(bytes) == text else { throw VoiceError.invitation }
        return bytes
    }
}

struct CallInvitation {
    let room: Data
    let secret: Data
    var roomID: String { VoiceProtocol.base64(room) }
    var text: String { "vp1.\(roomID).\(VoiceProtocol.base64(secret))" }

    init(_ text: String) throws {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "vp1" else { throw VoiceError.invitation }
        room = try VoiceProtocol.decode(String(parts[1]), size: 16)
        secret = try VoiceProtocol.decode(String(parts[2]), size: 32)
    }

    static func generate() throws -> CallInvitation {
        var bytes = [UInt8](repeating: 0, count: 48)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VoiceError.invitation
        }
        return try CallInvitation("vp1.\(VoiceProtocol.base64(Data(bytes.prefix(16))))."
                                  + VoiceProtocol.base64(Data(bytes.suffix(32))))
    }
}

struct KeyExchange {
    let invitation: CallInvitation
    private let key: Curve25519.KeyAgreement.PrivateKey

    init(_ invitation: CallInvitation) {
        self.invitation = invitation
        key = Curve25519.KeyAgreement.PrivateKey()
    }

    private struct Hello: Codable {
        let v: Int
        let `public`: String
        let proof: String
    }

    func hello() throws -> Data {
        let publicKey = key.publicKey.rawRepresentation
        let proof = HMAC<SHA256>.authenticationCode(
            for: VoiceProtocol.context + invitation.room + publicKey,
            using: SymmetricKey(data: invitation.secret)
        )
        return try JSONEncoder().encode(Hello(
            v: 1, public: VoiceProtocol.base64(publicKey),
            proof: VoiceProtocol.base64(Data(proof))
        ))
    }

    func authenticate(_ message: Data) throws -> CallKeys {
        guard message.count <= 512,
              let hello = try? JSONDecoder().decode(Hello.self, from: message),
              hello.v == 1,
              let peer = try? VoiceProtocol.decode(hello.public, size: 32),
              let proof = try? VoiceProtocol.decode(hello.proof, size: 32) else {
            throw VoiceError.peer
        }
        let own = key.publicKey.rawRepresentation
        guard own != peer, HMAC<SHA256>.isValidAuthenticationCode(
            proof, authenticating: VoiceProtocol.context + invitation.room + peer,
            using: SymmetricKey(data: invitation.secret)
        ) else { throw VoiceError.peer }
        let first = own.lexicographicallyPrecedes(peer)
        let transcript = VoiceProtocol.context + invitation.room + (first ? own + peer : peer + own)
        let material: Data
        do {
            let shared = try key.sharedSecretFromKeyAgreement(
                with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer)
            )
            material = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: invitation.secret, sharedInfo: transcript,
                outputByteCount: 64
            ).withUnsafeBytes { Data($0) }
        } catch { throw VoiceError.peer }
        let fingerprint = Array(SHA256.hash(
            data: Data("verification".utf8) + transcript + material
        ).prefix(12).map { String(format: "%02x", $0) }.joined())
        let code = stride(from: 0, to: 24, by: 4)
            .map { String(fingerprint[$0..<$0 + 4]) }.joined(separator: "-")
        let low = Data(material.prefix(32)), high = Data(material.suffix(32))
        return CallKeys(send: first ? low : high, receive: first ? high : low,
                        binding: Data(SHA256.hash(data: transcript)), code: code)
    }
}

/// Mutated only on the transport's serial actor.
struct CallKeys {
    private let sendingKey: SymmetricKey
    private let receivingKey: SymmetricKey
    private let binding: Data
    private var sent: UInt64 = 0
    private var received: UInt64 = 0
    let code: String

    init(send: Data, receive: Data, binding: Data, code: String) {
        sendingKey = SymmetricKey(data: send)
        receivingKey = SymmetricKey(data: receive)
        self.binding = binding
        self.code = code
    }

    mutating func seal(_ plaintext: Data) throws -> Data {
        guard sent < (1 << 32), plaintext.count <= 641 else { throw VoiceError.packet }
        var number = sent.bigEndian
        let counter = withUnsafeBytes(of: &number) { Data($0) }
        let box = try AES.GCM.seal(
            plaintext, using: sendingKey,
            nonce: AES.GCM.Nonce(data: Data(repeating: 0, count: 4) + counter),
            authenticating: binding + counter
        )
        sent += 1
        return counter + box.ciphertext + box.tag
    }

    mutating func open(_ packet: Data) throws -> Data {
        guard (24...665).contains(packet.count) else { throw VoiceError.packet }
        let counter = Data(packet.prefix(8))
        let sequence = counter.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard sequence == received, received < (1 << 32) else { throw VoiceError.order }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: Data(repeating: 0, count: 4) + counter),
                ciphertext: packet.dropFirst(8).dropLast(16), tag: packet.suffix(16)
            )
            let plaintext = try AES.GCM.open(box, using: receivingKey,
                                             authenticating: binding + counter)
            received += 1
            return plaintext
        } catch { throw VoiceError.packet }
    }
}
