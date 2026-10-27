import AVFoundation
import Combine
import Foundation
import UIKit

@MainActor
final class CallStore: ObservableObject {
    @Published var address = ""
    @Published var token = ""
    @Published var invitation = ""
    @Published var importCertificate = false
    @Published private(set) var status = "Create an invitation or paste one from your partner."
    @Published private(set) var busy = false
    @Published private(set) var connected = false
    @Published private(set) var muted = false
    @Published private(set) var verification = ""
    @Published private(set) var rootFingerprint: String?
    private var root: Data?
    private var relay: Relay?
    private var audio: AudioIO?
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var observers: [NSObjectProtocol] = []
    private var clipboardValue: String?

    func createInvitation() {
        guard !busy else { return }
        do {
            invitation = try CallInvitation.generate().text
            status = "Invitation ready. Share privately before entering your relay token."
        } catch { status = "Could not generate a secure invitation." }
    }

    func copyInvitation() {
        guard !busy, !invitation.isEmpty else { return }
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: invitation]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)]
        )
        clipboardValue = invitation
        status = "Copied locally for two minutes. Share only through a trusted channel."
    }

    func loadCertificate(_ url: URL) {
        guard !busy else { return }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize
            guard let size, size <= 32768 else { throw VoiceError.certificate }
            let der = try RelaySettings.certificate(Data(contentsOf: url))
            root = der
            rootFingerprint = RelaySettings.fingerprint(der)
            status = "Private CA loaded. Verify its fingerprint with your administrator."
        } catch { status = "Choose a single PEM or DER public root certificate." }
    }

    func clearCertificate() {
        guard !busy else { return }
        root = nil
        rootFingerprint = nil
        status = "Using standard iOS certificate trust."
    }

    func start() {
        guard !busy else { return }
        let invitation: CallInvitation
        let relay: Relay
        do {
            invitation = try CallInvitation(self.invitation)
            relay = Relay(try RelaySettings(address: address, token: token, root: root))
        } catch {
            status = (error as? VoiceError)?.errorDescription ?? "Check call details."
            return
        }
        let id = UUID()
        generation = id
        self.relay = relay
        busy = true
        status = "Checking microphone permission..."
        task = Task {
            do {
                guard await AudioIO.permission() else { throw VoiceError.microphone }
                try Task.checkCancellation()
                guard generation == id else { return }
                status = "Connecting securely..."
                let code = try await relay.connect(invitation) {
                    self.status = "Waiting for your partner (up to two minutes)..."
                }
                try Task.checkCancellation()
                guard generation == id else { return }
                let audio = AudioIO()
                self.audio = audio
                try audio.start()
                connected = true
                verification = code
                status = "Authenticated call. Compare verification codes independently."
                UIApplication.shared.isIdleTimerDisabled = true
                observeAudio(id)
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { @MainActor in
                        var lastCapture = ContinuousClock.now
                        while !Task.isCancelled {
                            if let frame = try audio.nextFrame() {
                                lastCapture = .now
                                try await relay.transmit(frame)
                            } else {
                                guard lastCapture.duration(to: .now) < .seconds(5) else {
                                    throw VoiceError.audio
                                }
                                try await Task.sleep(nanoseconds: 5_000_000)
                            }
                        }
                        throw CancellationError()
                    }
                    group.addTask { @MainActor in
                        while !Task.isCancelled {
                            try audio.play(await relay.listen())
                        }
                        throw CancellationError()
                    }
                    defer { group.cancelAll() }
                    try await group.next()
                }
                finish(id, message: "Call ended. Use a new invitation.")
            } catch {
                let message = (error as? VoiceError)?.errorDescription
                    ?? "Connection ended. Check relay, token, certificate, and network."
                finish(id, message: message)
            }
        }
    }

    func mute() {
        guard connected else { return }
        muted.toggle()
        audio?.mute(muted)
    }

    func hangUp(_ message: String = "Call ended. Use a new invitation.") {
        guard busy else { return }
        task?.cancel()
        finish(generation, message: message)
    }

    func background() {
        hangUp("Call ended because VPComm left the foreground.")
        token = ""
        // Unused invitations remain in memory so switching apps to share them works.
    }

    private func finish(_ id: UUID, message: String) {
        guard generation == id else { return }
        generation = UUID()
        relay?.stop()
        relay = nil
        audio?.stop()
        audio = nil
        observers.forEach(NotificationCenter.default.removeObserver)
        observers.removeAll()
        UIApplication.shared.isIdleTimerDisabled = false
        task = nil
        busy = false
        connected = false
        muted = false
        verification = ""
        invitation = ""
        status = message
        if let clipboardValue, UIPasteboard.general.string == clipboardValue {
            UIPasteboard.general.items = []
        }
        clipboardValue = nil
    }

    private func observeAudio(_ id: UUID) {
        for event in [AVAudioSession.interruptionNotification,
                      AVAudioSession.routeChangeNotification,
                      AVAudioSession.mediaServicesWereResetNotification] {
            observers.append(NotificationCenter.default.addObserver(
                forName: event, object: nil, queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    guard self?.generation == id else { return }
                    self?.hangUp("Audio route changed or was interrupted. Start a new call.")
                }
            })
        }
    }
}
