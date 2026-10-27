import AVFoundation
import Foundation

/// Shared by the real-time input tap and the call actor; buffers are always bounded.
final class AudioBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var frames: [Data] = []
    private var playbackCount = 0
    private var muted = false
    private var stopped = false
    private var failed = false

    func push(_ frame: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        if frames.count == 5 { frames.removeFirst() }
        frames.append(muted ? VoiceProtocol.silence : frame)
    }

    func pop() throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard !failed, !stopped else { throw VoiceError.audio }
        guard !frames.isEmpty else { return nil }
        let frame = frames.removeFirst()
        return muted ? VoiceProtocol.silence : frame
    }

    func mute(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        muted = value
        frames.removeAll()
    }

    func reservePlayback() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, playbackCount < 5 else { return false }
        playbackCount += 1
        return true
    }

    func played() {
        lock.lock(); defer { lock.unlock() }
        playbackCount = max(0, playbackCount - 1)
    }

    func fail() { lock.lock(); failed = true; lock.unlock() }
    func stop() {
        lock.lock(); defer { lock.unlock() }
        stopped = true
        frames.removeAll()
    }
}

private final class PCMConverter {
    let converter: AVAudioConverter
    let format: AVAudioFormat
    let queue: AudioBuffer
    var partial = Data()

    init(from: AVAudioFormat, to: AVAudioFormat, queue: AudioBuffer) throws {
        guard from.sampleRate > 0, from.channelCount > 0,
              let converter = AVAudioConverter(from: from, to: to) else { throw VoiceError.audio }
        self.converter = converter
        format = to
        self.queue = queue
    }

    func consume(_ input: AVAudioPCMBuffer) {
        let capacity = AVAudioFrameCount(
            ceil(Double(input.frameLength) * format.sampleRate / input.format.sampleRate) + 64
        )
        guard let output = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: capacity) else {
            queue.fail(); return
        }
        var supplied = false
        var error: NSError?
        let status = converter.convert(to: output, error: &error) { _, state in
            if supplied { state.pointee = .noDataNow; return nil }
            supplied = true
            state.pointee = .haveData
            return input
        }
        guard error == nil, status != .error, let samples = output.floatChannelData?[0] else {
            queue.fail(); return
        }
        for i in 0..<Int(output.frameLength) {
            let sample = samples[i].isFinite ? min(1, max(-1, samples[i])) : 0
            let bits = UInt16(bitPattern: Int16(clamping: Int((sample * 32767).rounded())))
            partial.append(UInt8(truncatingIfNeeded: bits))
            partial.append(UInt8(truncatingIfNeeded: bits >> 8))
        }
        while partial.count >= VoiceProtocol.frameSize {
            queue.push(Data(partial.prefix(VoiceProtocol.frameSize)))
            partial = Data(partial.dropFirst(VoiceProtocol.frameSize))
        }
    }
}

@MainActor
final class AudioIO {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let queue = AudioBuffer()
    private let wireFormat = AVAudioFormat(standardFormatWithSampleRate: 16000, channels: 1)!
    private var tapped = false
    private var active = false

    static func permission() async -> Bool {
        await withCheckedContinuation { continuation in
            AVAudioSession.sharedInstance().requestRecordPermission {
                continuation.resume(returning: $0)
            }
        }
    }

    func start() throws {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playAndRecord, mode: .voiceChat,
                                    options: [.defaultToSpeaker, .allowBluetooth])
            try session.setPreferredSampleRate(48000)
            try session.setPreferredIOBufferDuration(0.02)
            try session.setActive(true)
            active = true
            let input = engine.inputNode
            try input.setVoiceProcessingEnabled(true)
            let hardware = input.outputFormat(forBus: 0)
            let converter = try PCMConverter(from: hardware, to: wireFormat, queue: queue)
            input.installTap(onBus: 0, bufferSize: 1024, format: hardware) { buffer, _ in
                converter.consume(buffer)
            }
            tapped = true
            engine.attach(player)
            engine.connect(player, to: engine.mainMixerNode, format: wireFormat)
            engine.prepare()
            try engine.start()
            player.play()
        } catch {
            stop()
            throw VoiceError.audio
        }
    }

    func nextFrame() throws -> Data? {
        guard engine.isRunning else { throw VoiceError.audio }
        return try queue.pop()
    }

    func play(_ frame: Data) throws {
        guard frame.count == 640, engine.isRunning else { throw VoiceError.audio }
        guard queue.reservePlayback() else { return }
        guard let buffer = AVAudioPCMBuffer(pcmFormat: wireFormat, frameCapacity: 320),
              let samples = buffer.floatChannelData?[0] else {
            queue.played()
            throw VoiceError.audio
        }
        buffer.frameLength = 320
        let bytes = [UInt8](frame)
        for i in 0..<320 {
            let bits = UInt16(bytes[i * 2]) | (UInt16(bytes[i * 2 + 1]) << 8)
            samples[i] = Float(Int16(bitPattern: bits)) / 32768
        }
        let queue = queue
        player.scheduleBuffer(buffer, completionCallbackType: .dataPlayedBack) { _ in queue.played() }
    }

    func mute(_ value: Bool) { queue.mute(value) }

    func stop() {
        queue.stop()
        if tapped {
            engine.inputNode.removeTap(onBus: 0)
            tapped = false
        }
        player.stop()
        engine.stop()
        if active {
            try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
            active = false
        }
    }
}
