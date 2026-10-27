"""20 ms, 16 kHz mono PCM audio with bounded real-time device queues."""

import queue
import threading

from .crypto import FRAME_BYTES

SAMPLE_RATE = 16000
BLOCK_SIZE = 320
SILENCE = b"\0" * FRAME_BYTES


def put_latest(buffer: queue.Queue, frame: bytes):
    try:
        buffer.put_nowait(frame)
    except queue.Full:
        try:
            buffer.get_nowait()
        except queue.Empty:
            pass
        try:
            buffer.put_nowait(frame)
        except queue.Full:
            pass


class AudioDevice:
    def __init__(self, input_device=None, output_device=None):
        self.input_device = input_device
        self.output_device = output_device
        self.muted = threading.Event()
        self.incoming: queue.Queue[bytes] = queue.Queue(maxsize=5)
        self.outgoing: queue.Queue[bytes] = queue.Queue(maxsize=5)
        self.stream = None
        self.device_warnings = 0

    def start(self):
        import sounddevice as sd

        self.stream = sd.RawStream(
            samplerate=SAMPLE_RATE,
            blocksize=BLOCK_SIZE,
            device=(self.input_device, self.output_device),
            channels=1,
            dtype="int16",
            latency="low",
            callback=self._callback,
        )
        try:
            self.stream.start()
        except BaseException:
            self.close()
            raise

    def _callback(self, indata, outdata, frames, time_info, status):
        if status:
            self.device_warnings += 1
        if frames != BLOCK_SIZE:
            outdata[:] = b"\0" * len(outdata)
            return
        put_latest(self.outgoing, SILENCE if self.muted.is_set() else bytes(indata))
        try:
            outdata[:] = self.incoming.get_nowait()
        except queue.Empty:
            outdata[:] = SILENCE

    def capture(self) -> bytes | None:
        try:
            frame = self.outgoing.get_nowait()
            return SILENCE if self.muted.is_set() else frame
        except queue.Empty:
            return None

    def play(self, frame: bytes):
        put_latest(self.incoming, frame)

    def close(self):
        if self.stream is not None:
            try:
                self.stream.stop()
            finally:
                self.stream.close()
                self.stream = None
