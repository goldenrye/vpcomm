import queue

from vpcomm.audio import SILENCE, AudioDevice, put_latest


def test_bounded_queue_keeps_latest():
    buffer = queue.Queue(maxsize=2)
    for frame in (b"a", b"b", b"c"):
        put_latest(buffer, frame)
    assert buffer.qsize() == 2
    assert buffer.get_nowait() == b"b"
    assert buffer.get_nowait() == b"c"


def test_audio_callback_and_playback():
    audio = AudioDevice()
    captured = b"\x00\x10" * 320
    playback = b"\x00\x20" * 320
    audio.play(playback)
    outdata = bytearray(640)
    audio._callback(captured, outdata, 320, None, None)
    assert bytes(outdata) == playback
    assert audio.capture() == captured
    assert audio.capture() is None
    audio._callback(captured, outdata, 320, None, None)
    assert bytes(outdata) == SILENCE


def test_mute_covers_queued_and_new_microphone_audio():
    audio = AudioDevice()
    captured = b"\x00\x10" * 320
    outdata = bytearray(640)
    audio._callback(captured, outdata, 320, None, None)
    audio.muted.set()
    assert audio.capture() == SILENCE
    audio._callback(captured, outdata, 320, None, None)
    assert audio.capture() == SILENCE
    audio.muted.clear()
    audio._callback(captured, outdata, 320, None, None)
    assert audio.capture() == captured


def test_device_warning_and_bad_block_size():
    audio = AudioDevice()
    outdata = bytearray(320)
    audio._callback(b"x" * 320, outdata, 160, None, True)
    assert audio.device_warnings == 1
    assert bytes(outdata) == b"\0" * 320
    assert audio.capture() is None


def test_close_is_idempotent():
    audio = AudioDevice()
    audio.close()
    audio.close()
