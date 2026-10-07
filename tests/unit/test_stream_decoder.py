import random

from overlay.transport.frame import Frame, MsgType
from overlay.transport.tcp import StreamDecoder


def _make_frames(n: int, rng: random.Random) -> list[Frame]:
    frames: list[Frame] = []
    for _ in range(n):
        length = rng.randint(0, 2048)
        frames.append(
            Frame(
                type=MsgType.PING,
                request_id=Frame.new_request_id(),
                payload=bytes(rng.randrange(256) for _ in range(length)),
            )
        )
    return frames


def test_stream_decoder_random_chunking() -> None:
    rng = random.Random(1234)
    frames = _make_frames(100, rng)
    blob = b"".join(f.encode() for f in frames)

    decoder = StreamDecoder()
    got: list[Frame] = []
    i = 0
    while i < len(blob):
        step = rng.randint(1, 37)
        got.extend(decoder.feed(blob[i : i + step]))
        i += step

    assert got == frames
    assert decoder.buffered == 0


def test_stream_decoder_byte_by_byte() -> None:
    frames = _make_frames(10, random.Random(7))
    blob = b"".join(f.encode() for f in frames)

    decoder = StreamDecoder()
    got: list[Frame] = []
    for b in blob:
        got.extend(decoder.feed(bytes([b])))

    assert got == frames
    assert decoder.buffered == 0


def test_stream_decoder_multiple_frames_in_one_chunk() -> None:
    frames = _make_frames(5, random.Random(42))
    blob = b"".join(f.encode() for f in frames)

    decoder = StreamDecoder()
    got = decoder.feed(blob)

    assert got == frames
    assert decoder.buffered == 0


def test_stream_decoder_partial_header_then_payload() -> None:
    frame = Frame(
        type=MsgType.PING,
        request_id=Frame.new_request_id(),
        payload=b"abcdef",
    )
    raw = frame.encode()

    decoder = StreamDecoder()
    assert decoder.feed(raw[:5]) == []
    assert decoder.feed(raw[5:23]) == []
    assert decoder.feed(raw[23:]) == [frame]
    assert decoder.buffered == 0


def test_stream_decoder_empty_input() -> None:
    decoder = StreamDecoder()
    assert decoder.feed(b"") == []
    assert decoder.buffered == 0