#!/usr/bin/env python3
"""Generate the DroidVM virtio-media ABI (driver <-> user mode) from one specification.

Outputs (relative to this script's parent directory):

    client/vmedia_abi.h           C side, included by the UMD (d3d11_video.c, vmedia_client)
    media-wdm/src/vmedia_abi.rs   Rust side, the KMDF driver's no-std ABI module

Both files record the SHA-256 of *this script*, so a stale copy is visible without
guessing which side is newer, and both carry compile-time layout assertions for
every struct.

Run:
    python gen_abi.py                 # write both files
    python gen_abi.py --check         # do not write; diff against the repo copies
                                      # exit 1 if a file is out of date

Provenance
----------
This tool is *ours*, not the upstream author's.  The virtio-media WDM driver was
written from scratch in this project (P1c scaffold 2026-10-19 -> 1.0.0.30), and
the first version of this generator was written on 2026-10-22 (P2-1, sha256
022fe840...).  Later revisions (FLUSH, ZEROCOPY, SESSION-OWNERSHIP, TAG, ...)
were made by editing the generated headers by hand, which is why the files in the
repos still carry the old stamp 2886e5c0... and why they drifted apart
(client/vmedia_abi.h said 1.0.0.26 while src/vmedia_abi.rs said 1.0.0.30).

This file restores the single source of truth: every number the ABI promises
(IOCTL codes, struct sizes, version constants, "first driver version that ..."
gates) is defined once below and emitted into both languages.  Prose blocks are
kept verbatim so the text of the contract is preserved.
"""

import hashlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SELF_SHA = hashlib.sha256(pathlib.Path(__file__).resolve().read_bytes()).hexdigest()

# ---------------------------------------------------------------------------
# The contract, in one place.
# ---------------------------------------------------------------------------

ABI_VERSION = 1

# Current ABI revision.  Every bump changes the number a client compares against
# VM_OPEN_OUT.DriverVersion; see the per-feature MIN_* gates below.
DRIVER_VERSION = 0x0001_0024  # 1.0.0.36: runtime encoder bitrate
DRIVER_STRING = "1.0.0.36"

TAG_MIN_VERSION = 0x0001_001A  # 1.0.0.26: TAG ioctls
SESSION_OWNERSHIP_MIN_VERSION = 0x0001_0018  # 1.0.0.24: tokens, SEND_EX
MULTI_MAPPING_MIN_VERSION = 0x0001_0016  # 1.0.0.22: one mapping per buffer
MAP_FRAME_MIN_VERSION = 0x0001_0012  # 1.0.0.18: MAP/RELEASE_FRAME
HEVC_MAIN10_MIN_VERSION = 0x0001_0015  # 1.0.0.21: codec 4 + P010 CAPTURE
AV1_MIN_VERSION = 0x0001_0010  # 1.0.0.16: codec 3 ('AV01')
HEVC_MIN_VERSION = 0x0001_000F  # 1.0.0.15: codec 2 ('HEVC')
VP9_MIN_VERSION = 0x0001_000E  # 1.0.0.14: VM_OPEN_IN.Codec
FLUSH_MIN_VERSION = 0x0001_000B  # 1.0.0.11: VM_IOCTL_FLUSH

MAX_SESSIONS = 2  # Chromium keeps two decoder wrappers open
NO_SESSION_TOKEN = 0
RELEASE_ALL_INDEX = 0xFFFF_FFFF

DEVICE_TYPE = 0x22  # FILE_DEVICE_UNKNOWN
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
IOCTL_BASE_FUNCTION = 0x800  # first function code; one per entry below
VM_ENCODER_ABI_VERSION = 1
VM_ENCODER_CONFIG_CBR = 1
VM_ENCODER_INPUT_FORCE_KEYFRAME = 1
VM_ENCODER_EVENT_INPUT_DONE = 1
VM_ENCODER_EVENT_OUTPUT_DONE = 2
VM_ENCODER_EVENT_DRAIN_DONE = 3
VM_ENCODER_EVENT_ERROR = 4
VM_ENCODER_PACKET_FLAG_KEYFRAME = 1
VM_ENCODER_PACKET_FLAG_DRAIN_DONE = 2

GUID_D1 = 0xA3B2C1D0
GUID_D2 = 0x7E4A
GUID_D3 = 0x4C1B
GUID_D4 = [0x9F, 0x2D, 0x6A, 0x5B, 0x8C, 0x7D, 0x9E, 0x01]

CODECS = [
    ("H264", 0, "Open the session for H.264 ('H264' S_FMT on the host decoder)."),
    ("VP9", 1, "Open the session for VP9 ('VP90' S_FMT -> c2.qti.vp9.decoder)."),
    ("HEVC", 2, "P-BATCH HEVC (1.0.0.15): open the session for HEVC Main ('HEVC' S_FMT ->\n"
                "c2.qti.hevc.decoder).  Decoder only: there is no HEVC *encoder* path in this\n"
                "driver, so OPEN rejects it on the encoder function."),
    ("AV1", 3, "P-BATCH AV1 (1.0.0.16): open the session for AV1 ('AV01' S_FMT ->\n"
               "c2.qti.av1.decoder).  Decoder only, like HEVC.  The guest UMD rebuilds the\n"
               "AV1 OBU stream from DXVA_PicParams_AV1 + DXVA_Tile_AV1; this selector is\n"
               "what makes the host pick the AV1 backend instead of H.264."),
    ("HEVC_MAIN10", 4, "HEVC-MAIN10 (1.0.0.21): open the session for HEVC **Main10**.  The OUTPUT\n"
                       "format is the same 'HEVC' as codec 2 -- the same host decoder decodes Main\n"
                       "and Main10 -- but the CAPTURE queue is negotiated for 10 bits: S_FMT CAPTURE\n"
                       "asks V4L2_PIX_FMT_P010 first and falls back to NV12 (logged) when the device\n"
                       "refuses it.  Decoder only, like the other selectors.  A driver below\n"
                       "1.0.0.21 rejects the value at OPEN (ST_INVALID_PARAMETER), which is what the\n"
                       "UMD's version check keys on."),
]

# (name, C comment for the #define line, rust doc lines)
IOCTLS = [
    ("VM_IOCTL_OPEN", "open a decoder/encoder session",
     ["Open a decoder/encoder session"]),
    ("VM_IOCTL_SEND_BITSTREAM", "send one H.264 access unit",
     ["Send one h.264 access unit"]),
    ("VM_IOCTL_GET_FRAME", "block for one decoded NV12 frame",
     ["Block for one decoded nv12 frame"]),
    ("VM_IOCTL_CLOSE", "close the session",
     ["Close the session"]),
    ("VM_IOCTL_FLUSH", "P3-2: drop queued AUs/frames, new session",
     ["P3-2: drop the queued AUs/frames and restart the host session (seek / loop / pause-resume)"]),
    ("VM_IOCTL_MAP_FRAME", "P-BATCH ZEROCOPY: decoded frame, mapped",
     ["P-BATCH ZEROCOPY (1.0.0.18): block for one decoded frame and hand the caller",
      "a **user-mode VA of the capture buffer itself** instead of copying the NV12",
      "image into the output buffer.  The buffer stays checked out of the device",
      "until `VM_IOCTL_RELEASE_FRAME`, so the caller can upload from it directly."]),
    ("VM_IOCTL_RELEASE_FRAME", "P-BATCH ZEROCOPY: unmap + requeue",
     ["P-BATCH ZEROCOPY: unmap the frame `VM_IOCTL_MAP_FRAME` returned and give the",
      "capture buffer back to the device (the `QBUF` that `GET_FRAME` used to do",
      "after its copy).  `Index` must be the one `VM_FRAME_MAP.Index` reported."]),
    ("VM_IOCTL_SEND_BITSTREAM_EX", "SESSION-OWNERSHIP: SEND + SessionToken",
     ["SESSION-OWNERSHIP (1.0.0.24): `VM_IOCTL_SEND_BITSTREAM` with the session",
      "token in the header.  Same payload layout as the old code (`VM_SEND_IN_EX`",
      "instead of `VM_SEND_IN`, then `Size` bytes of access unit), a **separate code",
      "on purpose**: the header is followed immediately by the bitstream, so a",
      "longer header under the old code would be read by a 1.0.0.23 driver as",
      "\"16-byte header + an AU that starts 8 bytes too early\" and silently corrupt",
      "every decode.  An old driver answers this code with",
      "`STATUS_INVALID_DEVICE_REQUEST` (user mode `ERROR_INVALID_FUNCTION`), which is",
      "how the UMD detects that it has to fall back to the legacy code -- and say so",
      "in its log."]),
    ("VM_IOCTL_SEND_BITSTREAM_TAG", "TAG: EX header + Tag u64",
     ["TAG (1.0.0.26): SEND with a non-zero signed-64 internal frame tag. The",
      "legacy SEND header and IOCTL remain byte-for-byte unchanged."]),
    ("VM_IOCTL_GET_FRAME_TAG", "TAG: Info + Tag/token",
     ["TAG (1.0.0.26): GET_FRAME variant returning tag metadata. Its pixels start",
      "at byte 48 (legacy GET_FRAME remains byte 32 and is unchanged)."]),
    ("VM_IOCTL_MAP_FRAME_TAG", "TAG: Map + Tag/token", []),
    ("VM_IOCTL_ENC_CONFIG", "ENCODER v1: configure H.264 NV12 input and rate control", []),
    ("VM_IOCTL_ENC_QUEUE_INPUT", "ENCODER v1: queue one NV12 frame with timestamp", []),
    ("VM_IOCTL_ENC_GET_PACKET", "ENCODER v1: wait for and return one H.264 packet", []),
    ("VM_IOCTL_ENC_DRAIN", "ENCODER v1: drain delayed H.264 output", []),
    ("VM_IOCTL_ENC_FLUSH", "ENCODER v1: flush queued encoder input", []),
    ("VM_IOCTL_ENC_SET_BITRATE", "ENCODER v1: update target bitrate without reconfiguration", []),
]


def ctl(function):
    return (DEVICE_TYPE << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED


def ioctl_code(index):
    return ctl(IOCTL_BASE_FUNCTION + index)


# ---------------------------------------------------------------------------
# Struct layout, in one place.  `C` and `R` are per-dialect field lists:
#   ("u32" | "u64", NAME, [doc lines], separator_before_comment)
# Empty doc = no comment.  Sizes are computed, never typed twice.
# ---------------------------------------------------------------------------

SIZE_OF = {"u32": 4, "u64": 8}

C_STRUCTS = {
    "VM_OPEN_IN": [
        ("u32", "Kind", ["0 = decoder, 1 = encoder"], "  "),
        ("u32", "Codec", [
            "P-BATCH VP9/HEVC: VM_OPEN_CODEC_* (0 = H.264, the old",
            "default, so a client that leaves this 0 keeps the",
            "pre-VP9 behaviour).  Named Flags before 1.0.0.14 and",
            "required to be 0; the driver only ever read Kind.",
        ], " "),
    ],
    "VM_OPEN_OUT": [
        ("u32", "SessionId", ["virtio-media (host) session id"], "  "),
        ("u32", "IsDecoder", ["1 if this function decoded the card name as decoder"], "  "),
        ("u32", "DeviceCaps", ["virtio-media device_caps"], "  "),
        ("u32", "DeviceType", ["virtio-media device_type"], "  "),
        ("u32", "PoolSize", ["mapped media_host bytes (0 for encoder)"], "  "),
        ("u32", "DriverVersion", ["0x00010018 in 1.0.0.24"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: the generation this OPEN",
            "created.  Non-zero on a 1.0.0.24+ driver,",
            "0 on an older one (it was Reserved0).",
            "Send it back in every later IOCTL; a FLUSH",
            "replaces it with a new one.",
        ], "  "),
        ("u32", "Reserved1", ["0"], "  "),
    ],
    "VM_SEND_IN": [
        ("u32", "Width", ["coded width"], "  "),
        ("u32", "Height", ["coded height"], "  "),
        ("u32", "Size", ["H.264 bytes following this header"], "  "),
        ("u32", "Flags", ["bit 0 = request DECODER_CMD STOP after STREAMON"], "  "),
    ],
    "VM_SEND_IN_EX": [
        ("u32", "Width", [], "  "),
        ("u32", "Height", [], "  "),
        ("u32", "Size", [], "  "),
        ("u32", "Flags", [], "  "),
        ("u32", "SessionToken", ["VM_OPEN_OUT.SessionToken (0 = legacy)"], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_SEND_OUT": [
        ("u32", "Width", ["capture width accepted by S_FMT"], "  "),
        ("u32", "Height", ["capture height accepted by S_FMT"], "  "),
        ("u32", "OutputSizeImage", ["S_FMT OUTPUT sizeimage"], "  "),
        ("u32", "CaptureSizeImage", ["S_FMT CAPTURE sizeimage"], "  "),
        ("u32", "CaptureStride", ["S_FMT CAPTURE bytesperline"], "  "),
        ("u32", "CaptureCount", ["REQBUFS CAPTURE granted"], "  "),
        ("u32", "Reserved0", ["0"], "  "),
        ("u32", "Reserved1", ["0"], "  "),
    ],
    "VM_GET_FRAME_IN": [
        ("u32", "TimeoutMs", ["0 = poll once, else wait up to this many ms"], "  "),
        ("u32", "Flags", ["must be 0"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: VM_OPEN_OUT.SessionToken",
            "(0 = legacy client).  An older driver reads",
            "only the first 8 bytes and ignores this.",
        ], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_FRAME_INFO": [
        ("u32", "Width", ["decoded width"], "  "),
        ("u32", "Height", ["decoded height"], "  "),
        ("u32", "Stride", ["capture stride (bytes per row, both planes)"], "  "),
        ("u32", "Size", ["tight frame bytes following this header"], "  "),
        ("u32", "BytesUsed", ["DQBUF plane bytesused"], "  "),
        ("u32", "FourCC", ["0x3231564E ('NV12') or 0x30313050 ('P010', 1.0.0.21)"], "  "),
        ("u32", "SessionId", ["session that produced the frame"], "  "),
        ("u32", "Index", ["capture buffer index"], "  "),
    ],
    "VM_CLOSE_IN": [
        ("u32", "SessionId", ["virtio-media host session id (informational)"], "  "),
        ("u32", "Flags", ["must be 0"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: VM_OPEN_OUT.SessionToken.",
            "A CLOSE whose token is not the live session is",
            "IGNORED by the driver (success, one log line)",
            "instead of tearing down somebody else's",
            "session.  0 = legacy (accepted only while it",
            "is the only open session).",
        ], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_FLUSH_IN": [
        ("u32", "SessionId", ["virtio-media host session id (informational)"], "  "),
        ("u32", "Flags", ["must be 0"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: the token to flush; the",
            "answer carries the replacement's token and",
            "the old one is dead from then on.",
        ], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_FLUSH_OUT": [
        ("u32", "SessionId", ["host session id that replaces the flushed one"], "  "),
        ("u32", "DroppedAu", ["access units queued but never dequeued"], "  "),
        ("u32", "DroppedFrames", ["decoded frames the client never picked up"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: the NEW generation token.",
            "Use it for every IOCTL from now on; 0 means",
            "the driver predates 1.0.0.24 (Reserved0).",
        ], "  "),
    ],
    "VM_MAP_FRAME_IN": [
        ("u32", "TimeoutMs", ["0 = poll once, else wait up to this many ms"], "  "),
        ("u32", "Flags", ["must be 0"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: VM_OPEN_OUT.SessionToken",
            "(0 = legacy client).  A replaced session's",
            "MAP_FRAME is refused and nothing is checked",
            "out, so it can never read another session's",
            "frames.",
        ], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_FRAME_MAP": [
        ("u32", "Width", [], "  "),
        ("u32", "Height", [], "  "),
        ("u32", "Stride", ["pool row pitch (may be padded over Width)"], "     "),
        ("u32", "Size", ["tight frame bytes in the picture (NV12 or P010)"], "       "),
        ("u32", "BytesUsed", ["DQBUF plane bytesused"], "  "),
        ("u32", "FourCC", ["0x3231564E ('NV12') or 0x30313050 ('P010')"], "     "),
        ("u32", "SessionId", [], "  "),
        ("u32", "Index", ["capture buffer index (pass to RELEASE_FRAME)"], "      "),
        ("u64", "UserVa", ["user-mode VA of the first decoded byte"], "     "),
        ("u32", "MappedLength", ["readable bytes at UserVa (page-rounded)"], " "),
        ("u32", "Flags", ["0; bit 0 reserved for a cached mapping"], "      "),
    ],
    "VM_RELEASE_FRAME_IN": [
        ("u32", "SessionId", ["virtio-media host session id (informational)"], "  "),
        ("u32", "Index", ["VM_FRAME_MAP.Index, or 0xFFFFFFFF"], "  "),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: VM_OPEN_OUT.SessionToken.",
            "A release from a replaced session is refused",
            "(ERROR_BAD_COMMAND) and the live session's",
            "mapping for the same index is untouched.",
        ], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_ENCODER_CONFIG": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["structure size"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "Width", ["visible NV12 width"], "  "),
        ("u32", "Height", ["visible NV12 height; even for 4:2:0"], "  "),
        ("u32", "YStride", ["luma bytes per row"], "  "),
        ("u32", "UVStride", ["interleaved chroma bytes per row"], "  "),
        ("u32", "UVOffset", ["chroma plane byte offset within input payload"], "  "),
        ("u32", "FrameRateNum", ["frame rate numerator"], "  "),
        ("u32", "FrameRateDen", ["frame rate denominator"], "  "),
        ("u32", "Bitrate", ["target bitrate in bits per second"], "  "),
        ("u32", "GopFrames", ["maximum keyframe interval"], "  "),
        ("u32", "Flags", ["mode flags: 0 = VBR (default), VM_ENCODER_CONFIG_CBR = CBR; other bits must be 0"], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
    ],
    "VM_ENCODER_INPUT": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["header size; payload follows"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "BufferId", ["client input buffer identity"], "  "),
        ("u32", "DataSize", ["NV12 payload bytes following the header"], "  "),
        ("u32", "Flags", ["VM_ENCODER_INPUT_FORCE_KEYFRAME or 0"], "  "),
        ("u64", "Timestamp", ["opaque 100-ns timestamp; echoed on coded output"], "  "),
        ("u32", "YOffset", ["luma plane offset in payload"], "  "),
        ("u32", "UVOffset", ["chroma plane offset in payload"], "  "),
        ("u32", "YStride", ["luma bytes per row"], "  "),
        ("u32", "UVStride", ["chroma bytes per row"], "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
        ("u32", "Reserved1", ["must be 0; keeps the header 8-byte aligned"], "  "),
    ],
    "VM_ENCODER_GET_PACKET_IN": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["request structure size"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "TimeoutMs", ["0 polls once; otherwise bounded wait"], "  "),
        ("u32", "Capacity", ["maximum packet payload bytes in output buffer"], "  "),
        ("u32", "Flags", ["reserved; must be 0 in v1"], "  "),
    ],
    "VM_ENCODER_PACKET_INFO": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["packet metadata header size"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "BytesUsed", ["coded H.264 bytes following this header"], "  "),
        ("u32", "Flags", ["bit 0 = keyframe"] , "  "),
        ("u32", "Reserved0", ["must be 0"], "  "),
        ("u64", "Timestamp", ["submitted 100-ns timestamp"], "  "),
    ],
    "VM_ENCODER_RATE_CONTROL": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["structure size; 16 bytes"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "Bitrate", ["target bits per second; 1..INT32_MAX"], "  "),
    ],
    "VM_ENCODER_CONTROL": [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"], "  "),
        ("u32", "Size", ["structure size"], "  "),
        ("u32", "SessionToken", ["OPEN session generation token"], "  "),
        ("u32", "Flags", ["reserved; must be 0 in v1"], "  "),
    ],
}

# Structs emitted verbatim in C (several declarators per line); the sizes below
# are asserted in both languages.
C_RAW_STRUCTS = [
    ("VM_SEND_IN_TAG", [
        "typedef struct _VM_SEND_IN_TAG {",
        "    uint32_t Width, Height, Size, Flags, SessionToken, Reserved0;",
        "    uint64_t Tag;",
        "} VM_SEND_IN_TAG;",
    ], 32),
    ("VM_FRAME_TAG_OUT", [
        "typedef struct _VM_FRAME_TAG_OUT {",
        "    VM_FRAME_INFO Info;",
        "    uint64_t Tag;",
        "    uint32_t SessionToken, Reserved0;",
        "} VM_FRAME_TAG_OUT;",
    ], 48),
    ("VM_FRAME_MAP_TAG_OUT", [
        "typedef struct _VM_FRAME_MAP_TAG_OUT {",
        "    VM_FRAME_MAP Map;",
        "    uint64_t Tag;",
        "    uint32_t SessionToken, Reserved0;",
        "} VM_FRAME_MAP_TAG_OUT;",
    ], 64),
]

R_STRUCTS = [
    ("VM_OPEN_IN", None, [
        ("u32", "Kind", ["0 = decoder, 1 = encoder"]),
        ("u32", "Codec", [
            "VM_OPEN_CODEC_*: which coded format the host session is configured for.",
            "0 = H.264, which is what every pre-1.0.0.14 guest sent (the field was",
            "called `Flags` and required to be 0), so the layout and the old",
            "behaviour are unchanged.",
        ]),
    ]),
    ("VM_OPEN_OUT", None, [
        ("u32", "SessionId", ["virtio-media session id (the *host's* id; informational)"]),
        ("u32", "IsDecoder", ["1 if this function decoded the card name as decoder"]),
        ("u32", "DeviceCaps", ["virtio-media device_caps"]),
        ("u32", "DeviceType", ["virtio-media device_type"]),
        ("u32", "PoolSize", ["mapped media_host bytes (0 for encoder)"]),
        ("u32", "DriverVersion", ["0x0001000A"]),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP (1.0.0.24): the **generation token** of the session this",
            "OPEN created.  Never 0, never reused by this device instance, and a fresh",
            "one on every FLUSH.  This field used to be `Reserved0` (always 0), so the",
            "struct keeps its 32-byte size and a pre-1.0.0.24 client reads 0 here and",
            "is served as a legacy client (only accepted while it is the only session).",
        ]),
        ("u32", "Reserved1", ["0"]),
    ]),
    ("VM_SEND_IN_TAG", [
        "SESSION-OWNERSHIP (1.0.0.24): `VM_IOCTL_SEND_BITSTREAM_EX` input, followed by",
        "`Size` bytes of access unit.  The first four fields are exactly a",
        "`VM_SEND_IN`, so a client can fill one of these instead without changing what",
        "the driver reads for a legacy SEND.",
    ], [
        ("u32", "Width", []),
        ("u32", "Height", []),
        ("u32", "Size", []),
        ("u32", "Flags", []),
        ("u32", "SessionToken", []),
        ("u32", "Reserved0", []),
        ("u64", "Tag", ["Non-zero internal tag, encoded as signed timeval seconds/useconds."]),
    ]),
    ("VM_SEND_IN_EX", None, [
        ("u32", "Width", ["coded width"]),
        ("u32", "Height", ["coded height"]),
        ("u32", "Size", ["H.264 bytes following this header"]),
        ("u32", "Flags", ["bit 0 = request DECODER_CMD STOP after STREAMON"]),
        ("u32", "SessionToken", ["SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken` (0 = legacy client)"]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_SEND_IN", None, [
        ("u32", "Width", ["coded width"]),
        ("u32", "Height", ["coded height"]),
        ("u32", "Size", ["H.264 bytes following this header"]),
        ("u32", "Flags", ["bit 0 = request DECODER_CMD STOP after STREAMON"]),
    ]),
    ("VM_SEND_OUT", None, [
        ("u32", "Width", ["capture width accepted by S_FMT"]),
        ("u32", "Height", ["capture height accepted by S_FMT"]),
        ("u32", "OutputSizeImage", ["S_FMT OUTPUT sizeimage"]),
        ("u32", "CaptureSizeImage", ["S_FMT CAPTURE sizeimage"]),
        ("u32", "CaptureStride", ["S_FMT CAPTURE bytesperline"]),
        ("u32", "CaptureCount", ["REQBUFS CAPTURE granted"]),
        ("u32", "Reserved0", ["0"]),
        ("u32", "Reserved1", ["0"]),
    ]),
    ("VM_GET_FRAME_IN", None, [
        ("u32", "TimeoutMs", ["0 = poll once, else wait up to this many ms"]),
        ("u32", "Flags", ["must be 0"]),
        ("u32", "SessionToken", ["SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken` (0 = legacy client)"]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_FRAME_INFO", None, [
        ("u32", "Width", ["decoded width"]),
        ("u32", "Height", ["decoded height"]),
        ("u32", "Stride", ["capture stride"]),
        ("u32", "Size", ["tight NV12 bytes following this header"]),
        ("u32", "BytesUsed", ["DQBUF plane bytesused"]),
        ("u32", "FourCC", ["0x3231564E ('NV12')"]),
        ("u32", "SessionId", ["session that produced the frame"]),
        ("u32", "Index", ["capture buffer index"]),
    ]),
    ("VM_CLOSE_IN", None, [
        ("u32", "SessionId", [
            "virtio-media session id (host id; informational, also used as an",
            "ownership *hint* by a legacy client that has no token)",
        ]),
        ("u32", "Flags", ["must be 0"]),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken`.  When it names a session",
            "that is no longer live the CLOSE is **ignored** (success, one log line):",
            "that is exactly the \"the replaced decoder tears down its own session after",
            "the new one exists\" case this field was added for.",
        ]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_FLUSH_IN", [
        "P3-2 flush request: drop everything queued and hand back a fresh host",
        "session so the next SEND starts a new sequence (first AU must be an IDR with",
        "SPS/PPS -- the UMD injects them).",
    ], [
        ("u32", "SessionId", ["virtio-media session id (host id; informational)"]),
        ("u32", "Flags", ["must be 0"]),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken`.  A FLUSH **bumps** the",
            "generation: the answer carries the replacement's token, so any completion",
            "still in flight for the old token is refused from now on.",
        ]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_FLUSH_OUT", None, [
        ("u32", "SessionId", ["the host session id that replaces the flushed one"]),
        ("u32", "DroppedAu", ["access units that were queued but never dequeued"]),
        ("u32", "DroppedFrames", ["decoded frames the client never picked up"]),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: the **new** generation token.  The client must use it",
            "for every IOCTL from now on; the old one is dead.  Old field name:",
            "Reserved0 (always 0), so the struct keeps its 16 bytes.",
        ]),
    ]),
    ("VM_MAP_FRAME_IN", [
        "P-BATCH ZEROCOPY: input of `VM_IOCTL_MAP_FRAME`.  Same shape as",
        "`VM_GET_FRAME_IN` -- the wait is identical, only the handover differs.",
    ], [
        ("u32", "TimeoutMs", ["0 = poll once, else wait up to this many ms"]),
        ("u32", "Flags", ["must be 0"]),
        ("u32", "SessionToken", ["SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken` (0 = legacy client)"]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_FRAME_MAP", [
        "P-BATCH ZEROCOPY: output of `VM_IOCTL_MAP_FRAME`.",
        "",
        "The first eight fields are exactly a `VM_FRAME_INFO`, so a client can use",
        "this struct and the staged `GET_FRAME` result interchangeably.  `UserVa`",
        "points at the first byte of the decoded picture inside the capture buffer",
        "that is now mapped into the **calling process**; `MappedLength` is how many",
        "bytes starting at `UserVa` are readable (page-rounded, always >= `Size`).",
        "The mapping is `MmNonCached` (the pool itself is mapped PAGE_NOCACHE, and on",
        "ARM64 a cached read of a buffer the host wrote could return stale lines).",
        "",
        "The buffer is **checked out of the device** until `VM_IOCTL_RELEASE_FRAME`",
        "with `Index`: while it is out the device cannot write another frame into it,",
        "which is exactly what makes reading `UserVa` safe without a copy.",
    ], [
        ("u32", "Width", []),
        ("u32", "Height", []),
        ("u32", "Stride", []),
        ("u32", "Size", ["tight NV12 size of the picture (what `VM_FRAME_INFO.Size` reports)"]),
        ("u32", "BytesUsed", []),
        ("u32", "FourCC", []),
        ("u32", "SessionId", []),
        ("u32", "Index", []),
        ("u64", "UserVa", ["user-mode VA of the first decoded byte, in the calling process"]),
        ("u32", "MappedLength", ["readable bytes at `UserVa` (page-rounded mapping window)"]),
        ("u32", "Flags", ["0 today (bit 0 is reserved for \"cached mapping\")"]),
    ]),
    ("VM_RELEASE_FRAME_IN", [
        "P-BATCH ZEROCOPY: input of `VM_IOCTL_RELEASE_FRAME`.  `Index` is",
        "`VM_FRAME_MAP.Index`; 0xFFFFFFFF (`VM_RELEASE_ALL_INDEX`) means \"release every",
        "mapping of this session\".  CONCURRENT-MAPPING (1.0.0.22): a concrete `Index`",
        "frees **exactly that** capture buffer, so several mappings can be out at once",
        "and each is handed back on its own; an index that is not mapped answers",
        "`ST_INVALID_PARAMETER` and an empty table `ST_INVALID_DEVICE_STATE`.",
    ], [
        ("u32", "SessionId", ["virtio-media session id (host id; informational)"]),
        ("u32", "Index", []),
        ("u32", "SessionToken", [
            "SESSION-OWNERSHIP: `VM_OPEN_OUT.SessionToken`.  A RELEASE that names a",
            "replaced session is refused (`ST_INVALID_DEVICE_STATE`) and touches",
            "nothing: the new session's identical index stays mapped and its buffer",
            "stays checked out.",
        ]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_FRAME_TAG_OUT", None, [
        ("u32", "Info", []),
        ("u64", "Tag", []),
        ("u32", "SessionToken", []),
        ("u32", "Reserved0", []),
    ]),
    ("VM_FRAME_MAP_TAG_OUT", None, [
        ("u32", "Map", []),
        ("u64", "Tag", []),
        ("u32", "SessionToken", []),
        ("u32", "Reserved0", []),
    ]),
    ("VM_ENCODER_CONFIG", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["structure size"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "Width", ["visible NV12 width"]),
        ("u32", "Height", ["visible NV12 height; even for 4:2:0"]),
        ("u32", "YStride", ["luma bytes per row"]),
        ("u32", "UVStride", ["interleaved chroma bytes per row"]),
        ("u32", "UVOffset", ["chroma plane byte offset within input payload"]),
        ("u32", "FrameRateNum", ["frame rate numerator"]),
        ("u32", "FrameRateDen", ["frame rate denominator"]),
        ("u32", "Bitrate", ["target bitrate in bits per second"]),
        ("u32", "GopFrames", ["maximum keyframe interval"]),
        ("u32", "Flags", ["mode flags: 0 = VBR (default), VM_ENCODER_CONFIG_CBR = CBR; other bits must be 0"]),
        ("u32", "Reserved0", ["must be 0"]),
    ]),
    ("VM_ENCODER_INPUT", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["header size; payload follows"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "BufferId", ["client input buffer identity"]),
        ("u32", "DataSize", ["NV12 payload bytes following the header"]),
        ("u32", "Flags", ["VM_ENCODER_INPUT_FORCE_KEYFRAME or 0"]),
        ("u64", "Timestamp", ["opaque 100-ns timestamp; echoed on coded output"]),
        ("u32", "YOffset", ["luma plane offset in payload"]),
        ("u32", "UVOffset", ["chroma plane offset in payload"]),
        ("u32", "YStride", ["luma bytes per row"]),
        ("u32", "UVStride", ["chroma bytes per row"]),
        ("u32", "Reserved0", ["must be 0"]),
        ("u32", "Reserved1", ["must be 0; keeps the header 8-byte aligned"]),
    ]),
    ("VM_ENCODER_GET_PACKET_IN", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["request structure size"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "TimeoutMs", ["0 polls once; otherwise bounded wait"]),
        ("u32", "Capacity", ["maximum packet payload bytes in output buffer"]),
        ("u32", "Flags", ["reserved; must be 0 in v1"]),
    ]),
    ("VM_ENCODER_PACKET_INFO", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["packet metadata header size"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "BytesUsed", ["coded H.264 bytes following this header"]),
        ("u32", "Flags", ["bit 0 = keyframe"]),
        ("u32", "Reserved0", ["must be 0"]),
        ("u64", "Timestamp", ["submitted 100-ns timestamp"]),
    ]),
    ("VM_ENCODER_RATE_CONTROL", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["structure size; 16 bytes"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "Bitrate", ["target bits per second; 1..INT32_MAX"]),
    ]),
    ("VM_ENCODER_CONTROL", None, [
        ("u32", "Version", ["VM_ENCODER_ABI_VERSION"]),
        ("u32", "Size", ["structure size"]),
        ("u32", "SessionToken", ["OPEN session generation token"]),
        ("u32", "Flags", ["reserved; must be 0 in v1"]),
    ]),
]

# Reference sizes; every file asserts these, so a typo here fails the build.
EXPECTED_SIZES = {
    "VM_OPEN_IN": 8, "VM_OPEN_OUT": 32, "VM_SEND_IN": 16, "VM_SEND_IN_EX": 24,
    "VM_SEND_OUT": 32, "VM_GET_FRAME_IN": 16, "VM_FRAME_INFO": 32, "VM_CLOSE_IN": 16,
    "VM_FLUSH_IN": 16, "VM_FLUSH_OUT": 16, "VM_MAP_FRAME_IN": 16, "VM_FRAME_MAP": 48,
    "VM_RELEASE_FRAME_IN": 16, "VM_SEND_IN_TAG": 32, "VM_FRAME_TAG_OUT": 48,
    "VM_FRAME_MAP_TAG_OUT": 64,
    "VM_ENCODER_CONFIG": 56,
    "VM_ENCODER_INPUT": 56,
    "VM_ENCODER_GET_PACKET_IN": 24,
    "VM_ENCODER_PACKET_INFO": 32,
    "VM_ENCODER_CONTROL": 16,
    "VM_ENCODER_RATE_CONTROL": 16,
}

# TAG structs in Rust hold a nested struct plus a u64; their layout is spelled
# out here rather than computed from the field list above (Info/Map are structs).
RAW_SIZES = {"VM_FRAME_TAG_OUT": 48, "VM_FRAME_MAP_TAG_OUT": 64, "VM_SEND_IN_TAG": 32}


def struct_size(name):
    if name in RAW_SIZES:
        return RAW_SIZES[name]
    fields = C_STRUCTS.get(name)
    if fields is None:
        raise KeyError(name)
    return sum(SIZE_OF[t] for t, _, _, _ in fields)



size_of = struct_size  # sizes are declared once in the schema
C_RAW = [(n, l) for (n, l, _sz) in C_RAW_STRUCTS]  # C_RAW_STRUCTS also carries the asserted size
# ---------------------------------------------------------------------------
# 2. C emitter
# ---------------------------------------------------------------------------

LATE_C_STRUCTS = ("VM_MAP_FRAME_IN", "VM_FRAME_MAP", "VM_RELEASE_FRAME_IN")

# Comment padding used by the historical file (per struct/field), so a
# regeneration keeps the same columns instead of reformatting every line.
C_SEP = {
    ("VM_OPEN_IN", "Codec"): 1,
    ("VM_SEND_IN_EX", "Reserved0"): 5,
    ("VM_GET_FRAME_IN", "Reserved0"): 5,
    ("VM_CLOSE_IN", "Reserved0"): 5,
    ("VM_FLUSH_IN", "Reserved0"): 5,
    ("VM_MAP_FRAME_IN", "Flags"): 6,
    ("VM_MAP_FRAME_IN", "Reserved0"): 5,
    ("VM_FRAME_MAP", "Stride"): 5,
    ("VM_FRAME_MAP", "Size"): 7,
    ("VM_FRAME_MAP", "FourCC"): 5,
    ("VM_FRAME_MAP", "Index"): 6,
    ("VM_FRAME_MAP", "UserVa"): 5,
    ("VM_FRAME_MAP", "MappedLength"): 1,
    ("VM_FRAME_MAP", "Flags"): 6,
    ("VM_RELEASE_FRAME_IN", "Index"): 6,
    ("VM_RELEASE_FRAME_IN", "Reserved0"): 5,
}



C_TYPES = {"u32": "uint32_t", "u64": "uint64_t"}


def c_field(ctype, name, doc, sep):
    """One C struct member with its /* */ comment aligned like the file."""
    head = "    %-15s%s;" % (C_TYPES.get(ctype, ctype), name)
    if not doc:
        return [head]
    first = head + sep + "/* " + doc[0]
    if len(doc) == 1:
        return [first + " */"]
    star = first.index("/*") + 1
    out = [first]
    for line in doc[1:]:
        out.append((" " * star + "* " + line).rstrip())
    out[-1] += " */"
    return out


def c_struct(L, name):
    A = L.append
    A("typedef struct _%s {" % name)
    if name == "VM_FRAME_MAP":
        A("    /* The first eight fields are a VM_FRAME_INFO, field for field, so a client")
        A("     * can use this and the staged GET_FRAME result interchangeably. */")
    for ctype, fname, doc, sep in C_STRUCTS[name]:
        pad = C_SEP.get((name, fname))
        L.extend(c_field(ctype, fname, doc, sep if pad is None else " " * pad))
    A("} %s;" % name)
    A("")


def gen_c():
    L = []
    A = L.append

    A("/* @generated by tools/gen_abi.py -- do not edit.")
    A(" * generator sha256: %s" % SELF_SHA)
    A(" * ABI version %d, driver %s." % (ABI_VERSION, DRIVER_STRING))
    A(" *")
    A(" * Hand edits, all layout-preserving (same sizes, same field order):")
    A(" *   P-BATCH VP9/HEVC/AV1 renamed VM_OPEN_IN.Flags to .Codec and added the")
    A(" *   selector values 1..3; HEVC-MAIN10 (2026-10-25) adds value 4")
    A(" *   (VM_OPEN_CODEC_HEVC_MAIN10, \"HEVC Main10, ask the driver for")
    A(" *   V4L2_PIX_FMT_P010 CAPTURE\") and moves VMEDIA_DRIVER_VERSION to 0x00010015.")
    A(" *   VMEDIA_FLUSH_MIN_DRIVER_VERSION was added because VMEDIA_DRIVER_VERSION is")
    A(" *   the *current* ABI revision: a UMD built against a newer one must still flush")
    A(" *   on any driver that implemented VM_IOCTL_FLUSH, not only on its own version.")
    A(" *   The generated tool has to be updated to match before the next regeneration.")
    A(" */")
    A("#ifndef VMEDIA_ABI_H")
    A("#define VMEDIA_ABI_H")
    A("")
    A("#include <stdint.h>")
    A("")
    A("#define VMEDIA_ABI_VERSION  %d" % ABI_VERSION)
    A("/* 1.0.0.24 = SESSION-OWNERSHIP (2026-10-26).  The driver keeps two sessions per")
    A(" * function, hands out a generation *token* at OPEN (VM_OPEN_OUT.SessionToken)")
    A(" * and checks it on every later IOCTL, so a replaced decoder's CLOSE/FLUSH/SEND/")
    A(" * RELEASE can never touch the session that replaced it.  SEND moved to a second")
    A(" * IOCTL code (VM_IOCTL_SEND_BITSTREAM_EX) because its header is followed by the")
    A(" * access unit: a longer header under the old code would shift the bitstream.")
    A(" * A driver older than VMEDIA_SESSION_OWNERSHIP_MIN_VERSION answers the EX code")
    A(" * with ERROR_INVALID_FUNCTION; this client then falls back to the legacy code")
    A(" * (and logs once). */")
    A("#define VMEDIA_DRIVER_VERSION 0x%08Xu" % DRIVER_VERSION)
    A("#define VMEDIA_TAG_MIN_VERSION 0x%08Xu" % TAG_MIN_VERSION)
    A("/* First driver version that reads VM_OPEN_OUT.SessionToken and the SessionToken")
    A(" * field of the extended CLOSE/FLUSH/RELEASE/GET_FRAME/MAP_FRAME/SEND_EX input")
    A(" * structs (media-wdm 1.0.0.24).  Below it every request is \"legacy\" (token 0)")
    A(" * and the driver serves it as long as it is the only session. */")
    A("#define VMEDIA_SESSION_OWNERSHIP_MIN_VERSION 0x%08Xu" % SESSION_OWNERSHIP_MIN_VERSION)
    A("/* How many sessions one driver function keeps alive (2: Chromium opens two")
    A(" * decoder wrappers).  A client may hold this many OPEN handles at once. */")
    A("#define VMEDIA_MAX_SESSIONS %du" % MAX_SESSIONS)
    A("#define VMEDIA_DEVICE_TYPE 0x%02Xu" % DEVICE_TYPE)
    A("")
    A("/* CTL_CODE(FILE_DEVICE_UNKNOWN, 0x%03X..0x%03X, METHOD_BUFFERED, FILE_ANY_ACCESS) */"
      % (IOCTL_BASE_FUNCTION, IOCTL_BASE_FUNCTION + len(IOCTLS) - 1))
    for i, (name, cdoc, _) in enumerate(IOCTLS):
        A("#define %-28s 0x%08Xu  /* %s */" % (name, ioctl_code(i), cdoc))
    A("")
    A("/* Device interface class advertised with WdfDeviceCreateDeviceInterface. */")
    A("#define VMEDIA_INTERFACE_GUID \\")
    A("    { 0x%08X, 0x%04X, 0x%04X, { %s } }"
      % (GUID_D1, GUID_D2, GUID_D3, ", ".join("0x%02X" % b for b in GUID_D4)))
    A("")
    A("/* Kernel symbolic links the client opens: \\\\.\\VMediaDecoder / \\\\.\\VMediaEncoder */")
    A('#define VMEDIA_LINK_DECODER  L"\\\\\\\\.\\\\VMediaDecoder"')
    A('#define VMEDIA_LINK_ENCODER  L"\\\\\\\\.\\\\VMediaEncoder"')
    A("")
    A("#define VM_ENCODER_ABI_VERSION %du" % VM_ENCODER_ABI_VERSION)
    A("#define VM_ENCODER_CONFIG_CBR %du" % VM_ENCODER_CONFIG_CBR)
    A("#define VM_ENCODER_INPUT_FORCE_KEYFRAME %du" % VM_ENCODER_INPUT_FORCE_KEYFRAME)
    A("#define VM_ENCODER_EVENT_INPUT_DONE %du" % VM_ENCODER_EVENT_INPUT_DONE)
    A("#define VM_ENCODER_EVENT_OUTPUT_DONE %du" % VM_ENCODER_EVENT_OUTPUT_DONE)
    A("#define VM_ENCODER_EVENT_DRAIN_DONE %du" % VM_ENCODER_EVENT_DRAIN_DONE)
    A("#define VM_ENCODER_EVENT_ERROR %du" % VM_ENCODER_EVENT_ERROR)
    A("#define VM_ENCODER_PACKET_FLAG_KEYFRAME %du" % VM_ENCODER_PACKET_FLAG_KEYFRAME)
    A("#define VM_ENCODER_PACKET_FLAG_DRAIN_DONE %du" % VM_ENCODER_PACKET_FLAG_DRAIN_DONE)
    A("")

    for name in C_STRUCTS:
        if name in LATE_C_STRUCTS:
            continue
        if name == "VM_FLUSH_IN":
            A("/* P3-2: drop everything queued and restart the host session (seek / loop /")
            A(" * pause-resume). The next SEND must be an IDR with SPS/PPS. */")
        c_struct(L, name)
        if name == "VM_OPEN_IN":
            A("/* VM_OPEN_IN.Codec: which coded format the host session is configured for.")
            A(" * The host virtio-media decoder picks its MediaCodec backend from the V4L2")
            A(" * OUTPUT pixel format the guest driver sends at S_FMT time ('H264', 'VP90' or")
            A(" * 'HEVC'), so the choice has to travel with OPEN -- SEND has no room for it and")
            A(" * must stay a pure access unit.  0 keeps H.264, so old UMDs and old guests are")
            A(" * unaffected. */")
            A("#define VM_OPEN_CODEC_H264 0u")
            A("#define VM_OPEN_CODEC_VP9  1u")
            A("#define VM_OPEN_CODEC_HEVC 2u")
            A("/* P-BATCH AV1: codec 3 -> S_FMT 'AV01' -> c2.qti.av1.decoder on the host. */")
            A("#define VM_OPEN_CODEC_AV1  3u")
            A("/* HEVC-MAIN10 (1.0.0.21): codec 4 = HEVC Main10.  Same OUTPUT pixel format as")
            A(" * codec 2 ('HEVC' -- the same host decoder decodes Main and Main10), but the")
            A(" * driver configures the CAPTURE queue for 10-bit: it asks S_FMT CAPTURE for")
            A(" * V4L2_PIX_FMT_P010 first and falls back to NV12 (with a log line) when the")
            A(" * device refuses it.  A driver below 1.0.0.21 rejects the value at OPEN, so the")
            A(" * UMD refuses the combination up front (VMEDIA_HEVC_MAIN10_MIN_DRIVER_VERSION). */")
            A("#define VM_OPEN_CODEC_HEVC_MAIN10 4u")
            A("")
            A("")
            A("/* First driver version that honours VM_OPEN_IN.Codec (media-wdm 1.0.0.14).")
            A(" * A VP9 decoder created against an older driver would be configured for H.264 on")
            A(" * the host and could only time out, so the UMD refuses it and logs why. */")
            A("#define VMEDIA_VP9_MIN_DRIVER_VERSION 0x%08Xu" % VP9_MIN_VERSION)
            A("")
            A("/* First driver version that accepts VM_OPEN_CODEC_HEVC and sends S_FMT 'HEVC'")
            A(" * (media-wdm 1.0.0.15).  1.0.0.14 rejects any codec id above 1 at OPEN, so an")
            A(" * HEVC decoder against it fails immediately instead of timing out per frame --")
            A(" * the UMD still refuses the combination up front so the log names the reason. */")
            A("#define VMEDIA_HEVC_MIN_DRIVER_VERSION 0x%08Xu" % HEVC_MIN_VERSION)
            A("")
            A("/* First driver version that accepts VM_OPEN_CODEC_AV1 and sends S_FMT 'AV01'")
            A(" * (media-wdm 1.0.0.16).  1.0.0.15 rejects any codec id above 2 at OPEN, so an")
            A(" * AV1 decoder against it fails immediately; the UMD refuses the combination up")
            A(" * front so the log names the reason instead of timing out per frame. */")
            A("#define VMEDIA_AV1_MIN_DRIVER_VERSION 0x%08Xu" % AV1_MIN_VERSION)
            A("")
            A("/* First driver version that accepts VM_OPEN_CODEC_HEVC_MAIN10 and negotiates")
            A(" * V4L2_PIX_FMT_P010 on the CAPTURE queue (media-wdm 1.0.0.21).  1.0.0.20 and")
            A(" * older reject any codec id above 3 at OPEN, and their CAPTURE format is NV12")
            A(" * only, so a Main10 decoder against them could not be 10-bit anyway. */")
            A("#define VMEDIA_HEVC_MAIN10_MIN_DRIVER_VERSION 0x%08Xu" % HEVC_MAIN10_MIN_VERSION)
            A("")
            A("/* First driver version that implements VM_IOCTL_FLUSH (media-wdm 1.0.0.11).")
            A(" * Kept separate from VMEDIA_DRIVER_VERSION: the flush test must stay true for")
            A(" * every driver that has the IOCTL, not only for the ABI revision this UMD was")
            A(" * built against (a 1.0.0.20 guest flushes exactly like a 1.0.0.21 one). */")
            A("#define VMEDIA_FLUSH_MIN_DRIVER_VERSION 0x%08Xu" % FLUSH_MIN_VERSION)
            A("")
            A("")
        if name == "VM_SEND_IN":
            A("/* SESSION-OWNERSHIP (1.0.0.24): VM_IOCTL_SEND_BITSTREAM_EX input, followed by")
            A(" * `Size` bytes of access unit.  The first four fields are a VM_SEND_IN. */")
        if name == "VM_CLOSE_IN":
            pass
        if name == "VM_FLUSH_IN":
            pass

    A("/* Offsets inside the VM_IOCTL_GET_FRAME output buffer. */")
    A("#define VM_FRAME_INFO_SIZE %d" % size_of("VM_FRAME_INFO"))
    A("#define VM_FRAME_DATA_OFFSET %d" % size_of("VM_FRAME_INFO"))
    A("")
    A("/* ------------------------------------------------------------------------- */")
    A("/* P-BATCH ZEROCOPY (1.0.0.18): VM_IOCTL_MAP_FRAME / VM_IOCTL_RELEASE_FRAME   */")
    A("/*                                                                           */")
    A("/* MAP_FRAME blocks for the next decoded frame exactly like GET_FRAME, but    */")
    A("/* instead of copying the NV12 image into the ioctl output buffer it maps the */")
    A("/* capture buffer's media_host pool pages into the *calling process* and      */")
    A("/* reports that VA.  The buffer stays checked out of the device (the QBUF      */")
    A("/* GET_FRAME used to do after its copy is deferred) until RELEASE_FRAME, so   */")
    A("/* the pixels cannot be overwritten while the client uploads from them.       */")
    A("/*                                                                           */")
    A("/* RELEASE_FRAME unmaps the frame and requeues the capture buffer.  `Index`   */")
    A("/* is VM_FRAME_MAP.Index; 0xFFFFFFFF means \"whatever is mapped\".              */")
    A("/* ------------------------------------------------------------------------- */")
    A("")
    A("/* First driver version that implements MAP_FRAME/RELEASE_FRAME.  A UMD must")
    A(" * check VM_OPEN_OUT.DriverVersion against this before it tries the direct")
    A(" * path; an older driver answers ST_INVALID_DEVICE_REQUEST, which surfaces as")
    A(" * ERROR_INVALID_FUNCTION (1) and would otherwise cost one failed ioctl per")
    A(" * frame. */")
    A("#define VMEDIA_MAP_FRAME_MIN_DRIVER_VERSION 0x%08Xu" % MAP_FRAME_MIN_VERSION)
    A("")
    A("/* CONCURRENT-MAPPING (1.0.0.22): first driver version whose MAP_FRAME may be")
    A(" * called while other capture buffers are still mapped, and whose RELEASE_FRAME")
    A(" * frees exactly the index it is given.  A driver below this answers the second")
    A(" * MAP_FRAME with ERROR_BAD_COMMAND, so a UMD that keeps more than one frame in")
    A(" * flight has to check VM_OPEN_OUT.DriverVersion against it first. */")
    A("#define VMEDIA_MULTI_MAPPING_MIN_DRIVER_VERSION 0x%08Xu" % MULTI_MAPPING_MIN_VERSION)
    A("")
    A("/* CONCURRENT-MAPPING: VM_RELEASE_FRAME_IN.Index value that means \"release every")
    A(" * mapping of this session\" (the pre-1.0.0.22 \"whatever is mapped\"). */")
    A("#define VM_RELEASE_ALL_INDEX 0x%08Xu" % RELEASE_ALL_INDEX)
    A("")

    for name in LATE_C_STRUCTS:
        c_struct(L, name)

    A("/* TAG v1.0.0.26. Tag is an internal job id, not application PTS.")
    A(" * SEND payload starts at 32; GET_TAG pixels start at 48. Legacy offsets stay 16/32.")
    A(" * Tag must be in [1, INT64_MAX]; no fallback is allowed for tag APIs. */")
    for name, lines in C_RAW:
        L.extend(lines)
    A("typedef char vm_assert_send_tag[(sizeof(VM_SEND_IN_TAG) == %d) ? 1 : -1];" % size_of("VM_SEND_IN_TAG"))
    A("typedef char vm_assert_frame_tag[(sizeof(VM_FRAME_TAG_OUT) == %d) ? 1 : -1];" % size_of("VM_FRAME_TAG_OUT"))
    A("typedef char vm_assert_map_tag[(sizeof(VM_FRAME_MAP_TAG_OUT) == %d) ? 1 : -1];" % size_of("VM_FRAME_MAP_TAG_OUT"))
    A("")
    A("/* Compile-time layout checks. */")
    for name, expected in EXPECTED_SIZES.items():
        if name in ("VM_SEND_IN_TAG", "VM_FRAME_TAG_OUT", "VM_FRAME_MAP_TAG_OUT"):
            continue  # these three have their own vm_assert_* lines above
        A("typedef char vm_assert_%s_size[(sizeof(%s) == %d) ? 1 : -1];" % (name, name, expected))
    A("")
    A("#endif /* VMEDIA_ABI_H */")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 3. Rust emitter
# ---------------------------------------------------------------------------

# The two TAG output structs embed a whole struct field.
for _i, (_n, _d, _f) in enumerate(R_STRUCTS):
    if _n == "VM_FRAME_TAG_OUT":
        R_STRUCTS[_i] = (_n, _d, [("VM_FRAME_INFO", "Info", []), ("u64", "Tag", []),
                                  ("u32", "SessionToken", []), ("u32", "Reserved0", [])])
    elif _n == "VM_FRAME_MAP_TAG_OUT":
        R_STRUCTS[_i] = (_n, _d, [("VM_FRAME_MAP", "Map", []), ("u64", "Tag", []),
                                  ("u32", "SessionToken", []), ("u32", "Reserved0", [])])

R_SIZE = {
    "VM_OPEN_IN": 8, "VM_OPEN_OUT": 32, "VM_SEND_IN_TAG": 32, "VM_SEND_IN_EX": 24,
    "VM_SEND_IN": 16, "VM_SEND_OUT": 32, "VM_GET_FRAME_IN": 16, "VM_FRAME_INFO": 32,
    "VM_CLOSE_IN": 16, "VM_FLUSH_IN": 16, "VM_FLUSH_OUT": 16, "VM_MAP_FRAME_IN": 16,
    "VM_FRAME_MAP": 48, "VM_RELEASE_FRAME_IN": 16, "VM_FRAME_TAG_OUT": 48,
    "VM_FRAME_MAP_TAG_OUT": 64,
    "VM_ENCODER_CONFIG": 56,
    "VM_ENCODER_INPUT": 56,
    "VM_ENCODER_GET_PACKET_IN": 24,
    "VM_ENCODER_PACKET_INFO": 32,
    "VM_ENCODER_CONTROL": 16,
    "VM_ENCODER_RATE_CONTROL": 16,
}


def rust_doc(L, lines, indent=""):
    for line in lines:
        if line:
            L.append(indent + "/// " + line)
        else:
            L.append(indent + "///")


def rust_struct(L, name, doc, fields, blank_after=True):
    if doc:
        rust_doc(L, doc)
    L.append("#[repr(C)]")
    L.append("#[derive(Clone, Copy, Default)]")
    L.append("pub struct %s {" % name)
    for rtype, fname, fdoc in fields:
        rust_doc(L, fdoc, "    ")
        L.append("    pub %s: %s," % (fname, rtype))
    L.append("}")
    if blank_after:
        L.append("")


def gen_rust():
    L = []
    A = L.append

    A("//! @generated by tools/gen_abi.py -- do not edit.")
    A("//! generator sha256: %s" % SELF_SHA)
    A("//! ABI version %d, driver %s." % (ABI_VERSION, DRIVER_STRING))
    A("//! P-BATCH VP9 hand edit (same layout, same sizes): VM_OPEN_IN.Flags became")
    A("//! VM_OPEN_IN.Codec (0 = H.264, 1 = VP9) and the driver version moved to")
    A("//! 0x0001000E so a UMD can tell whether the codec selector exists.  P-BATCH HEVC")
    A("//! adds codec 2 ('HEVC') and moves the version to 0x0001000F; P-BATCH AV1 adds")
    A("//! codec 3 ('AV01') and moves it to 0x00010010.  HEVC-MAIN10 adds codec 4")
    A("//! (HEVC Main10: same 'HEVC' OUTPUT format, CAPTURE negotiated as")
    A("//! V4L2_PIX_FMT_P010 with an NV12 fallback) and moved the version to")
    A("//! 0x00010015; no IOCTL or struct layout changed.  CONCURRENT-MAPPING (1.0.0.22)")
    A("//! changes only *what MAP_FRAME/RELEASE_FRAME may do* -- one mapping per capture")
    A("//! buffer instead of one per session -- and moves the version to 0x00010016; the")
    A("//! IOCTL codes, the structs and `VMEDIA_ABI_VERSION` are untouched.  Relayouting")
    A("//! the generated file by hand is safe here because only the *name* and the")
    A("//! meaning of an always-zero field changed; the generated tool has to be updated")
    A("//! to match before the next regeneration.")
    A("#![allow(non_snake_case, non_upper_case_globals)]")
    A("")
    A("pub const VMEDIA_ABI_VERSION: u32 = %d;" % ABI_VERSION)
    rust_doc(L, [
        "1.0.0.18 (P-BATCH ZEROCOPY): adds MAP_FRAME/RELEASE_FRAME.  1.0.0.17 was the",
        "MSI-X batch; its version string was bumped without the ABI constant, so the",
        "two disagreed (string 1.0.0.17 / constant 1.0.0.16) until here.",
        "1.0.0.19 (MERGE-20261024): same ABI as 1.0.0.18; the single tree that carries",
        "VP9/HEVC/AV1 (one `Codec` field), MSI-X, P010 and MAP_FRAME/RELEASE_FRAME.",
        "1.0.0.20 (P-BATCH POOLFIX / E173): same ABI; only how many CAPTURE buffers the",
        "driver asks for (capacity-based) and what it does when REQBUFS refuses.",
        "1.0.0.21 (HEVC-MAIN10): same IOCTL table and struct layout; a new codec",
        "selector value (`VM_OPEN_CODEC_HEVC_MAIN10`) and the P010 CAPTURE negotiation",
        "it enables.",
        "1.0.0.22 (CONCURRENT-MAPPING): same IOCTL table and struct layout.  The driver",
        "now keeps **one mapping per capture buffer** instead of one per session, so a",
        "second `MAP_FRAME` no longer answers `ST_INVALID_DEVICE_STATE`; every mapping",
        "is released by its own `VM_RELEASE_FRAME_IN.Index`, and 0xFFFFFFFF keeps the",
        "old \"release all\" meaning.  A client can tell the semantics apart with",
        "`DriverVersion >= VMEDIA_MULTI_MAPPING_MIN_VERSION`.",
        "1.0.0.23 (CACHED-POOL): same IOCTL table and struct layout.  A **memory",
        "attribute** change only: the `media_host` pool and the per-frame user windows",
        "over it are mapped `MmCached` instead of `MmNonCached`, with per-frame",
        "maintenance in both directions.  Nothing in the ABI moves; the version is",
        "bumped because the *timing* of every MAP_FRAME/GET_FRAME changes by two",
        "orders of magnitude and a log has to be attributable to one binary.",
        "1.0.0.24 (SESSION-OWNERSHIP): **identity, ordering and recovery** (author doc",
        "5.4).  `VM_OPEN` hands out a *generation token* (`VM_OPEN_OUT.SessionToken`,",
        "the old `Reserved0` slot -- layout unchanged, so a pre-1.0.0.24 client reads",
        "the same 32 bytes and simply sees 0) and every later IOCTL carries it back in",
        "a `SessionToken` field appended to its input struct.  CLOSE / FLUSH /",
        "RELEASE_FRAME / MAP_FRAME / GET_FRAME / SEND only act on the session that owns",
        "the token; a token that belongs to a *replaced* session is ignored (CLOSE) or",
        "refused with `ST_INVALID_DEVICE_STATE` (everything else) instead of tearing",
        "down whatever session happens to be live.  FLUSH and a re-OPEN bump the",
        "generation, so a completion that was in flight for the old generation can",
        "never write the new one's buffers.  SEND grew a second IOCTL code",
        "(`VM_IOCTL_SEND_BITSTREAM_EX`, 24-byte header) instead of a longer",
        "`VM_SEND_IN`, because its input is `header + bitstream`: a longer header in",
        "place would make a new UMD's access unit start 8 bytes too early on an old",
        "driver.  A **zero token means \"legacy client\"**: it is accepted only while",
        "exactly one session is open, and every such request is counted and logged.",
    ])
    A("pub const VMEDIA_DRIVER_VERSION: u32 = 0x%04X_%04X;" % (DRIVER_VERSION >> 16, DRIVER_VERSION & 0xFFFF))
    A("pub const VMEDIA_TAG_MIN_VERSION: u32 = 0x%04X_%04X;" % (TAG_MIN_VERSION >> 16, TAG_MIN_VERSION & 0xFFFF))
    A("")
    rust_doc(L, [
        "SESSION-OWNERSHIP (1.0.0.24): first driver version that accepts the",
        "`SessionToken` field of the extended input structs and the",
        "`VM_IOCTL_SEND_BITSTREAM_EX` code.  A UMD must compare",
        "`VM_OPEN_OUT.DriverVersion` against it before it relies on either; below it",
        "the token reads as 0 and `SEND_BITSTREAM_EX` answers",
        "`STATUS_INVALID_DEVICE_REQUEST` (user mode ERROR_INVALID_FUNCTION).",
    ])
    A("pub const VMEDIA_SESSION_OWNERSHIP_MIN_VERSION: u32 = 0x%04X_%04X;"
      % (SESSION_OWNERSHIP_MIN_VERSION >> 16, SESSION_OWNERSHIP_MIN_VERSION & 0xFFFF))
    A("")
    rust_doc(L, [
        "SESSION-OWNERSHIP: how many sessions one virtio-media function keeps alive at",
        "once.  Chromium builds two decoder wrappers (`Initialize` and",
        "`RecreateDecoderWrapper`) and both are open for the lifetime of the second",
        "OPEN, so one slot is not enough; 2 is what the media_host pool can carry,",
        "because each session's CAPTURE ask is scaled to `pool / open_sessions`.",
    ])
    A("pub const VMEDIA_MAX_SESSIONS: u32 = %d;" % MAX_SESSIONS)
    A("")
    rust_doc(L, [
        "SESSION-OWNERSHIP: the `SessionToken` value that means \"no identity\" (a",
        "pre-1.0.0.24 client, or a zeroed struct).  The driver never issues it: tokens",
        "start at 1 and only grow.",
    ])
    A("pub const VMEDIA_NO_SESSION_TOKEN: u32 = %d;" % NO_SESSION_TOKEN)
    A("")
    rust_doc(L, [
        "CONCURRENT-MAPPING (1.0.0.22): first driver version whose `MAP_FRAME` may be",
        "called while other capture buffers are still mapped, and whose",
        "`RELEASE_FRAME` frees exactly the index it is given.  A driver below this",
        "answers the second `MAP_FRAME` with `ST_INVALID_DEVICE_STATE` (user mode",
        "err=22), so a UMD that wants more than one frame in flight must check",
        "`VM_OPEN_OUT.DriverVersion` against it first.  Same IOCTL codes and same",
        "struct sizes: an old UMD (one frame at a time, release by index) runs",
        "unchanged on a 1.0.0.22 driver.",
    ])
    A("pub const VMEDIA_MULTI_MAPPING_MIN_VERSION: u32 = 0x%04X_%04X;"
      % (MULTI_MAPPING_MIN_VERSION >> 16, MULTI_MAPPING_MIN_VERSION & 0xFFFF))
    A("")
    rust_doc(L, [
        "CONCURRENT-MAPPING: `VM_RELEASE_FRAME_IN.Index` value that means \"release",
        "every mapping of this session\" (the pre-1.0.0.22 \"whatever is mapped\").",
    ])
    A("pub const VM_RELEASE_ALL_INDEX: u32 = 0x%04X_%04X;" % (RELEASE_ALL_INDEX >> 16, RELEASE_ALL_INDEX & 0xFFFF))
    A("")
    A("pub const VMEDIA_DEVICE_TYPE: u32 = 0x%02X;" % DEVICE_TYPE)
    A("pub const VMEDIA_METHOD_BUFFERED: u32 = %d;" % METHOD_BUFFERED)
    A("")

    for i, (name, _, rdoc) in enumerate(IOCTLS):
        if name == "VM_IOCTL_MAP_FRAME":
            A("")
        rust_doc(L, rdoc)
        A("pub const %s: u32 = 0x%08X;" % (name, ioctl_code(i)))
    A("")

    A("#[repr(C)]")
    A("#[derive(Clone, Copy)]")
    A("pub struct Guid {")
    A("    pub Data1: u32,")
    A("    pub Data2: u16,")
    A("    pub Data3: u16,")
    A("    pub Data4: [u8; 8],")
    A("}")
    A("")
    A("pub const VMEDIA_INTERFACE_GUID: Guid = Guid {")
    A("    Data1: 0x%08X," % GUID_D1)
    A("    Data2: 0x%04X," % GUID_D2)
    A("    Data3: 0x%04X," % GUID_D3)
    A("    Data4: [%s]," % ", ".join("0x%02X" % b for b in GUID_D4))
    A("};")
    A("")
    A(r'pub const VMEDIA_LINK_DECODER: &[u8] = b"\\DosDevices\\VMediaDecoder";')
    A(r'pub const VMEDIA_LINK_ENCODER: &[u8] = b"\\DosDevices\\VMediaEncoder";')
    A("")
    A("pub const VM_ENCODER_ABI_VERSION: u32 = %d;" % VM_ENCODER_ABI_VERSION)
    A("pub const VM_ENCODER_CONFIG_CBR: u32 = %d;" % VM_ENCODER_CONFIG_CBR)
    A("pub const VM_ENCODER_INPUT_FORCE_KEYFRAME: u32 = %d;" % VM_ENCODER_INPUT_FORCE_KEYFRAME)
    A("pub const VM_ENCODER_EVENT_INPUT_DONE: u32 = %d;" % VM_ENCODER_EVENT_INPUT_DONE)
    A("pub const VM_ENCODER_EVENT_OUTPUT_DONE: u32 = %d;" % VM_ENCODER_EVENT_OUTPUT_DONE)
    A("pub const VM_ENCODER_EVENT_DRAIN_DONE: u32 = %d;" % VM_ENCODER_EVENT_DRAIN_DONE)
    A("pub const VM_ENCODER_EVENT_ERROR: u32 = %d;" % VM_ENCODER_EVENT_ERROR)
    A("pub const VM_ENCODER_PACKET_FLAG_KEYFRAME: u32 = %d;" % VM_ENCODER_PACKET_FLAG_KEYFRAME)
    A("pub const VM_ENCODER_PACKET_FLAG_DRAIN_DONE: u32 = %d;" % VM_ENCODER_PACKET_FLAG_DRAIN_DONE)
    A("")

    for name, doc, fields in R_STRUCTS:
        rust_struct(L, name, doc, fields,
                    blank_after=name not in ("VM_FRAME_TAG_OUT",))
        if name == "VM_OPEN_IN":
            for cname, value, cdoc in CODECS:
                rust_doc(L, cdoc.splitlines() if isinstance(cdoc, str) else cdoc)
                A("pub const VM_OPEN_CODEC_%s: u32 = %d;" % (cname, value))
            A("")
            A("")

    # The last struct has no blank line before the assertion block.
    L[-1:] = []
    A("const _: () = {")
    A("    assert!(core::mem::size_of::<VM_SEND_IN_TAG>() == %d);" % R_SIZE["VM_SEND_IN_TAG"])
    A("    assert!(core::mem::size_of::<VM_FRAME_TAG_OUT>() == %d);" % R_SIZE["VM_FRAME_TAG_OUT"])
    A("    assert!(core::mem::size_of::<VM_FRAME_MAP_TAG_OUT>() == %d);" % R_SIZE["VM_FRAME_MAP_TAG_OUT"])
    A("    use core::mem::size_of;")
    for name in ("VM_OPEN_IN", "VM_OPEN_OUT", "VM_SEND_IN", "VM_SEND_OUT", "VM_GET_FRAME_IN",
                 "VM_FRAME_INFO", "VM_CLOSE_IN", "VM_FLUSH_IN", "VM_FLUSH_OUT", "VM_MAP_FRAME_IN",
                 "VM_FRAME_MAP", "VM_RELEASE_FRAME_IN"):
        A("    assert!(size_of::<%s>() == %d);" % (name, R_SIZE[name]))
    A("    // SESSION-OWNERSHIP (1.0.0.24): the extended SEND header is exactly a")
    A("    // VM_SEND_IN followed by the token, which is what lets the driver read the")
    A("    // first 16 bytes of either struct with the same code.")
    A("    assert!(size_of::<VM_SEND_IN_EX>() == %d);" % R_SIZE["VM_SEND_IN_EX"])
    for name, expected in EXPECTED_SIZES.items():
        if name.startswith("VM_ENCODER_"):
            A("    assert!(size_of::<%s>() == %d);" % (name, expected))
    for i, (name, _, _) in enumerate(IOCTLS):
        A("    assert!(%s == 0x%08X);" % (name, ioctl_code(i)))
    A("    // CONCURRENT-MAPPING: the version a client checks, and the \"release all\"")
    A("    // index, are part of the contract even though no layout changed.")
    A("    // CACHED-POOL (1.0.0.23) bumps the version again -- same layouts, but the")
    A("    // read timing changed completely, so the number has to say which binary.")
    A("    // SESSION-OWNERSHIP (1.0.0.24) is the first version that reads the token.")
    A("    assert!(VMEDIA_DRIVER_VERSION == 0x%08X);" % DRIVER_VERSION)
    A("    assert!(VMEDIA_TAG_MIN_VERSION == 0x%08X);" % TAG_MIN_VERSION)
    A("    assert!(VMEDIA_MULTI_MAPPING_MIN_VERSION == 0x%08X);" % MULTI_MAPPING_MIN_VERSION)
    A("    assert!(VMEDIA_SESSION_OWNERSHIP_MIN_VERSION == 0x%08X);" % SESSION_OWNERSHIP_MIN_VERSION)
    A("    assert!(VMEDIA_MAX_SESSIONS == %d);" % MAX_SESSIONS)
    A("    assert!(VMEDIA_NO_SESSION_TOKEN == %d);" % NO_SESSION_TOKEN)
    A("    assert!(VM_RELEASE_ALL_INDEX == 0x%04X_%04X);" % (RELEASE_ALL_INDEX >> 16, RELEASE_ALL_INDEX & 0xFFFF))
    A("};")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 4. Entry point
# ---------------------------------------------------------------------------

def main(argv):
    root = ROOT
    check = "--check" in argv
    if "--root" in argv:
        root = pathlib.Path(argv[argv.index("--root") + 1]).resolve()

    header = root / "client" / "vmedia_abi.h"
    rust = root / "media-wdm" / "src" / "vmedia_abi.rs"
    if "--header" in argv:
        header = pathlib.Path(argv[argv.index("--header") + 1]).resolve()
    if "--rust" in argv:
        rust = pathlib.Path(argv[argv.index("--rust") + 1]).resolve()

    # Fail fast on a schema typo: the sizes the files assert must be the sizes
    # the field lists actually produce.
    for _name, _expected in EXPECTED_SIZES.items():
        if size_of(_name) != _expected:
            raise SystemExit("schema error: %s is %d bytes, expected %d"
                             % (_name, size_of(_name), _expected))

    outputs = [(header, gen_c()), (rust, gen_rust())]

    status = 0
    for path, text in outputs:
        if check:
            if not path.exists():
                print("MISSING  %s" % path)
                status = 1
                continue
            # The repo copies live on Windows (CRLF); compare line-ending-agnostic.
            old = path.read_text(encoding="utf-8").replace(chr(13) + chr(10), chr(10))
            if old == text:
                print("OK       %s" % path)
            else:
                import difflib
                diff = list(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                                 fromfile=str(path) + " (repo)",
                                                 tofile=str(path) + " (generated)", n=1))
                print("STALE    %s  (%d diff lines)" % (path, len(diff)))
                sys.stdout.writelines(diff[:120])
                status = 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline=chr(10))
            print("wrote %s  (%d bytes)" % (path, len(text)))
    if not check:
        print("generator sha256 %s" % SELF_SHA)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
