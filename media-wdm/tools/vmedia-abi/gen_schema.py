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
DRIVER_VERSION = 0x0001_001E  # 1.0.0.30
DRIVER_STRING = "1.0.0.30"

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
]

# Reference sizes; every file asserts these, so a typo here fails the build.
EXPECTED_SIZES = {
    "VM_OPEN_IN": 8, "VM_OPEN_OUT": 32, "VM_SEND_IN": 16, "VM_SEND_IN_EX": 24,
    "VM_SEND_OUT": 32, "VM_GET_FRAME_IN": 16, "VM_FRAME_INFO": 32, "VM_CLOSE_IN": 16,
    "VM_FLUSH_IN": 16, "VM_FLUSH_OUT": 16, "VM_MAP_FRAME_IN": 16, "VM_FRAME_MAP": 48,
    "VM_RELEASE_FRAME_IN": 16, "VM_SEND_IN_TAG": 32, "VM_FRAME_TAG_OUT": 48,
    "VM_FRAME_MAP_TAG_OUT": 64,
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

