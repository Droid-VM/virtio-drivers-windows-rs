#[path = "../src/vmedia_abi.rs"]
mod vmedia_abi;
#[path = "../src/encoder_abi.rs"]
mod encoder_abi;

use encoder_abi::{validate_config, validate_input, validate_get_packet, validate_control, validate_format_reply_len, validate_negotiated_dimensions, EncoderRequestError};
use vmedia_abi::{VM_ENCODER_CONFIG, VM_ENCODER_INPUT, VM_ENCODER_GET_PACKET_IN,
    VM_ENCODER_CONTROL, VM_ENCODER_ABI_VERSION, VM_ENCODER_INPUT_FORCE_KEYFRAME,
    VM_ENCODER_PACKET_FLAG_KEYFRAME, VM_ENCODER_PACKET_FLAG_DRAIN_DONE,
    VM_ENCODER_CONFIG_CBR, VM_ENCODER_RATE_CONTROL, VM_IOCTL_ENC_SET_BITRATE,
    VM_IOCTL_ENC_FLUSH};

fn config() -> VM_ENCODER_CONFIG {
    VM_ENCODER_CONFIG { Version: VM_ENCODER_ABI_VERSION, Size: 56, SessionToken: 7,
        Width: 64, Height: 48, YStride: 64, UVStride: 64, UVOffset: 3072,
        FrameRateNum: 30, FrameRateDen: 1, Bitrate: 2_000_000, GopFrames: 60,
        Flags: 0, Reserved0: 0 }
}
fn input() -> VM_ENCODER_INPUT {
    VM_ENCODER_INPUT { Version: VM_ENCODER_ABI_VERSION, Size: 56, SessionToken: 7,
        BufferId: 3, DataSize: 4608, Flags: 0, Timestamp: 1234, YOffset: 0,
        UVOffset: 3072, YStride: 64, UVStride: 64, Reserved0: 0, Reserved1: 0 }
}
#[test]
fn valid_nv12_layout_and_input() {
    assert_eq!(validate_config(&config()).unwrap().total, 4608);
    assert_eq!(validate_input(&config(), &input(), 4608).unwrap().uv_end, 4608);
}
#[test]
fn config_defaults_to_vbr() {
    let c = config();
    assert_eq!(c.Flags, 0);
    assert_eq!(validate_config(&c).unwrap().total, 4608);
    assert!(validate_input(&c, &input(), 4608).is_ok());
}
#[test]
fn config_allows_cbr() {
    assert_eq!(VM_ENCODER_CONFIG_CBR, 1);
    let mut c = config();
    c.Flags = VM_ENCODER_CONFIG_CBR;
    assert_eq!(validate_config(&c).unwrap().total, 4608);
    assert!(validate_input(&c, &input(), 4608).is_ok());
}
#[test]
fn config_rejects_unknown_mode_bits() {
    for bit in 1..32 {
        for mode in [0, VM_ENCODER_CONFIG_CBR] {
            let mut c = config();
            c.Flags = mode | (1u32 << bit);
            assert_eq!(validate_config(&c), Err(EncoderRequestError::Flags));
        }
    }
}
#[test]
fn config_rejects_reserved_field_in_either_mode() {
    for mode in [0, VM_ENCODER_CONFIG_CBR] {
        let mut c = config();
        c.Flags = mode;
        c.Reserved0 = 1;
        assert_eq!(validate_config(&c), Err(EncoderRequestError::Reserved));
    }
}
#[test]
fn s_fmt_reply_length_is_bounded_before_fields_are_read() {
    assert_eq!(validate_format_reply_len(207,208),Err(EncoderRequestError::PayloadLength));
    assert_eq!(validate_format_reply_len(208,208),Ok(()));
    assert_eq!(validate_format_reply_len(216,208),Ok(()));
}
#[test]
fn rejects_adjusted_encoder_dimensions() {
    let c = config();
    assert_eq!(validate_negotiated_dimensions(&c, 64, 48), Ok(()));
    assert_eq!(validate_negotiated_dimensions(&c, 128, 48), Err(EncoderRequestError::Dimensions));
    assert_eq!(validate_negotiated_dimensions(&c, 64, 128), Err(EncoderRequestError::Dimensions));
    assert_eq!(validate_negotiated_dimensions(&c, 0, 0), Err(EncoderRequestError::Dimensions));
}
#[test]
fn force_idr_flag_is_allowed() {
    let mut f=input();f.Flags=VM_ENCODER_INPUT_FORCE_KEYFRAME;
    assert!(validate_input(&config(),&f,4608).is_ok());
}
#[test]
fn rejects_odd_geometry() {
    let mut c=config();c.Width=63;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::Dimensions));
}
#[test]
fn rejects_short_stride() {
    let mut c=config();c.YStride=32;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::Stride));
}
#[test]
fn rejects_wrong_uv_offset() {
    let mut c=config();c.UVOffset=3000;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::PlaneOffset));
}
#[test]
fn rejects_short_payload() {
    assert_eq!(validate_input(&config(),&input(),4607),Err(EncoderRequestError::PayloadLength));
}
#[test]
fn rejects_mismatched_token() {
    let mut f=input();f.SessionToken=8;
    assert_eq!(validate_input(&config(),&f,4608),Err(EncoderRequestError::SessionToken));
}
#[test]
fn rejects_unknown_flags_and_reserved() {
    let mut f=input();f.Flags=2;
    assert_eq!(validate_input(&config(),&f,4608),Err(EncoderRequestError::Flags));
    let mut f=input();f.Reserved1=1;
    assert_eq!(validate_input(&config(),&f,4608),Err(EncoderRequestError::Reserved));
}
#[test]
fn rejects_mismatched_stride() {
    let mut f=input();f.UVStride=128;
    assert_eq!(validate_input(&config(),&f,4608),Err(EncoderRequestError::PlaneOffset));
}
#[test]
fn rejects_size_overflow_before_mapping() {
    let mut c=config();c.Width=u32::MAX-1;c.Height=u32::MAX-1;
    c.YStride=u32::MAX;c.UVStride=u32::MAX;c.UVOffset=u32::MAX;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::Overflow));
}
#[test]
fn rejects_config_version_and_size() {
    let mut c=config();c.Version=2;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::Version));
    let mut c=config();c.Size=0;
    assert_eq!(validate_config(&c),Err(EncoderRequestError::Size));
}
fn packet_req()->VM_ENCODER_GET_PACKET_IN{VM_ENCODER_GET_PACKET_IN{Version:1,Size:24,SessionToken:7,TimeoutMs:100,Capacity:2048,Flags:0}}
fn control()->VM_ENCODER_CONTROL{VM_ENCODER_CONTROL{Version:1,Size:16,SessionToken:7,Flags:0}}
#[test]
fn validates_bounded_packet_wait_and_output_space(){let r=packet_req();assert_eq!(validate_get_packet(&r,7,2080),Ok(2048));assert_eq!(validate_get_packet(&r,7,2079),Err(EncoderRequestError::PacketCapacity));let mut r=packet_req();r.TimeoutMs=30_001;assert_eq!(validate_get_packet(&r,7,4096),Err(EncoderRequestError::Timeout));let mut r=packet_req();r.Capacity=u32::MAX;assert_eq!(validate_get_packet(&r,7,4096),Err(EncoderRequestError::PacketCapacity));}
#[test]
fn packet_flags_separate_keyframe_and_drain_done(){assert_eq!(VM_ENCODER_PACKET_FLAG_KEYFRAME,1);assert_eq!(VM_ENCODER_PACKET_FLAG_DRAIN_DONE,2);assert_eq!(encoder_abi::encoder_packet_flags(false,false),0);assert_eq!(encoder_abi::encoder_packet_flags(true,false),1);assert_eq!(encoder_abi::encoder_packet_flags(false,true),2);assert_eq!(encoder_abi::encoder_packet_flags(true,true),3);}
#[test]
fn validates_control_version_token_and_reserved(){let c=control();assert_eq!(validate_control(&c,7),Ok(()));let mut c=control();c.SessionToken=8;assert_eq!(validate_control(&c,7),Err(EncoderRequestError::SessionToken));let mut c=control();c.Flags=1;assert_eq!(validate_control(&c,7),Err(EncoderRequestError::Reserved));}

fn rate_control() -> VM_ENCODER_RATE_CONTROL {
    VM_ENCODER_RATE_CONTROL {
        Version: VM_ENCODER_ABI_VERSION, Size: 16, SessionToken: 7, Bitrate: 2_000_000,
    }
}

#[test]
fn bitrate_ioctl_uses_next_function_and_preserves_control_layout() {
    assert_eq!(VM_IOCTL_ENC_SET_BITRATE, 0x00222040);
    assert_eq!(VM_IOCTL_ENC_SET_BITRATE, VM_IOCTL_ENC_FLUSH + 4);
    assert_eq!(core::mem::size_of::<VM_ENCODER_RATE_CONTROL>(), 16);
    assert_eq!(core::mem::size_of::<VM_ENCODER_CONTROL>(), 16);
}

#[test]
fn validates_bitrate_signed_control_boundaries() {
    for bitrate in [1, 2_000_000, i32::MAX as u32] {
        let mut r = rate_control();
        r.Bitrate = bitrate;
        assert_eq!(encoder_abi::validate_rate_control(&r, 7), Ok(()));
    }
    for bitrate in [0, i32::MAX as u32 + 1, u32::MAX] {
        let mut r = rate_control();
        r.Bitrate = bitrate;
        assert_eq!(encoder_abi::validate_rate_control(&r, 7), Err(EncoderRequestError::Bitrate));
    }
}

#[test]
fn bitrate_control_rejects_version_size_and_stale_or_zero_token() {
    let mut r = rate_control();
    r.Version += 1;
    assert_eq!(encoder_abi::validate_rate_control(&r, 7), Err(EncoderRequestError::Version));
    for size in [0, 12, 20, u32::MAX] {
        let mut r = rate_control();
        r.Size = size;
        assert_eq!(encoder_abi::validate_rate_control(&r, 7), Err(EncoderRequestError::Size));
    }
    for token in [0, 8] {
        let mut r = rate_control();
        r.SessionToken = token;
        assert_eq!(encoder_abi::validate_rate_control(&r, 7), Err(EncoderRequestError::SessionToken));
    }
    assert_eq!(encoder_abi::validate_rate_control(&rate_control(), 0), Err(EncoderRequestError::SessionToken));
}
