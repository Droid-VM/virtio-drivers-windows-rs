use crate::vmedia_abi::{VM_ENCODER_CONFIG, VM_ENCODER_INPUT, VM_ENCODER_GET_PACKET_IN,
    VM_ENCODER_CONTROL, VM_ENCODER_ABI_VERSION, VM_ENCODER_INPUT_FORCE_KEYFRAME,
    VM_ENCODER_PACKET_INFO, VM_ENCODER_CONFIG_CBR, VM_ENCODER_RATE_CONTROL};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderRequestError {
    Version,
    Size,
    Reserved,
    Dimensions,
    Stride,
    PlaneOffset,
    PayloadLength,
    Flags,
    SessionToken,
    PacketCapacity,
    Timeout,
    Overflow,
    Bitrate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nv12Layout {
    pub y_end: u32,
    pub uv_end: u32,
    pub total: u32,
}

pub fn encoder_packet_flags(keyframe: bool, last: bool) -> u32 {
    (if keyframe { crate::vmedia_abi::VM_ENCODER_PACKET_FLAG_KEYFRAME } else { 0 })
        | (if last { crate::vmedia_abi::VM_ENCODER_PACKET_FLAG_DRAIN_DONE } else { 0 })
}

pub fn validate_format_reply_len(used: usize, required: usize) -> Result<(), EncoderRequestError> {
    if used < required { return Err(EncoderRequestError::PayloadLength); }
    Ok(())
}

pub fn validate_negotiated_dimensions(c: &VM_ENCODER_CONFIG, width: u32, height: u32)
    -> Result<(), EncoderRequestError> {
    if width != c.Width || height != c.Height { return Err(EncoderRequestError::Dimensions); }
    Ok(())
}

pub fn validate_config(c: &VM_ENCODER_CONFIG) -> Result<Nv12Layout, EncoderRequestError> {
    if c.Version != VM_ENCODER_ABI_VERSION { return Err(EncoderRequestError::Version); }
    if c.Size as usize != core::mem::size_of::<VM_ENCODER_CONFIG>() { return Err(EncoderRequestError::Size); }
    if c.Flags & !VM_ENCODER_CONFIG_CBR != 0 { return Err(EncoderRequestError::Flags); }
    if c.Reserved0 != 0 { return Err(EncoderRequestError::Reserved); }
    if c.Width == 0 || c.Height == 0 || (c.Width & 1) != 0 || (c.Height & 1) != 0 {
        return Err(EncoderRequestError::Dimensions);
    }
    if c.YStride < c.Width || c.UVStride < c.Width { return Err(EncoderRequestError::Stride); }
    if c.FrameRateNum == 0 || c.FrameRateDen == 0 || c.Bitrate == 0 || c.GopFrames == 0 {
        return Err(EncoderRequestError::Dimensions);
    }
    let y=(c.YStride as u64).checked_mul(c.Height as u64).ok_or(EncoderRequestError::Overflow)?;
    let uvrows=(c.Height/2) as u64;
    let uv=uvrows.checked_mul(c.UVStride as u64).ok_or(EncoderRequestError::Overflow)?;
    let end=y.checked_add(uv).ok_or(EncoderRequestError::Overflow)?;
    if y > u32::MAX as u64 || end > u32::MAX as u64 { return Err(EncoderRequestError::Overflow); }
    if c.UVOffset as u64 != y { return Err(EncoderRequestError::PlaneOffset); }
    Ok(Nv12Layout { y_end:y as u32, uv_end:end as u32, total:end as u32 })
}

pub fn validate_get_packet(req:&VM_ENCODER_GET_PACKET_IN,token:u32,out_len:usize)
    ->Result<usize,EncoderRequestError>{
    if req.Version!=VM_ENCODER_ABI_VERSION{return Err(EncoderRequestError::Version)}
    if req.Size as usize!=core::mem::size_of::<VM_ENCODER_GET_PACKET_IN>(){return Err(EncoderRequestError::Size)}
    if req.SessionToken==0||req.SessionToken!=token{return Err(EncoderRequestError::SessionToken)}
    if req.Flags!=0{return Err(EncoderRequestError::Reserved)}
    if req.TimeoutMs>30_000{return Err(EncoderRequestError::Timeout)}
    let header=core::mem::size_of::<VM_ENCODER_PACKET_INFO>();
    let capacity=req.Capacity as usize;
    if capacity==0||capacity.checked_add(header).filter(|&n|n<=out_len).is_none(){
        return Err(EncoderRequestError::PacketCapacity)
    }
    Ok(capacity)
}

pub fn validate_rate_control(req: &VM_ENCODER_RATE_CONTROL, token: u32)
    -> Result<(), EncoderRequestError> {
    if req.Version != VM_ENCODER_ABI_VERSION { return Err(EncoderRequestError::Version); }
    if req.Size as usize != core::mem::size_of::<VM_ENCODER_RATE_CONTROL>() {
        return Err(EncoderRequestError::Size);
    }
    if req.SessionToken == 0 || req.SessionToken != token {
        return Err(EncoderRequestError::SessionToken);
    }
    if req.Bitrate == 0 || req.Bitrate > i32::MAX as u32 {
        return Err(EncoderRequestError::Bitrate);
    }
    Ok(())
}

pub fn validate_control(req:&VM_ENCODER_CONTROL,token:u32)->Result<(),EncoderRequestError>{
    if req.Version!=VM_ENCODER_ABI_VERSION{return Err(EncoderRequestError::Version)}
    if req.Size as usize!=core::mem::size_of::<VM_ENCODER_CONTROL>(){return Err(EncoderRequestError::Size)}
    if req.SessionToken==0||req.SessionToken!=token{return Err(EncoderRequestError::SessionToken)}
    if req.Flags!=0{return Err(EncoderRequestError::Reserved)}
    Ok(())
}

pub fn validate_input(c: &VM_ENCODER_CONFIG, f: &VM_ENCODER_INPUT, payload_len: usize)
    -> Result<Nv12Layout, EncoderRequestError> {
    if f.Version != VM_ENCODER_ABI_VERSION { return Err(EncoderRequestError::Version); }
    if f.Size as usize != core::mem::size_of::<VM_ENCODER_INPUT>() { return Err(EncoderRequestError::Size); }
    if f.Reserved0 != 0 || f.Reserved1 != 0 { return Err(EncoderRequestError::Reserved); }
    if f.Flags & !VM_ENCODER_INPUT_FORCE_KEYFRAME != 0 { return Err(EncoderRequestError::Flags); }
    if f.SessionToken == 0 || f.SessionToken != c.SessionToken { return Err(EncoderRequestError::SessionToken); }
    if f.YOffset != 0 || f.YStride != c.YStride || f.UVStride != c.UVStride || f.UVOffset != c.UVOffset {
        return Err(EncoderRequestError::PlaneOffset);
    }
    let layout=validate_config(c)?;
    if payload_len < f.DataSize as usize || (f.DataSize as u64) < layout.total as u64 {
        return Err(EncoderRequestError::PayloadLength);
    }
    let yend=(f.YOffset as u64).checked_add(layout.y_end as u64).ok_or(EncoderRequestError::Overflow)?;
    let uvend=(f.UVOffset as u64).checked_add((layout.uv_end-layout.y_end) as u64).ok_or(EncoderRequestError::Overflow)?;
    if yend > f.DataSize as u64 || uvend > f.DataSize as u64 { return Err(EncoderRequestError::PayloadLength); }
    Ok(layout)
}
