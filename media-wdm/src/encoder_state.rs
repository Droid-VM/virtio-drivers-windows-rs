use crate::encoder_abi::{validate_config, validate_input, EncoderRequestError, Nv12Layout};
use crate::vmedia_abi::{VM_ENCODER_CONFIG, VM_ENCODER_INPUT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderOwner {
    pub open: bool,
    pub host_id: u32,
    pub token: u32,
    /// Opaque WDFFILEOBJECT identity; never dereferenced by the pure state model.
    pub file_object: usize,
}
impl EncoderOwner {
    pub const fn empty() -> Self {
        Self { open: false, host_id: 0, token: 0, file_object: 0 }
    }

    pub fn install(&mut self, host_id: u32, token: u32) -> Result<(), EncoderStateError> {
        if self.open {
            return Err(EncoderStateError::AlreadyConfigured);
        }
        if token == 0 {
            return Err(EncoderStateError::BadRequest(EncoderRequestError::SessionToken));
        }
        self.open = true;
        self.host_id = host_id;
        self.token = token;
        Ok(())
    }

    pub fn bind_file(&mut self,token:u32,file_object:usize)->bool {
        if !self.owns(token)||file_object==0||self.file_object!=0{return false}
        self.file_object=file_object;true
    }
    pub fn owns_file(&self,file_object:usize)->bool {
        self.open&&file_object!=0&&self.file_object==file_object
    }

    pub fn owns(&self, token: u32) -> bool {
        self.open && token != 0 && self.token == token
    }

    pub fn clear(&mut self, token: u32) -> bool {
        if !self.owns(token) {
            return false;
        }
        *self = Self::empty();
        true
    }
}

pub const MAX_ENCODER_INPUTS: usize = 8;
pub const MAX_ENCODER_OUTPUTS: usize = 8;
pub const MAX_ENCODER_POOL_RANGES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolRangeError { Full, ZeroLength, Overflow, OutOfPool, Overlap, UnknownRange }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderPoolRange { pub id:u32, pub driver_addr:u64, pub offset:u64, pub len:u64, pub mem_offset:u32, pub buffer_len:u32, pub kind:u8, pub live:bool }
impl EncoderPoolRange { const EMPTY:Self=Self{id:0,driver_addr:0,offset:0,len:0,mem_offset:0,buffer_len:0,kind:0,live:false}; }

/// Tracks host-returned VIRTIO_MEDIA_CMD_MMAP ranges for encoder resources.
/// The host allocator remains authoritative; this table validates bounds and
/// prevents aliasing before the driver exposes/copies packet memory.
#[derive(Clone, Copy)]
pub struct EncoderPoolRanges { pool_size:u64, entries:[EncoderPoolRange;MAX_ENCODER_POOL_RANGES] }
impl EncoderPoolRanges {
    pub const fn new(pool_size:u64)->Self{Self{pool_size,entries:[EncoderPoolRange::EMPTY;MAX_ENCODER_POOL_RANGES]}}
    pub fn insert(&mut self,id:u32,kind:u8,driver_addr:u64,offset:u64,len:u64,mem_offset:u32,buffer_len:u32)->Result<(),PoolRangeError>{
        if len==0{return Err(PoolRangeError::ZeroLength)}
        let end=offset.checked_add(len).ok_or(PoolRangeError::Overflow)?;
        if end>self.pool_size{return Err(PoolRangeError::OutOfPool)}
        for r in self.entries.iter().filter(|r|r.live){
            if r.id==id&&r.kind==kind{return Err(PoolRangeError::Overlap)}
            let r_end=r.offset.checked_add(r.len).ok_or(PoolRangeError::Overflow)?;
            if offset<r_end&&r.offset<end{return Err(PoolRangeError::Overlap)}
        }
        let Some(slot)=self.entries.iter_mut().find(|r|!r.live)else{return Err(PoolRangeError::Full)};
        if buffer_len==0{return Err(PoolRangeError::ZeroLength)}
        *slot=EncoderPoolRange{id,driver_addr,offset,len,mem_offset,buffer_len,kind,live:true};Ok(())
    }
    pub fn remove(&mut self,id:u32,kind:u8)->Result<EncoderPoolRange,PoolRangeError>{
        let Some(slot)=self.entries.iter_mut().find(|r|r.live&&r.id==id&&r.kind==kind)else{return Err(PoolRangeError::UnknownRange)};
        let out=*slot;*slot=EncoderPoolRange::EMPTY;Ok(out)
    }
    pub fn pop_any(&mut self)->Option<EncoderPoolRange>{
        let slot=self.entries.iter_mut().find(|r|r.live)?;let out=*slot;*slot=EncoderPoolRange::EMPTY;Some(out)
    }
    pub fn len(&self)->usize{self.entries.iter().filter(|r|r.live).count()}
    pub fn count_kind(&self,kind:u8)->usize{self.entries.iter().filter(|r|r.live&&r.kind==kind).count()}
    pub fn range(&self,id:u32,kind:u8)->Option<EncoderPoolRange>{self.entries.iter().find(|r|r.live&&r.id==id&&r.kind==kind).copied()}
    pub fn is_empty(&self)->bool{self.len()==0}
    pub fn clear(&mut self){self.entries=[EncoderPoolRange::EMPTY;MAX_ENCODER_POOL_RANGES];}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderStateError {
    NotConfigured,
    AlreadyConfigured,
    InvalidCapacity,
    DuplicateInputId,
    UnknownInputId,
    Draining,
    AlreadyDraining,
    QueueFull,
    CounterOverflow,
    NoInput,
    DrainNotPending,
    PacketPending,
    QueueConfig,
    BadRequest(EncoderRequestError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderPendingPacket {
    pub index:u32,
    pub bytesused:u32,
    pub timestamp_us:u64,
    pub timestamp_valid:bool,
    pub keyframe:bool,
    pub last:bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderQueueConfig {
    pub input_type:u32,
    pub output_type:u32,
    pub input_count:u32,
    pub output_count:u32,
    pub input_sizeimage:u32,
    pub output_sizeimage:u32,
    pub streamon_mask:u8,
}

pub const V4L2_ENCODER_OUTPUT_MPLANE:u32=10;
pub const V4L2_ENCODER_CAPTURE_MPLANE:u32=9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderCounters {
    pub accepted_inputs: u32,
    pub completed_inputs: u32,
    pub completed_packets: u32,
    pub drain_pending: bool,
    pub queues_configured: bool,
    pub input_buffer_count: u32,
    pub output_buffer_count: u32,
    pub terminal_error: u32,
}

/// Per-session admission model. Host calls/events are intentionally left to E3;
/// this helper makes the guest's bounded ownership transitions testable first.
pub struct EncoderSlot {
    configured: bool,
    draining: bool,
    drained: bool,
    empty_drain_pending: bool,
    format_ready: bool,
    input_sizeimage: u32,
    input_stride: u32,
    output_sizeimage: u32,
    queues: Option<EncoderQueueConfig>,
    pending_packet: Option<EncoderPendingPacket>,
    pool_ranges: EncoderPoolRanges,
    input_buffer_count: u32,
    output_buffer_count: u32,
    config: VM_ENCODER_CONFIG,
    layout: Nv12Layout,
    input_capacity: usize,
    input_ids: [u32; MAX_ENCODER_INPUTS],
    input_used: [bool; MAX_ENCODER_INPUTS],
    inputs_accepted: u32,
    inputs_completed: u32,
    packets_completed: u32,
    terminal_error: u32,
}

impl EncoderSlot {
    pub const fn new(input_capacity: usize) -> Self {
        Self { configured:false, draining:false, drained:false, empty_drain_pending:false, format_ready:false,input_sizeimage:0,input_stride:0,output_sizeimage:0,queues:None,pending_packet:None,pool_ranges:EncoderPoolRanges::new(0),input_buffer_count:0,output_buffer_count:0, config: VM_ENCODER_CONFIG {
            Version:0,Size:0,SessionToken:0,Width:0,Height:0,YStride:0,UVStride:0,
            UVOffset:0,FrameRateNum:0,FrameRateDen:0,Bitrate:0,GopFrames:0,Flags:0,Reserved0:0 },
            layout:Nv12Layout { y_end:0, uv_end:0, total:0 }, input_capacity,
            input_ids:[0;MAX_ENCODER_INPUTS],input_used:[false;MAX_ENCODER_INPUTS],
            inputs_accepted:0,inputs_completed:0,packets_completed:0,terminal_error:0 }
    }

    pub fn configure(&mut self, config: &VM_ENCODER_CONFIG) -> Result<Nv12Layout, EncoderStateError> {
        if self.configured { return Err(EncoderStateError::AlreadyConfigured); }
        if config.SessionToken == 0 { return Err(EncoderStateError::BadRequest(EncoderRequestError::SessionToken)); }
        if self.input_capacity==0 || self.input_capacity>MAX_ENCODER_INPUTS { return Err(EncoderStateError::InvalidCapacity); }
        let layout=validate_config(config).map_err(EncoderStateError::BadRequest)?;
        self.configured=true;self.config=*config;self.layout=layout;
        self.format_ready=false;self.input_sizeimage=0;self.input_stride=0;self.output_sizeimage=0;
        self.queues=None;self.pending_packet=None;self.input_buffer_count=0;self.output_buffer_count=0;
        self.draining=false;self.drained=false;self.empty_drain_pending=false;self.inputs_accepted=0;self.inputs_completed=0;
        self.input_ids=[0;MAX_ENCODER_INPUTS];self.input_used=[false;MAX_ENCODER_INPUTS];
        self.packets_completed=0;self.terminal_error=0;
        Ok(layout)
    }

    pub fn abort_configure(&mut self){
        self.configured=false;self.format_ready=false;self.input_sizeimage=0;self.input_stride=0;
        self.output_sizeimage=0;self.queues=None;self.pending_packet=None;self.pool_ranges.clear();self.input_buffer_count=0;
        self.output_buffer_count=0;self.input_ids=[0;MAX_ENCODER_INPUTS];self.input_used=[false;MAX_ENCODER_INPUTS];
        self.inputs_accepted=0;self.inputs_completed=0;self.packets_completed=0;self.draining=false;self.drained=false;self.empty_drain_pending=false;
    }

    pub fn set_negotiated_formats(&mut self,input_stride:u32,input_sizeimage:u32,output_sizeimage:u32)->Result<(),EncoderStateError>{
        if !self.configured{return Err(EncoderStateError::NotConfigured)}
        if input_stride<self.config.YStride||output_sizeimage==0{return Err(EncoderStateError::QueueConfig)}
        let mut config=self.config;
        config.YStride=input_stride;config.UVStride=input_stride;
        config.UVOffset=input_stride.checked_mul(config.Height).ok_or(EncoderStateError::CounterOverflow)?;
        let layout=validate_config(&config).map_err(EncoderStateError::BadRequest)?;
        if input_sizeimage<layout.total{return Err(EncoderStateError::QueueConfig)}
        self.config=config;self.layout=layout;
        self.input_stride=input_stride;self.input_sizeimage=input_sizeimage;self.output_sizeimage=output_sizeimage;self.format_ready=true;Ok(())
    }
    pub fn negotiated_sizes(&self)->Option<(u32,u32,u32)>{if self.format_ready{Some((self.input_stride,self.input_sizeimage,self.output_sizeimage))}else{None}}

    pub fn configure_queues(&mut self,q:EncoderQueueConfig,ranges:&EncoderPoolRanges)->Result<(),EncoderStateError>{
        if !self.configured{return Err(EncoderStateError::NotConfigured)}
        if !self.format_ready{return Err(EncoderStateError::QueueConfig)}
        if self.queues.is_some(){return Err(EncoderStateError::AlreadyConfigured)}
        let total=(q.input_count as usize).checked_add(q.output_count as usize).ok_or(EncoderStateError::CounterOverflow)?;
        if q.input_sizeimage<self.input_sizeimage||q.output_sizeimage<self.output_sizeimage{return Err(EncoderStateError::QueueConfig)}
        let expected_input=(self.layout.total as u64).min(u32::MAX as u64) as u32;
        if q.input_type!=V4L2_ENCODER_OUTPUT_MPLANE||q.output_type!=V4L2_ENCODER_CAPTURE_MPLANE
            ||q.input_count==0||q.input_count as usize>MAX_ENCODER_INPUTS
            ||q.output_count==0||q.output_count as usize>MAX_ENCODER_OUTPUTS
            ||q.input_sizeimage<expected_input||q.output_sizeimage==0||q.streamon_mask!=2
            ||ranges.len()<total||ranges.count_kind(0)<q.input_count as usize
            ||ranges.count_kind(1)<q.output_count as usize{return Err(EncoderStateError::QueueConfig)}
        self.input_capacity=q.input_count as usize;self.input_buffer_count=q.input_count;
        self.output_buffer_count=q.output_count;self.pool_ranges=*ranges;self.queues=Some(q);Ok(())
    }

    pub fn mark_input_streaming(&mut self)->Result<(),EncoderStateError>{
        let Some(mut q)=self.queues else{return Err(EncoderStateError::QueueConfig)};
        if q.streamon_mask&2==0{return Err(EncoderStateError::QueueConfig)}
        if q.streamon_mask&1!=0{return Err(EncoderStateError::AlreadyConfigured)}
        q.streamon_mask|=1;self.queues=Some(q);Ok(())
    }
    pub fn clear_input_streaming(&mut self){if let Some(mut q)=self.queues{q.streamon_mask&=!1;self.queues=Some(q)}}

    pub fn queue_input(&mut self, frame: &VM_ENCODER_INPUT, payload_len: usize) -> Result<u32, EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if frame.SessionToken!=self.config.SessionToken{return Err(EncoderStateError::BadRequest(EncoderRequestError::SessionToken))}
        if self.queues.map(|q|q.streamon_mask&2!=0).unwrap_or(false)==false{return Err(EncoderStateError::QueueConfig)}
        if self.draining || self.drained { return Err(EncoderStateError::Draining); }
        validate_input(&self.config,frame,payload_len).map_err(EncoderStateError::BadRequest)?;
        if self.input_ids.iter().zip(self.input_used.iter()).any(|(&id,&used)| used && id==frame.BufferId) {
            return Err(EncoderStateError::DuplicateInputId);
        }
        let Some(index)=self.input_used[..self.input_capacity].iter().position(|used| !*used) else {
            return Err(EncoderStateError::QueueFull);
        };
        self.inputs_accepted=self.inputs_accepted.checked_add(1).ok_or(EncoderStateError::CounterOverflow)?;
        self.input_ids[index]=frame.BufferId;self.input_used[index]=true;
        Ok(frame.BufferId)
    }

    pub fn input_slot(&self,buffer_id:u32)->Option<u32>{
        self.input_ids[..self.input_capacity].iter().zip(self.input_used[..self.input_capacity].iter())
            .position(|(&id,&used)|used&&id==buffer_id).map(|i|i as u32)
    }
    pub fn input_buffer_id(&self,slot:u32)->Option<u32>{
        self.input_ids.get(slot as usize).copied().filter(|_|self.input_used.get(slot as usize).copied().unwrap_or(false))
    }

    pub fn cancel_input(&mut self,buffer_id:u32)->Result<(),EncoderStateError>{
        if !self.configured{return Err(EncoderStateError::NotConfigured)}
        let Some(index)=self.input_ids[..self.input_capacity].iter().zip(self.input_used[..self.input_capacity].iter())
            .position(|(&id,&used)|used&&id==buffer_id)else{return Err(EncoderStateError::UnknownInputId)};
        self.input_used[index]=false;self.input_ids[index]=0;
        self.inputs_accepted=self.inputs_accepted.saturating_sub(1);Ok(())
    }

    pub fn input_done(&mut self, buffer_id:u32) -> Result<(), EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if self.queues.is_none(){return Err(EncoderStateError::QueueConfig)}
        let Some(index)=self.input_ids[..self.input_capacity].iter().zip(self.input_used[..self.input_capacity].iter())
            .position(|(&id,&used)|used && id==buffer_id) else { return Err(EncoderStateError::UnknownInputId); };
        self.input_used[index]=false;self.input_ids[index]=0;
        self.inputs_completed=self.inputs_completed.checked_add(1).ok_or(EncoderStateError::CounterOverflow)?;
        Ok(())
    }

    pub fn packet_done(&mut self) -> Result<u32, EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if self.queues.is_none(){return Err(EncoderStateError::QueueConfig)}
        self.packets_completed=self.packets_completed.checked_add(1).ok_or(EncoderStateError::CounterOverflow)?;Ok(self.packets_completed)
    }

    pub fn begin_drain(&mut self) -> Result<(), EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if self.queues.is_none() { return Err(EncoderStateError::QueueConfig); }
        if self.draining || self.drained { return Err(EncoderStateError::AlreadyDraining); }
        self.draining=true;
        self.empty_drain_pending=self.inputs_accepted==0;
        Ok(())
    }

    pub fn complete_drain(&mut self) -> Result<(), EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if !self.draining { return Err(EncoderStateError::DrainNotPending); }
        self.draining=false;self.drained=true;self.empty_drain_pending=false;Ok(())
    }

    pub fn cancel_drain(&mut self) {
        if !self.drained { self.draining=false;self.empty_drain_pending=false; }
    }
    pub fn empty_drain_pending(&self)->bool { self.empty_drain_pending }
    pub fn is_drained(&self)->bool { self.drained }

    pub fn flush(&mut self, replacement_token: u32) -> Result<(), EncoderStateError> {
        if !self.configured { return Err(EncoderStateError::NotConfigured); }
        if replacement_token==0 || replacement_token==self.config.SessionToken {
            return Err(EncoderStateError::BadRequest(EncoderRequestError::SessionToken));
        }
        self.config.SessionToken=replacement_token;self.draining=false;self.drained=false;self.empty_drain_pending=false;self.queues=None;self.pending_packet=None;self.pool_ranges.clear();self.input_buffer_count=0;self.output_buffer_count=0;self.inputs_accepted=0;
        self.inputs_completed=0;self.input_ids=[0;MAX_ENCODER_INPUTS];self.input_used=[false;MAX_ENCODER_INPUTS];
        self.packets_completed=0;self.terminal_error=0;
        Ok(())
    }

    pub fn counters(&self) -> EncoderCounters {
        EncoderCounters { accepted_inputs:self.inputs_accepted,
            completed_inputs:self.inputs_completed,completed_packets:self.packets_completed,
            drain_pending:self.draining,queues_configured:self.queues.is_some(),
            input_buffer_count:self.input_buffer_count,output_buffer_count:self.output_buffer_count,
            terminal_error:self.terminal_error }
    }
    pub fn layout(&self) -> Nv12Layout { self.layout }
    pub fn token(&self) -> u32 { self.config.SessionToken }
    pub fn negotiated_config(&self) -> VM_ENCODER_CONFIG { self.config }
    pub fn set_bitrate(&mut self,bitrate:u32){self.config.Bitrate=bitrate;}
    pub fn queue_config(&self)->Option<EncoderQueueConfig>{self.queues}
    pub fn set_pending_packet(&mut self,p:EncoderPendingPacket)->Result<(),EncoderStateError>{
        if self.pending_packet.is_some(){return Err(EncoderStateError::PacketPending)}
        self.pending_packet=Some(p);Ok(())
    }
    pub fn pending_packet(&self)->Option<EncoderPendingPacket>{self.pending_packet}
    pub fn clear_pending_packet(&mut self,index:u32)->bool{
        if self.pending_packet.map(|p|p.index)==Some(index){self.pending_packet=None;true}else{false}
    }
    pub fn pool_range(&self,id:u32,kind:u8)->Option<EncoderPoolRange>{self.pool_ranges.range(id,kind)}
    pub fn take_pool_range(&mut self)->Option<EncoderPoolRange>{self.pool_ranges.pop_any()}
}
