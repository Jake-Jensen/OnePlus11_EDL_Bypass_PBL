use crate::{capture::Event, transport::Transport};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub fn status_name(status: u32) -> &'static str {
    match status {
        0 => "SUCCESS",
        1 => "INVALID_CMD: invalid command in current state",
        2 => "PROTOCOL_MISMATCH",
        3 => "INVALID_TARGET_PROTOCOL",
        4 => "INVALID_HOST_PROTOCOL",
        5 => "INVALID_PACKET_SIZE",
        6 => "UNEXPECTED_IMAGE_ID",
        7 => "INVALID_HEADER_SIZE",
        8 => "INVALID_DATA_SIZE",
        9 => "INVALID_IMAGE_TYPE",
        10 => "INVALID_TX_LENGTH",
        11 => "INVALID_RX_LENGTH",
        12 => "GENERAL_TX_RX_ERROR",
        13 => "READ_DATA_ERROR",
        14 => "UNSUPPORTED_NUM_PHDRS",
        15 => "INVALID_PHDR_SIZE",
        16 => "MULTIPLE_SHARED_SEGMENTS",
        17 => "UNINITIALIZED_PHDR_LOCATION",
        18 => "INVALID_DESTINATION_ADDRESS",
        19 => "INVALID_IMAGE_HEADER_DATA_SIZE",
        20 => "INVALID_ELF_HEADER",
        21 => "UNKNOWN_HOST_ERROR",
        22 => "TIMEOUT_RX",
        23 => "TIMEOUT_TX",
        24 => "INVALID_HOST_MODE",
        25 => "INVALID_MEMORY_READ",
        26 => "INVALID_DATA_SIZE_REQUEST",
        27 => "MEMORY_DEBUG_NOT_SUPPORTED",
        28 => "INVALID_MODE_SWITCH",
        29 => "COMMAND_EXECUTION_FAILURE",
        30 => "EXEC_INVALID_PARAMETER",
        31 => "EXEC_UNSUPPORTED",
        32 => "EXEC_INVALID_CLIENT_COMMAND",
        33 => "HASH_TABLE_AUTH_FAILURE",
        34 => "SEGMENT_HASH_VERIFICATION_FAILURE",
        35 => "HASH_TABLE_NOT_FOUND",
        36 => "TARGET_INIT_FAILURE",
        37 => "IMAGE_AUTH_FAILURE",
        38 => "INVALID_IMAGE_HASH_TABLE_SIZE",
        39 => "ENUMERATION_FAILURE",
        40 => "HARDWARE_BULK_TRANSFER_ERROR",
        _ => "UNKNOWN_STATUS",
    }
}

fn u32at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|n| n.to_le_bytes()).collect()
}
pub fn hello_response(version: u32, minimum: u32, mode: u32) -> Vec<u8> {
    words(&[2, 48, version, minimum, 0, mode, 0, 0, 0, 0, 0, 0])
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Packet {
    Hello {
        version: u32,
        minimum: u32,
        max_command: u32,
        mode: u32,
    },
    Read {
        image: u64,
        offset: u64,
        length: u64,
    },
    End {
        image: u32,
        status: u32,
    },
    CommandReady,
    ExecuteResponse {
        command: u32,
        length: u32,
    },
    DoneResponse {
        status: u32,
    },
    Other {
        command: u32,
    },
}
impl Packet {
    pub fn decode(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() >= 8,
            "Sahara header truncated: {} bytes",
            data.len()
        );
        let command = u32at(data, 0);
        let size = u32at(data, 4) as usize;
        ensure!(
            size == data.len(),
            "Sahara length mismatch: declared {size}, received {}",
            data.len()
        );
        let need = match command {
            1 => 48,
            3 => 20,
            4 => 16,
            6 => 12,
            11 => 8,
            14 => 16,
            18 => 32,
            _ => 8,
        };
        ensure!(
            data.len() >= need,
            "Sahara command 0x{command:x} is truncated"
        );
        if matches!(command, 1 | 3 | 4 | 6 | 11 | 14 | 18) {
            ensure!(
                data.len() == need,
                "Unexpected length for Sahara command 0x{command:x}"
            );
        }
        Ok(match command {
            1 => {
                ensure!(size == 48, "Invalid HELLO length");
                Self::Hello {
                    version: u32at(data, 8),
                    minimum: u32at(data, 12),
                    max_command: u32at(data, 16),
                    mode: u32at(data, 20),
                }
            }
            3 => Self::Read {
                image: u32at(data, 8) as u64,
                offset: u32at(data, 12) as u64,
                length: u32at(data, 16) as u64,
            },
            18 => Self::Read {
                image: u64at(data, 8),
                offset: u64at(data, 16),
                length: u64at(data, 24),
            },
            4 => Self::End {
                image: u32at(data, 8),
                status: u32at(data, 12),
            },
            11 => Self::CommandReady,
            14 => Self::ExecuteResponse {
                command: u32at(data, 8),
                length: u32at(data, 12),
            },
            6 => Self::DoneResponse {
                status: u32at(data, 8),
            },
            _ => Self::Other { command },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum State {
    Disconnected,
    AwaitHello,
    AwaitCommandReady,
    Command,
    AwaitImageHello,
    ImageTransfer,
    AwaitDone,
    Complete,
    Rejected,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Options {
    pub timeout_ms: u64,
    pub missed_hello: bool,
    pub recovered_v3: bool,
    pub identity: bool,
    pub upload: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            timeout_ms: 1500,
            missed_hello: true,
            recovered_v3: true,
            identity: true,
            upload: false,
        }
    }
}

pub struct Client<T, F>
where
    T: Transport,
    F: FnMut(Event) -> Result<()>,
{
    transport: T,
    observer: F,
    pub state: State,
    options: Options,
    cancel: Arc<AtomicBool>,
    pub transferred: u64,
}
impl<T: Transport, F: FnMut(Event) -> Result<()>> Client<T, F> {
    pub fn new(transport: T, options: Options, cancel: Arc<AtomicBool>, observer: F) -> Self {
        Self {
            transport,
            observer,
            state: State::Disconnected,
            options,
            cancel,
            transferred: 0,
        }
    }
    fn transition(&mut self, next: State) -> Result<()> {
        use State::*;
        let valid = matches!(
            (self.state, next),
            (Disconnected, AwaitHello)
                | (AwaitHello, AwaitCommandReady)
                | (AwaitCommandReady, Command)
                | (Command, AwaitImageHello)
                | (AwaitImageHello, ImageTransfer)
                | (ImageTransfer, AwaitDone)
                | (AwaitDone, ImageTransfer)
                | (AwaitDone, Complete)
                | (ImageTransfer, ImageTransfer)
                | (Command, Complete)
                | (AwaitImageHello, Complete)
        ) || matches!(next, Rejected | Cancelled);
        ensure!(
            valid,
            "Invalid Sahara transition {:?} -> {next:?}",
            self.state
        );
        self.state = next;
        self.emit(Event::message("STATE", format!("{next:?}")))
    }
    fn emit(&mut self, event: Event) -> Result<()> {
        (self.observer)(event)
    }
    fn check_cancel(&mut self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            self.transition(State::Cancelled)?;
            bail!("Session cancelled; no further commands sent");
        }
        Ok(())
    }
    fn read_exact(&mut self, size: usize, allow_silence: bool) -> Result<Option<Vec<u8>>> {
        let mut bytes = vec![0; size];
        let mut count = 0;
        let deadline = Instant::now() + Duration::from_millis(self.options.timeout_ms);
        while count < size {
            self.check_cancel()?;
            match self.transport.read(&mut bytes[count..]) {
                Ok(n) => count += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    if count > 0 {
                        self.emit(Event::packet(
                            "RX_PARTIAL",
                            &bytes[..count],
                            "Transport failed during reception",
                        ))?;
                    }
                    return Err(e.into());
                }
            }
            if Instant::now() >= deadline && count < size {
                if count == 0 && allow_silence {
                    return Ok(None);
                }
                if count > 0 {
                    self.emit(Event::packet(
                        "RX_PARTIAL",
                        &bytes[..count],
                        "Incomplete reception",
                    ))?;
                }
                bail!("Reception timed out: {count}/{size} bytes; no cross-protocol probes sent");
            }
        }
        Ok(Some(bytes))
    }
    fn receive(&mut self, allow_silence: bool) -> Result<Option<Packet>> {
        let Some(mut bytes) = self.read_exact(8, allow_silence)? else {
            return Ok(None);
        };
        if bytes.starts_with(b"<?xml") {
            self.emit(Event::packet(
                "RX",
                &bytes,
                "Existing Firehose XML detected",
            ))?;
            bail!(
                "Device is already emitting Firehose XML. Sahara session stopped; storage commands disabled."
            );
        }
        let size = u32at(&bytes, 4) as usize;
        ensure!(
            (8..=65536).contains(&size),
            "Invalid Sahara packet length {size}; header {}",
            hex::encode(bytes)
        );
        if size > 8 {
            bytes.extend(self.read_exact(size - 8, false)?.unwrap());
        }
        let packet = Packet::decode(&bytes)?;
        self.emit(Event::packet("RX", &bytes, format!("{packet:?}")))?;
        if let Packet::End { image, status } = packet
            && status != 0
        {
            self.transition(State::Rejected)?;
            bail!(
                "END_IMAGE_TX: image {image}, status 0x{status:02x} — {}. Programmer bytes sent: {}",
                status_name(status),
                self.transferred
            );
        }
        Ok(Some(packet))
    }
    fn send(&mut self, bytes: &[u8], summary: &str) -> Result<()> {
        self.check_cancel()?;
        self.emit(Event::packet("TX_BEGIN", bytes, summary))?;
        let mut count = 0;
        // The first underlying write contains the entire logical transfer.
        // Retry only an explicitly reported partial write, never 512-byte chunks.
        while count < bytes.len() {
            self.check_cancel()?;
            let n = self.transport.write(&bytes[count..])?;
            ensure!(
                n > 0 && n <= bytes.len() - count,
                "Serial write made no valid progress"
            );
            self.emit(Event {
                details: Some(json!({"requested":bytes.len()-count,"accepted":n})),
                ..Event::message("WRITE", format!("Accepted {n} bytes"))
            })?;
            count += n;
        }
        self.emit(Event::packet("TX", bytes, summary))
    }
    fn execute(&mut self, command: u32) -> Result<Vec<u8>> {
        ensure!(
            self.state == State::Command,
            "Execute requires command mode"
        );
        self.send(&words(&[13, 12, command]), "EXECUTE_REQ")?;
        let response = self.receive(false)?.unwrap();
        let Packet::ExecuteResponse {
            command: echo,
            length,
        } = response
        else {
            bail!("Expected EXECUTE_RSP, received {response:?}");
        };
        ensure!(
            echo == command && length > 0 && length <= 65536,
            "Invalid EXECUTE_RSP command/length"
        );
        self.send(&words(&[15, 12, command]), "EXECUTE_DATA")?;
        let bytes = self.read_exact(length as usize, false)?.unwrap();
        self.emit(Event::packet(
            "RX_DATA",
            &bytes,
            format!("Command 0x{command:x} payload"),
        ))?;
        Ok(bytes)
    }
    fn hello(&mut self, p: Packet, mode: u32) -> Result<u32> {
        let Packet::Hello {
            version,
            minimum,
            mode: target_mode,
            ..
        } = p
        else {
            bail!("Expected HELLO_REQ; received {p:?}");
        };
        ensure!(
            minimum <= version && minimum <= 3 && version >= 1,
            "Unsupported target Sahara range {minimum}..{version}"
        );
        ensure!(
            target_mode != 2,
            "Target is in memory-debug mode; automatic memory access is disabled"
        );
        let selected = version.min(3);
        self.send(
            &hello_response(selected, minimum, mode),
            "HELLO_RSP (zero reserved fields)",
        )?;
        Ok(selected)
    }
    pub fn run(&mut self, images: &BTreeMap<u64, Arc<Vec<u8>>>) -> Result<State> {
        self.transition(State::AwaitHello)?;
        let greeting = self.receive(true)?;
        let (version, recovered) = if let Some(greeting) = greeting {
            let version = self.hello(greeting, 3)?;
            (version, false)
        } else {
            ensure!(
                self.options.missed_hello,
                "No greeting; recovery is disabled"
            );
            self.emit(Event::message(
                "RECOVERY",
                "Missed HELLO: verified command-mode HELLO_RSP v2/min2",
            ))?;
            self.send(&hello_response(2, 2, 3), "Missed-HELLO recovery")?;
            (2, true)
        };
        self.transition(State::AwaitCommandReady)?;
        ensure!(
            self.receive(false)? == Some(Packet::CommandReady),
            "Expected CMD_READY"
        );
        self.transition(State::Command)?;
        if self.options.identity {
            let serial = self.execute(1)?;
            self.emit(Event {
                details: Some(json!({"serial_hex":hex::encode(&serial)})),
                ..Event::message(
                    "DEVICE",
                    format!("Serial payload: {}", hex::encode(&serial)),
                )
            })?;
            let use_v3 = version >= 3 || (recovered && self.options.recovered_v3);
            if use_v3 {
                let data = self.execute(10)?;
                ensure!(data.len() >= 44, "V3 chip identity is truncated");
                let msm = u32at(&data, 36);
                let mut oem = u16::from_le_bytes(data[40..42].try_into().unwrap());
                if oem == 0 && data.len() >= 46 {
                    oem = u16::from_le_bytes(data[44..46].try_into().unwrap());
                }
                let model = u16::from_le_bytes(data[42..44].try_into().unwrap());
                let descriptor = crate::catalog::descriptor_for_msm(msm);
                self.emit(Event {
                    details: Some(
                        json!({"msm":msm,"oem":oem,"model":model,"descriptor":descriptor,"raw":hex::encode(data)}),
                    ),
                    ..Event::message(
                        "DEVICE",
                        format!("{} · MSM 0x{msm:08x} · OEM 0x{oem:04x} · Model 0x{model:04x}", descriptor.unwrap_or("Unknown chipset")),
                    )
                })?;
            } else {
                let data = self.execute(2)?;
                self.emit(Event::packet("DEVICE", &data, "V2 hardware identity"))?;
            }
            // Never issue legacy PK hash / HW-ID probes on a known V3 target.
        }
        self.send(
            &words(&[12, 12, 3]),
            "SWITCH_MODE(command): request real image greeting",
        )?;
        self.transition(State::AwaitImageHello)?;
        let image_hello = self.receive(false)?.unwrap();
        if !self.options.upload {
            self.transition(State::Complete)?;
            return Ok(self.state);
        }
        ensure!(!images.is_empty(), "No programmer mapping selected");
        self.hello(image_hello, 0)?;
        self.transition(State::ImageTransfer)?;
        let mut requests = 0usize;
        loop {
            self.check_cancel()?;
            requests += 1;
            ensure!(
                requests <= 100000,
                "Excessive Sahara requests; session stopped"
            );
            let packet = self.receive(false)?.unwrap();
            match packet {
                Packet::Read {
                    image,
                    offset,
                    length,
                } => {
                    let data = images.get(&image).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Target requested unmapped image ID {image}; no guessed mapping used"
                        )
                    })?;
                    let end = offset
                        .checked_add(length)
                        .ok_or_else(|| anyhow::anyhow!("Requested range overflow"))?;
                    ensure!(
                        length > 0 && length <= 32 * 1024 * 1024 && end <= data.len() as u64,
                        "Invalid requested range: image {image}, offset 0x{offset:x}, length {length}, file {}",
                        data.len()
                    );
                    let payload = &data[offset as usize..end as usize];
                    self.send(
                        payload,
                        &format!("Image {image}, offset 0x{offset:x}, {length} bytes"),
                    )?;
                    self.transferred += length;
                    self.emit(Event {details:Some(json!({"image":image,"offset":offset,"requested":length,"transferred":self.transferred,"file_size":data.len(),"end":end})),
                        ..Event::message("PROGRESS",format!("{} bytes supplied · offset 0x{offset:x}",self.transferred))})?;
                }
                Packet::End { status: 0, .. } => {
                    self.transition(State::AwaitDone)?;
                    self.send(&words(&[5, 8]), "DONE_REQ")?;
                    match self.receive(false)?.unwrap() {
                        Packet::DoneResponse { status: 1 } => {
                            self.transition(State::Complete)?;
                            self.emit(Event::message("COMPLETE","Sahara upload completed. Stopped before Firehose/storage commands."))?;
                            return Ok(self.state);
                        }
                        Packet::DoneResponse { status: 0 } => {
                            self.transition(State::ImageTransfer)?
                        }
                        other => bail!("Unexpected DONE response: {other:?}"),
                    }
                }
                p @ Packet::Hello { .. } => {
                    self.hello(p, 0)?;
                }
                other => bail!("Unexpected packet in image-transfer state: {other:?}"),
            }
        }
    }
}
