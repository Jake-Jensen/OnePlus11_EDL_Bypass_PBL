use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    time::Duration,
};

/// Every call represents one logical transfer. Never impose USB-packet-sized writes.
pub trait Transport: Send {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortInfo {
    pub name: String,
    pub description: String,
    pub edl: bool,
}

pub fn ports() -> Result<Vec<PortInfo>> {
    Ok(serialport::available_ports()?
        .into_iter()
        .map(|p| {
            let (description, edl) = match p.port_type {
                serialport::SerialPortType::UsbPort(u) => (
                    format!(
                        "{:04x}:{:04x} {}",
                        u.vid,
                        u.pid,
                        u.product.unwrap_or_default()
                    ),
                    u.vid == 0x05c6 && matches!(u.pid, 0x9008 | 0x900e),
                ),
                _ => ("Serial interface".into(), false),
            };
            PortInfo {
                name: p.port_name,
                description,
                edl,
            }
        })
        .collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerialSettings {
    pub port: String,
    pub baud: u32,
    pub dtr: bool,
    pub rts: bool,
    pub hardware_flow: bool,
    #[serde(default = "default_wait")]
    pub wait_seconds: u64,
}
fn default_wait() -> u64 {
    30
}
impl Default for SerialSettings {
    fn default() -> Self {
        Self {
            port: "COM3".into(),
            baud: 115200,
            dtr: true,
            rts: true,
            hardware_flow: false,
            wait_seconds: default_wait(),
        }
    }
}

pub struct SerialTransport {
    port: Box<dyn serialport::SerialPort>,
}
impl SerialTransport {
    pub fn open_wait(
        settings: &SerialSettings,
        cancel: &std::sync::atomic::AtomicBool,
        mut waiting: impl FnMut(&str) -> Result<()>,
    ) -> Result<Self> {
        let deadline =
            std::time::Instant::now() + Duration::from_secs(settings.wait_seconds.min(120));
        let mut announced = false;
        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                bail!("Session cancelled before opening device");
            }
            match Self::open(settings) {
                Ok(port) => return Ok(port),
                Err(error) => {
                    let missing = error.downcast_ref::<serialport::Error>().is_some_and(|e| {
                        matches!(
                            e.kind,
                            serialport::ErrorKind::NoDevice
                                | serialport::ErrorKind::Io(std::io::ErrorKind::NotFound)
                        )
                    });
                    if !missing || std::time::Instant::now() >= deadline {
                        return Err(error);
                    }
                    if !announced {
                        waiting(&format!(
                            "Waiting for {} to enumerate ({} s deadline)",
                            settings.port, settings.wait_seconds
                        ))?;
                        announced = true;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    pub fn open(settings: &SerialSettings) -> Result<Self> {
        if settings.port.trim().is_empty() {
            bail!("Select a serial interface first");
        }
        let mut port = serialport::new(&settings.port, settings.baud)
            .timeout(Duration::from_millis(50))
            .flow_control(if settings.hardware_flow {
                serialport::FlowControl::Hardware
            } else {
                serialport::FlowControl::None
            })
            .open()
            .with_context(|| {
                format!(
                    "Opening {}. Close any other tool holding this interface.",
                    settings.port
                )
            })?;
        port.write_data_terminal_ready(settings.dtr)?;
        if !settings.hardware_flow {
            port.write_request_to_send(settings.rts)?;
        }
        // No clear/purge: retain any greeting the Windows driver makes available.
        Ok(Self { port })
    }
}
impl Transport for SerialTransport {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.port.read(data)
    }
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.port.write(data)
    }
}

/// Deterministic transport replay: TX must match exactly; RX may be fragmented.
/// It has no hardware handle and cannot transmit to a device.
pub struct ReplayTransport {
    frames: std::collections::VecDeque<(bool, Vec<u8>)>,
    offset: usize,
    pub writes: usize,
}
impl ReplayTransport {
    pub fn from_events(events: &[crate::capture::Event]) -> Result<Self> {
        let mut frames = std::collections::VecDeque::new();
        for event in events {
            let receive = match event.event.as_str() {
                "RX" | "RX_DATA" => true,
                "TX" => false,
                _ => continue,
            };
            if let Some(ref text) = event.hex {
                let bytes = hex::decode(text)?;
                if !bytes.is_empty() {
                    frames.push_back((receive, bytes));
                }
            }
        }
        Ok(Self {
            frames,
            offset: 0,
            writes: 0,
        })
    }
    pub fn remaining(&self) -> usize {
        self.frames.len()
    }
}
impl Transport for ReplayTransport {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        let Some((receive, bytes)) = self.frames.front() else {
            return Err(std::io::ErrorKind::TimedOut.into());
        };
        if !receive {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let n = data.len().min(bytes.len() - self.offset);
        data[..n].copy_from_slice(&bytes[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset == bytes.len() {
            self.frames.pop_front();
            self.offset = 0;
        }
        Ok(n)
    }
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let Some((receive, expected)) = self.frames.front() else {
            return Err(std::io::Error::other("Replay exhausted before TX"));
        };
        if *receive || self.offset != 0 || expected != data {
            return Err(std::io::Error::other(format!(
                "Replay TX mismatch: {} bytes, expected {}",
                data.len(),
                expected.len()
            )));
        }
        self.frames.pop_front();
        self.writes += 1;
        Ok(data.len())
    }
}
