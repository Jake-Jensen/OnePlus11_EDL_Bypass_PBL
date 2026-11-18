use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub time: String,
    pub event: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(default)]
    pub size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}
impl Event {
    pub fn message(kind: &str, message: impl Into<String>) -> Self {
        Self {
            time: chrono::Local::now().to_rfc3339(),
            event: kind.into(),
            summary: message.into(),
            hex: None,
            size: 0,
            details: None,
        }
    }
    pub fn packet(kind: &str, bytes: &[u8], summary: impl Into<String>) -> Self {
        Self {
            hex: Some(hex::encode(bytes)),
            size: bytes.len(),
            ..Self::message(kind, summary)
        }
    }
}

pub struct Recorder {
    file: File,
    pub path: PathBuf,
}
impl Recorder {
    pub fn create(folder: &Path) -> Result<Self> {
        std::fs::create_dir_all(folder)?;
        let path = folder.join(format!(
            "session-{}.jsonl",
            chrono::Local::now().format("%Y%m%d-%H%M%S-%f")
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        Ok(Self { file, path })
    }
    pub fn append(&mut self, event: &Event) -> Result<()> {
        serde_json::to_writer(&mut self.file, event)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(())
    }
}

pub fn load(path: &Path) -> Result<Vec<Event>> {
    let mut result = Vec::new();
    for (index, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > 128 * 1024 * 1024 {
            bail!("Capture line {} exceeds 128 MiB", index + 1);
        }
        let raw: Value = serde_json::from_str(&line)
            .with_context(|| format!("Invalid JSON at capture line {}", index + 1))?;
        let kind = raw["event"].as_str().unwrap_or("NOTE");
        let data = raw["hex"].as_str().map(str::to_owned);
        if let Some(ref data) = data {
            hex::decode(data).with_context(|| format!("Invalid hex at line {}", index + 1))?;
        }
        let summary = raw["summary"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if let Some(ref hex) = data {
                    decode_summary(&hex::decode(hex).unwrap_or_default())
                } else {
                    raw.to_string()
                }
            });
        result.push(Event {
            time: raw["time"].as_str().unwrap_or("").into(),
            event: kind.into(),
            summary,
            size: raw["size"].as_u64().unwrap_or(0) as usize,
            hex: data,
            details: Some(raw),
        });
    }
    // Python records a serial header and its body as separate RX events.
    // Annotate them as one protocol packet without altering the recorded bytes.
    let mut pending: Option<Vec<u8>> = None;
    for event in &mut result {
        if event.event != "RX" {
            continue;
        }
        let Some(ref text) = event.hex else {
            continue;
        };
        let Ok(bytes) = hex::decode(text) else {
            continue;
        };
        if let Some(mut header) = pending.take() {
            let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
            if bytes.len() + 8 == length {
                header.extend_from_slice(&bytes);
                event.summary = decode_summary(&header);
                continue;
            }
        }
        if bytes.len() == 8 {
            let command = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            if matches!(command, 1 | 3 | 4 | 6 | 14 | 18) && (9..=65536).contains(&length) {
                event.summary = format!("Sahara header: command 0x{command:02x}, length {length}");
                pending = Some(bytes);
            }
        }
    }
    Ok(result)
}

pub fn decode_summary(data: &[u8]) -> String {
    match crate::protocol::Packet::decode(data) {
        Ok(crate::protocol::Packet::End { image, status }) => format!(
            "END_IMAGE_TX · image {image} · status 0x{status:02x} {}",
            crate::protocol::status_name(status)
        ),
        Ok(crate::protocol::Packet::Read {
            image,
            offset,
            length,
        }) => format!("READ_DATA · image {image} · offset 0x{offset:x} · {length} bytes"),
        Ok(p) => format!("{p:?}"),
        Err(_) => format!("{} raw bytes", data.len()),
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TransferCheck {
    pub image_id: u64,
    pub offset: u64,
    pub requested: u64,
    pub sent: usize,
    pub matches: bool,
}

/// Accept both native records and Python's separate header/body RX events.
pub fn verify_transfers(events: &[Event], image: &[u8]) -> Vec<TransferCheck> {
    let mut checks = Vec::new();
    let mut pending: Option<usize> = None;
    let mut expect_read64_body = false;
    let mut expect_read32_body = false;
    for event in events {
        let Some(ref text) = event.hex else {
            continue;
        };
        let Ok(bytes) = hex::decode(text) else {
            continue;
        };
        if event.event == "RX" {
            let mut request = None;
            if expect_read64_body && bytes.len() == 24 {
                request = Some((
                    u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
                    u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                    u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                ));
            } else if expect_read32_body && bytes.len() == 12 {
                request = Some((
                    u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64,
                    u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as u64,
                    u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as u64,
                ));
            } else if let Ok(crate::protocol::Packet::Read {
                image,
                offset,
                length,
            }) = crate::protocol::Packet::decode(&bytes)
            {
                request = Some((image, offset, length));
            }
            expect_read64_body = bytes == [18, 0, 0, 0, 32, 0, 0, 0];
            expect_read32_body = bytes == [3, 0, 0, 0, 20, 0, 0, 0];
            // Retain every request, including interrupted or unanswered transfers.
            // A later successful TX must not hide an earlier missing response.
            pending = request.map(|(image_id, offset, requested)| {
                checks.push(TransferCheck {
                    image_id,
                    offset,
                    requested,
                    ..Default::default()
                });
                checks.len() - 1
            });
        } else if event.event == "TX"
            && let Some(index) = pending.take()
        {
            let check = &mut checks[index];
            let (offset, length) = (check.offset, check.requested);
            let expected = offset.checked_add(length).and_then(|end| {
                image.get(usize::try_from(offset).ok()?..usize::try_from(end).ok()?)
            });
            check.sent = bytes.len();
            check.matches =
                length > 0 && expected == Some(bytes.as_slice()) && bytes.len() as u64 == length;
        }
    }
    checks
}
