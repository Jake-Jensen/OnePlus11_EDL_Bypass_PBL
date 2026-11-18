use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use x509_parser::prelude::*;

fn slice(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    data.get(
        offset
            ..offset
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("Offset overflow"))?,
    )
    .ok_or_else(|| anyhow::anyhow!("Truncated image at 0x{offset:x}, requested {size} bytes"))
}
fn n16(d: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(d, o, 2)?.try_into()?))
}
fn n32(d: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(d, o, 4)?.try_into()?))
}
fn n64(d: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(slice(d, o, 8)?.try_into()?))
}
fn address(n: u64) -> Result<usize> {
    usize::try_from(n).context("Image offset does not fit address space")
}
fn sum(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| anyhow::anyhow!("Image offset overflow"))
}
pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub size: usize,
    pub version_major: Option<u32>,
    pub version_minor: Option<u32>,
    pub rollback: Option<u32>,
    pub mrc_index: Option<u32>,
    pub soc_hw_versions: Vec<u32>,
    pub serial_numbers: Vec<u64>,
    pub oem_id: Option<u32>,
    pub product_id: Option<u32>,
    pub flags: Option<u32>,
    pub raw: String,
}
fn metadata(d: &[u8]) -> Result<Metadata> {
    let mut m = Metadata {
        size: d.len(),
        version_major: None,
        version_minor: None,
        rollback: None,
        mrc_index: None,
        soc_hw_versions: vec![],
        serial_numbers: vec![],
        oem_id: None,
        product_id: None,
        flags: None,
        raw: hex::encode(d),
    };
    if d.len() == 224 && n32(d, 0)? == 2 {
        m.version_major = Some(n32(d, 0)?);
        m.version_minor = Some(n32(d, 4)?);
        m.rollback = Some(n32(d, 8)?);
        m.mrc_index = Some(n32(d, 12)?);
        m.soc_hw_versions = (0..12).map(|i| n32(d, 16 + i * 4)).collect::<Result<_>>()?;
        m.serial_numbers = (0..8).map(|i| n64(d, 72 + i * 8)).collect::<Result<_>>()?;
        m.oem_id = Some(n32(d, 136)?);
        m.product_id = Some(n32(d, 140)?);
        m.flags = Some(n32(d, 220)?);
    }
    Ok(m)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub offset: usize,
    pub size: usize,
    pub subject: String,
    pub issuer: String,
    pub sha256: String,
    pub sha384: String,
    pub signature_algorithm: String,
    pub issuer_signature: String,
    pub valid_from: String,
    pub valid_until: String,
}
fn der_length(d: &[u8]) -> Result<usize> {
    ensure!(d.len() >= 2 && d[0] == 0x30, "Invalid DER sequence");
    if d[1] < 128 {
        return Ok(d[1] as usize + 2);
    }
    let width = (d[1] & 127) as usize;
    ensure!((1..=4).contains(&width), "Invalid DER length width");
    let mut size = 0usize;
    for b in slice(d, 2, width)? {
        size = (size << 8) | (*b as usize);
    }
    sum(2 + width, size)
}
fn certificates(d: &[u8], absolute: usize) -> Result<(Vec<Certificate>, Vec<Vec<u8>>)> {
    let mut raw = vec![];
    let mut cursor = 0;
    while d.get(cursor) == Some(&0x30) {
        let length = der_length(&d[cursor..])?;
        let der = slice(d, cursor, length)?;
        parse_x509_certificate(der).map_err(|e| {
            anyhow::anyhow!("Invalid certificate at 0x{:x}: {e}", absolute + cursor)
        })?;
        raw.push(der.to_vec());
        cursor += length;
        ensure!(raw.len() <= 32, "Excessive certificate chain length");
    }
    let mut records = vec![];
    cursor = 0;
    for (i, der) in raw.iter().enumerate() {
        let (_, cert) = parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("{e}"))?;
        let parent = raw.get(i + 1).unwrap_or(der);
        let (_, issuer) = parse_x509_certificate(parent).map_err(|e| anyhow::anyhow!("{e}"))?;
        let verification = if cert.issuer() != issuer.subject() {
            "Issuer missing / names differ".into()
        } else {
            match cert.verify_signature(Some(issuer.public_key())) {
                Ok(()) => "Valid".into(),
                Err(e) => format!("Invalid or unsupported: {e}"),
            }
        };
        records.push(Certificate {
            offset: absolute + cursor,
            size: der.len(),
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            sha256: sha256(der),
            sha384: hex::encode(Sha384::digest(der)),
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
            issuer_signature: verification,
            valid_from: cert.validity().not_before.to_string(),
            valid_until: cert.validity().not_after.to_string(),
        });
        cursor += der.len();
    }
    Ok((records, raw))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashEntry {
    pub index: usize,
    pub stored: String,
    pub zero: bool,
    pub direct_match: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signing {
    pub version: u32,
    pub header_words: Vec<u32>,
    pub software_id: Option<u32>,
    pub hash_algorithm: Option<u32>,
    pub qti_metadata: Metadata,
    pub oem_metadata: Metadata,
    pub qti_certificates: Vec<Certificate>,
    pub oem_certificates: Vec<Certificate>,
    pub image_signature: String,
    pub hash_entries: Vec<HashEntry>,
    pub trailing_bytes: usize,
    pub trailing_all_ff: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Segment {
    pub index: usize,
    pub kind: u32,
    pub offset: u64,
    pub absolute: usize,
    pub va: u64,
    pub pa: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
    pub alignment: u64,
    pub aligned: bool,
    pub qcom_type: u32,
    pub signing: Option<Signing>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfImage {
    pub base: usize,
    pub extent: usize,
    pub class: u8,
    pub machine: u16,
    pub entry: u64,
    pub flags: u32,
    pub ph_offset: u64,
    pub ph_size: u16,
    pub section_offset: u64,
    pub section_count: u16,
    pub sha256: String,
    pub segments: Vec<Segment>,
}
impl ElfImage {
    pub fn machine_name(&self) -> &str {
        match self.machine {
            1 => "EM_M32 (vendor value)",
            40 => "ARM",
            183 => "AArch64",
            243 => "RISC-V",
            _ => "Other",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageReport {
    pub path: PathBuf,
    pub size: usize,
    pub sha256: String,
    pub images: Vec<ElfImage>,
    #[serde(default)]
    pub mbn: Option<Box<Signing>>,
}
#[derive(Clone)]
pub struct Programmer {
    pub report: ImageReport,
    pub bytes: Arc<Vec<u8>>,
}
impl Programmer {
    pub fn load(path: &Path) -> Result<Self> {
        let size = std::fs::metadata(path)?.len();
        ensure!(
            size > 0 && size <= 512 * 1024 * 1024,
            "Programmer size must be 1 byte..512 MiB"
        );
        let bytes = std::fs::read(path)?;
        let report = parse(&bytes, path)?;
        Ok(Self {
            report,
            bytes: Arc::new(bytes),
        })
    }
    pub fn describe_offset(&self, offset: u64) -> String {
        if self.report.mbn.is_some() && offset < self.report.size as u64 {
            return "Standalone MBN programmer".into();
        }
        for (i, e) in self.report.images.iter().enumerate() {
            if offset >= e.base as u64 && offset < (e.base + e.extent) as u64 {
                for s in &e.segments {
                    if offset >= s.absolute as u64 && offset < (s.absolute as u64 + s.file_size) {
                        return format!(
                            "ELF {} · {} · segment {}{}",
                            i + 1,
                            e.machine_name(),
                            s.index,
                            if s.qcom_type == 2 {
                                " · signed hash table"
                            } else {
                                ""
                            }
                        );
                    }
                }
                return format!("ELF {} · {} · header/table", i + 1, e.machine_name());
            }
        }
        "Outside image".into()
    }
}

fn signing(blob: &[u8], elf: &ElfImage, segment: &Segment) -> Result<Signing> {
    let d = slice(blob, segment.absolute, address(segment.file_size)?)?;
    let version = n32(d, 4)?;
    let header_len = if version == 6 { 48 } else { 40 };
    let header = (0..header_len / 4)
        .map(|i| n32(d, i * 4))
        .collect::<Result<Vec<_>>>()?;
    let mut out = Signing {
        version,
        header_words: header.clone(),
        software_id: None,
        hash_algorithm: None,
        qti_metadata: metadata(&[])?,
        oem_metadata: metadata(&[])?,
        qti_certificates: vec![],
        oem_certificates: vec![],
        image_signature: "Not verified for this signing format".into(),
        hash_entries: vec![],
        trailing_bytes: 0,
        trailing_all_ff: false,
    };
    let (mut cursor, hash_size, qs, qc, os, oc) = match version {
        7 => {
            ensure!(header[2] >= 24, "MBNv7 common metadata truncated");
            out.software_id = Some(n32(d, 48)?);
            out.hash_algorithm = Some(n32(d, 56)?);
            let mut cursor = sum(40, header[2] as usize)?;
            out.qti_metadata = metadata(slice(d, cursor, header[3] as usize)?)?;
            cursor = sum(cursor, header[3] as usize)?;
            out.oem_metadata = metadata(slice(d, cursor, header[4] as usize)?)?;
            cursor = sum(cursor, header[4] as usize)?;
            (
                cursor, header[5], header[6], header[7], header[8], header[9],
            )
        }
        6 => {
            let mut cursor = 48;
            out.qti_metadata = metadata(slice(d, cursor, header[10] as usize)?)?;
            cursor = sum(cursor, header[10] as usize)?;
            out.oem_metadata = metadata(slice(d, cursor, header[11] as usize)?)?;
            cursor = sum(cursor, header[11] as usize)?;
            (
                cursor, header[5], header[2], header[3], header[7], header[9],
            )
        }
        5 => (40, header[5], header[2], header[3], header[7], header[9]),
        3 => {
            out.software_id = Some(header[0]);
            (40, header[5], 0, 0, header[7], header[9])
        }
        _ => return Ok(out),
    };
    let table = slice(d, cursor, hash_size as usize)?;
    if out.hash_algorithm == Some(3) && table.len() == elf.segments.len() * 48 {
        for (i, s) in elf.segments.iter().enumerate() {
            let stored = &table[i * 48..(i + 1) * 48];
            let raw = slice(blob, s.absolute, address(s.file_size)?)?;
            out.hash_entries.push(HashEntry {
                index: i,
                stored: hex::encode(stored),
                zero: stored.iter().all(|b| *b == 0),
                direct_match: stored == Sha384::digest(raw).as_slice(),
            });
        }
    }
    cursor = sum(cursor, hash_size as usize)?;
    slice(d, cursor, qs as usize)?;
    cursor = sum(cursor, qs as usize)?;
    out.qti_certificates =
        certificates(slice(d, cursor, qc as usize)?, segment.absolute + cursor)?.0;
    cursor = sum(cursor, qc as usize)?;
    let sig_start = cursor;
    let sig = slice(d, cursor, os as usize)?;
    cursor = sum(cursor, os as usize)?;
    let (certs, raw) = certificates(slice(d, cursor, oc as usize)?, segment.absolute + cursor)?;
    out.oem_certificates = certs;
    if version == 7
        && qs == 0
        && os > 0
        && let Some(leaf) = raw.first()
    {
        let (_, cert) = parse_x509_certificate(leaf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let public = cert.public_key().subject_public_key.data.as_ref();
        let algorithm = match public.len() {
            97 => Some(&ring::signature::ECDSA_P384_SHA384_ASN1),
            65 => Some(&ring::signature::ECDSA_P256_SHA256_ASN1),
            _ => None,
        };
        out.image_signature = if let Some(algorithm) = algorithm {
            let size = der_length(sig)?;
            match ring::signature::UnparsedPublicKey::new(algorithm, public)
                .verify(&d[..sig_start], slice(sig, 0, size)?)
            {
                Ok(()) => "Valid OEM image signature (local key; target trust unknown)".into(),
                Err(_) => "INVALID OEM image signature".into(),
            }
        } else {
            "Unsupported OEM public key algorithm".into()
        };
    } else if version == 7 && qs > 0 {
        out.image_signature="Dual-authority image signature not verified; certificate signatures verified separately".into();
    }
    cursor = sum(cursor, oc as usize)?;
    let trailing = slice(
        d,
        cursor,
        d.len()
            .checked_sub(cursor)
            .ok_or_else(|| anyhow::anyhow!("Signing fields exceed hash segment"))?,
    )?;
    out.trailing_bytes = trailing.len();
    out.trailing_all_ff = trailing.iter().all(|b| *b == 255);
    Ok(out)
}

pub fn parse(blob: &[u8], path: &Path) -> Result<ImageReport> {
    if !blob.starts_with(b"\x7fELF") {
        return parse_mbn(blob, path);
    }
    let mut images = vec![];
    let mut base = 0;
    while base < blob.len() {
        ensure!(images.len() < 256, "Too many concatenated ELF images");
        let d = &blob[base..];
        ensure!(
            slice(d, 0, 4)? == b"\x7fELF",
            "Expected ELF at concatenation boundary 0x{base:x}"
        );
        let class = *slice(d, 4, 1)?.first().unwrap();
        ensure!(class == 1 || class == 2, "Unsupported ELF class {class}");
        ensure!(
            slice(d, 5, 1)? == [1],
            "Only little-endian ELF is supported"
        );
        let (entry, phoff, shoff, flags, eh, phsize, num, shnum) = if class == 1 {
            (
                n32(d, 24)? as u64,
                n32(d, 28)? as u64,
                n32(d, 32)? as u64,
                n32(d, 36)?,
                n16(d, 40)?,
                n16(d, 42)?,
                n16(d, 44)?,
                n16(d, 48)?,
            )
        } else {
            (
                n64(d, 24)?,
                n64(d, 32)?,
                n64(d, 40)?,
                n32(d, 48)?,
                n16(d, 52)?,
                n16(d, 54)?,
                n16(d, 56)?,
                n16(d, 60)?,
            )
        };
        ensure!(
            num > 0 && num <= 1024 && phsize == if class == 1 { 32 } else { 56 },
            "Invalid ELF program header count/size"
        );
        let mut e = ElfImage {
            base,
            extent: sum(address(phoff)?, num as usize * phsize as usize)?.max(eh as usize),
            class: if class == 1 { 32 } else { 64 },
            machine: n16(d, 18)?,
            entry,
            flags,
            ph_offset: phoff,
            ph_size: phsize,
            section_offset: shoff,
            section_count: shnum,
            sha256: String::new(),
            segments: vec![],
        };
        slice(d, 0, e.extent)?;
        for i in 0..num as usize {
            let p = slice(d, address(phoff)? + i * phsize as usize, phsize as usize)?;
            let (kind, offset, va, pa, file_size, memory_size, flags, alignment) = if class == 1 {
                (
                    n32(p, 0)?,
                    n32(p, 4)? as u64,
                    n32(p, 8)? as u64,
                    n32(p, 12)? as u64,
                    n32(p, 16)? as u64,
                    n32(p, 20)? as u64,
                    n32(p, 24)?,
                    n32(p, 28)? as u64,
                )
            } else {
                (
                    n32(p, 0)?,
                    n64(p, 8)?,
                    n64(p, 16)?,
                    n64(p, 24)?,
                    n64(p, 32)?,
                    n64(p, 40)?,
                    n32(p, 4)?,
                    n64(p, 48)?,
                )
            };
            let absolute = sum(base, address(offset)?)?;
            slice(blob, absolute, address(file_size)?)?;
            if file_size > 0 {
                e.extent = e.extent.max(sum(address(offset)?, address(file_size)?)?);
            }
            e.segments.push(Segment {
                index: i,
                kind,
                offset,
                absolute,
                va,
                pa,
                file_size,
                memory_size,
                flags,
                alignment,
                aligned: alignment <= 1 || offset % alignment == va % alignment,
                qcom_type: (flags >> 24) & 7,
                signing: None,
            });
        }
        e.sha256 = sha256(slice(blob, base, e.extent)?);
        for i in 0..e.segments.len() {
            if e.segments[i].qcom_type == 2 && e.segments[i].file_size > 0 {
                let s = signing(blob, &e, &e.segments[i])
                    .with_context(|| format!("ELF {} hash segment", images.len() + 1))?;
                e.segments[i].signing = Some(s);
            }
        }
        base = sum(base, e.extent)?;
        images.push(e);
    }
    if images.is_empty() {
        bail!("Empty programmer");
    }
    Ok(ImageReport {
        path: path.into(),
        size: blob.len(),
        sha256: sha256(blob),
        images,
        mbn: None,
    })
}

fn parse_mbn(blob: &[u8], path: &Path) -> Result<ImageReport> {
    let image_id = n32(blob, 0)?;
    if image_id == 0x844bdcd1 {
        return parse_sbl(blob, path);
    }
    let version = n32(blob, 4)?;
    ensure!(
        (1..=65535).contains(&image_id),
        "Unrecognized programmer content (not ELF or a supported MBN)"
    );
    ensure!(
        matches!(version, 3 | 5 | 6 | 7),
        "Unsupported standalone MBN header version {version}"
    );
    let code_size = n32(blob, 20)? as usize;
    ensure!(code_size > 0, "Empty MBN code payload");
    // Common MBN headers use code/signature/certificate lengths, not file extensions.
    // signing() validates metadata and all individual payload extents below.
    if version != 7 {
        let mut expected = code_size;
        for offset in if version == 3 {
            vec![28, 36]
        } else {
            vec![8, 12, 28, 36]
        } {
            expected = sum(expected, n32(blob, offset)? as usize)?;
        }
        let image_size = n32(blob, 16)? as usize;
        ensure!(
            image_size == expected || image_size == (sum(expected, 3)? & !3),
            "Inconsistent MBN image/code/signing sizes"
        );
        let header_size = if version == 6 {
            sum(sum(48, n32(blob, 40)? as usize)?, n32(blob, 44)? as usize)?
        } else {
            40
        };
        slice(blob, header_size, image_size)?;
    }
    let elf = ElfImage {
        base: 0,
        extent: blob.len(),
        class: 0,
        machine: 0,
        entry: 0,
        flags: 0,
        ph_offset: 0,
        ph_size: 0,
        section_offset: 0,
        section_count: 0,
        sha256: String::new(),
        segments: vec![],
    };
    let segment = Segment {
        index: 0,
        kind: 1,
        offset: 0,
        absolute: 0,
        va: 0,
        pa: 0,
        file_size: blob.len() as u64,
        memory_size: blob.len() as u64,
        flags: 0,
        alignment: 1,
        aligned: true,
        qcom_type: 0,
        signing: None,
    };
    Ok(ImageReport {
        path: path.into(),
        size: blob.len(),
        sha256: sha256(blob),
        images: vec![],
        mbn: Some(Box::new(signing(blob, &elf, &segment)?)),
    })
}

fn parse_sbl(blob: &[u8], path: &Path) -> Result<ImageReport> {
    // Qualcomm/coreboot Sbl_Hdr: 20 words, codeword + magic followed by lengths.
    let header = (0..20)
        .map(|i| n32(blob, i * 4))
        .collect::<Result<Vec<_>>>()?;
    ensure!(header[1] == 0x73d71034, "Invalid legacy MBN magic");
    let source = header[5] as usize;
    ensure!(source >= 80, "Legacy MBN payload overlaps its header");
    slice(blob, source, header[7] as usize)?;
    let mut normalized = crate::protocol::words(&[
        header[2], 3, 0, header[6], header[7], header[8], header[9], header[10], header[11],
        header[12],
    ]);
    normalized.extend_from_slice(&blob[source..]);
    let mut report = parse_mbn(&normalized, path)?;
    report.size = blob.len();
    report.sha256 = sha256(blob);
    if let Some(signing) = &mut report.mbn {
        signing.header_words = header;
        signing.image_signature = "Legacy MBN image signature unverified; embedded certificate signatures inspected locally".into();
        for certificate in &mut signing.oem_certificates {
            certificate.offset = sum(certificate.offset, source - 40)?;
        }
    }
    Ok(report)
}

impl ImageReport {
    pub fn format_name(&self) -> &'static str {
        if let Some(signing) = &self.mbn {
            if signing.header_words.len() == 20 {
                "Legacy MBN (SBL)"
            } else {
                "Standalone MBN"
            }
        } else if self.images.len() > 1 {
            "MELF"
        } else {
            "ELF"
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Difference {
    pub start: usize,
    pub end: usize,
    pub left_preview: String,
    pub right_preview: String,
    pub location: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Comparison {
    pub left: String,
    pub right: String,
    pub differing_bytes: usize,
    pub ranges: Vec<Difference>,
    pub total_ranges: usize,
}
pub fn compare(a: &Programmer, b: &Programmer) -> Comparison {
    let mut ranges = vec![];
    let mut count = 0;
    let mut total = 0;
    let mut i = 0;
    let max = a.bytes.len().max(b.bytes.len());
    while i < max {
        if a.bytes.get(i) == b.bytes.get(i) {
            i += 1;
            continue;
        }
        let start = i;
        while i < max && a.bytes.get(i) != b.bytes.get(i) {
            count += 1;
            i += 1;
        }
        total += 1;
        if ranges.len() < 2000 {
            ranges.push(Difference {
                start,
                end: i,
                left_preview: hex::encode(
                    &a.bytes[start.min(a.bytes.len())..i.min(start + 24).min(a.bytes.len())],
                ),
                right_preview: hex::encode(
                    &b.bytes[start.min(b.bytes.len())..i.min(start + 24).min(b.bytes.len())],
                ),
                location: a.describe_offset(start as u64),
            });
        }
    }
    Comparison {
        left: a.report.path.display().to_string(),
        right: b.report.path.display().to_string(),
        differing_bytes: count,
        ranges,
        total_ranges: total,
    }
}
