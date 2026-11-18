//! Folder-level programmer discovery. Extensions never determine the container format.
use crate::image::{self, Programmer};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub path: PathBuf,
    pub format: String,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Folder {
    pub path: PathBuf,
    pub programmers: Vec<Candidate>,
    pub digests: Vec<PathBuf>,
    pub verifications: Vec<PathBuf>,
    pub other: Vec<PathBuf>,
}
impl Folder {
    pub fn label(&self) -> String {
        let kind = if !self.digests.is_empty() || !self.verifications.is_empty() {
            if !self.digests.is_empty() && !self.verifications.is_empty() {
                "programmer + digest + verification"
            } else {
                "incomplete companion set"
            }
        } else {
            "standalone programmer(s)"
        };
        format!(
            "{} · {} programmer(s) · {kind}",
            self.path.file_name().unwrap_or_default().to_string_lossy(),
            self.programmers.len()
        )
    }
    pub fn matches_descriptor(&self, descriptor: &str) -> bool {
        let descriptor = descriptor.trim().to_ascii_uppercase();
        !descriptor.is_empty()
            && self
                .path
                .to_string_lossy()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token.eq_ignore_ascii_case(&descriptor))
    }
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Library {
    pub root: PathBuf,
    pub folders: Vec<Folder>,
    pub warnings: Vec<String>,
}

pub fn scan(root: &Path) -> Result<Library> {
    ensure!(
        root.is_dir(),
        "Programmer folder does not exist: {}",
        root.display()
    );
    let mut library = Library {
        root: root.into(),
        ..Default::default()
    };
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0;
    let mut file_count = 0;
    while let Some(path) = pending.pop() {
        visited += 1;
        ensure!(visited <= 4096, "Folder scan exceeds 4096 directories");
        let mut folder = Folder {
            path: path.clone(),
            ..Default::default()
        };
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) => {
                library
                    .warnings
                    .push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            file_count += 1;
            ensure!(file_count <= 10000, "Folder scan exceeds 10000 files");
            let path = entry.path();
            let stem = entry.file_name().to_string_lossy().to_ascii_lowercase();
            // Companion roles are filename hints only. They are never uploaded as a programmer,
            // and no version suffix is used to associate them with one of the payloads.
            if stem.contains("digest") {
                folder.digests.push(path);
            } else if stem == "sig"
                || stem.starts_with("sig.")
                || stem.contains("sign")
                || stem.contains("verif")
            {
                folder.verifications.push(path);
            } else {
                match format_hint(&path) {
                    Ok(Some(format)) => folder.programmers.push(Candidate { path, format }),
                    Ok(None) => folder.other.push(path),
                    Err(error) => library
                        .warnings
                        .push(format!("{}: {error:#}", path.display())),
                }
            }
        }
        folder.programmers.sort_by(|a, b| a.path.cmp(&b.path));
        folder.digests.sort();
        folder.verifications.sort();
        folder.other.sort();
        if !folder.programmers.is_empty()
            || !folder.digests.is_empty()
            || !folder.verifications.is_empty()
            || !folder.other.is_empty()
        {
            library.folders.push(folder);
        }
    }
    library.folders.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(library)
}

fn format_hint(path: &Path) -> Result<Option<String>> {
    let mut header = [0u8; 40];
    let mut file = fs::File::open(path)?;
    let count = file.read(&mut header)?;
    let elf = header.starts_with(b"\x7fELF");
    let mbn = count >= 40
        && ((matches!(u32::from_le_bytes(header[4..8].try_into()?), 3 | 5 | 6 | 7)
            && (1..=65535).contains(&u32::from_le_bytes(header[..4].try_into()?)))
            || header[..8] == [0xd1, 0xdc, 0x4b, 0x84, 0x34, 0x10, 0xd7, 0x73]);
    if !elf && !mbn {
        return Ok(None);
    }
    let p = Programmer::load(path)?;
    Ok(Some(p.report.format_name().into()))
}

#[derive(Clone, Debug, Serialize)]
pub struct FileReview {
    pub role: String,
    pub path: PathBuf,
    pub size: usize,
    pub sha256: String,
    pub inspection: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct BundleReview {
    pub files: Vec<FileReview>,
    pub relationship: String,
}
pub fn review(
    programmer: &Path,
    digest: Option<&Path>,
    verification: Option<&Path>,
) -> Result<BundleReview> {
    let programmer = Programmer::load(programmer)?;
    let mut files = vec![FileReview {
        role: "Programmer".into(),
        path: programmer.report.path.clone(),
        size: programmer.report.size,
        sha256: programmer.report.sha256.clone(),
        inspection: inspection_summary(&programmer.report),
    }];
    for (role, path) in [("Digest", digest), ("Verification", verification)] {
        let Some(path) = path else {
            continue;
        };
        ensure!(
            path != programmer.report.path,
            "The {role} must be a separate file"
        );
        let len = fs::metadata(path)
            .with_context(|| format!("{role}: {}", path.display()))?
            .len();
        ensure!(
            len > 0 && len <= 512 * 1024 * 1024,
            "{role} file size must be 1 byte..512 MiB"
        );
        let bytes = fs::read(path)?;
        let inspection = if bytes.starts_with(b"\x7fELF") {
            let report = image::parse(&bytes, path)?;
            inspection_summary(&report)
        } else {
            "Opaque companion; format and detached signature relationship unverified".into()
        };
        files.push(FileReview {
            role: role.into(),
            path: path.into(),
            size: bytes.len(),
            sha256: image::sha256(&bytes),
            inspection,
        });
    }
    Ok(BundleReview { files, relationship: "File integrity and supported embedded signatures inspected locally. Digest/programmer association and detached verification are unverified; filenames and shared folders do not prove compatibility. Companions are not transmitted by the Sahara uploader.".into() })
}

/// Raw Sahara MSM IDs are a different namespace from Linux socinfo IDs.
/// SM8550 is confirmed by the original OnePlus 11 V3 capture (MSM 0x001ca0e1).
/// Older MSM values: B. Kerler's edlclient/Config/qualcomm_config.py (upstream).
pub fn descriptor_for_msm(msm: u32) -> Option<&'static str> {
    match msm {
        0x001ca0e1 => Some("SM8550"),
        0x001350e1 | 0x001520e1 | 0x0019e0e1 => Some("SM8350"),
        0x0014d0e1 => Some("SM6115"),
        0x0016f0e1 | 0x0016e0e1 => Some("SM4350"),
        0x000a50e1 => Some("SM8150"),
        0x000c30e1 | 0x000ce0e1 | 0x001560e1 => Some("SM8250"),
        _ => None,
    }
}

pub fn review_loaded(
    programmer: &Programmer,
    digest: Option<&Path>,
    verification: Option<&Path>,
) -> Result<BundleReview> {
    let review = review(&programmer.report.path, digest, verification)?;
    ensure!(
        review.files[0].sha256 == programmer.report.sha256,
        "Programmer changed on disk after loading. Reload it before verifying or uploading."
    );
    Ok(review)
}

fn inspection_summary(report: &image::ImageReport) -> String {
    let signing = report
        .images
        .iter()
        .flat_map(|e| &e.segments)
        .filter_map(|s| s.signing.as_ref())
        .chain(report.mbn.as_deref());
    let mut messages = vec![format!("{}; parsed successfully", report.format_name())];
    for block in signing {
        messages.push(block.image_signature.clone());
        for cert in block.qti_certificates.iter().chain(&block.oem_certificates) {
            messages.push(format!(
                "Certificate {}: {}",
                cert.subject, cert.issuer_signature
            ));
        }
        let mismatches = block
            .hash_entries
            .iter()
            .filter(|h| !h.zero && !h.direct_match)
            .count();
        if mismatches > 0 {
            messages.push(format!("{mismatches} segment hash mismatch(es)"));
        }
    }
    messages.join("; ")
}
