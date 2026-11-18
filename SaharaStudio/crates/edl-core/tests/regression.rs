use edl_core::{
    capture::{self, Event},
    image::{self, Programmer},
    protocol::{Client, Options, Packet, State, hello_response, words},
    transport::{ReplayTransport, Transport},
};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

fn fixture(name: &str) -> PathBuf {
    std::env::var_os("SAHARA_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .join(name)
}
fn programmer() -> PathBuf {
    std::env::var_os("SAHARA_BASELINE_PROGRAMMER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"P:\OnePlus11\IMAGES\prog_firehose_ddr.elf"))
}
struct Mock {
    rx: VecDeque<Vec<u8>>,
    writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    partial: bool,
}
impl Transport for Mock {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        let Some(front) = self.rx.front_mut() else {
            return Err(std::io::ErrorKind::TimedOut.into());
        };
        if front.is_empty() {
            self.rx.pop_front();
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let n = data.len().min(front.len()).min(3);
        data[..n].copy_from_slice(&front[..n]);
        front.drain(..n);
        if front.is_empty() {
            self.rx.pop_front();
        }
        Ok(n)
    }
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let n = if self.partial {
            data.len().min(37)
        } else {
            data.len()
        };
        self.writes.lock().unwrap().push(data[..n].to_vec());
        Ok(n)
    }
}
fn hello(version: u32) -> Vec<u8> {
    words(&[1, 48, version, 1, 1024, 0, 0, 0, 0, 0, 0, 0])
}

#[test]
fn packet_length_and_status_are_exact() {
    assert_eq!(
        Packet::decode(&words(&[4, 16, 13, 8])).unwrap(),
        Packet::End {
            image: 13,
            status: 8
        }
    );
    assert_eq!(
        edl_core::protocol::status_name(33),
        "HASH_TABLE_AUTH_FAILURE"
    );
    assert!(Packet::decode(&words(&[4, 48, 13, 8])).is_err());
    assert!(Packet::decode(&[1, 0, 0]).is_err());
    assert_eq!(
        hello_response(2, 2, 3),
        words(&[2, 48, 2, 2, 0, 3, 0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn v2_state_machine_supplies_one_128k_write_and_stops_after_done() {
    let writes = Arc::new(std::sync::Mutex::new(vec![]));
    let rx = vec![
        hello(2),
        words(&[11, 8]),
        hello(2),
        words(&[3, 20, 13, 0, 131072]),
        words(&[4, 16, 13, 0]),
        words(&[6, 12, 1]),
    ];
    let mock = Mock {
        rx: rx.into(),
        writes: writes.clone(),
        partial: false,
    };
    let options = Options {
        identity: false,
        upload: true,
        ..Default::default()
    };
    let payload = Arc::new(vec![0xa5; 131072]);
    let images = BTreeMap::from([(13, payload.clone())]);
    let mut client = Client::new(mock, options, Arc::new(AtomicBool::new(false)), |_| Ok(()));
    assert_eq!(client.run(&images).unwrap(), State::Complete);
    let w = writes.lock().unwrap();
    assert!(w.iter().any(|p| p.as_slice() == payload.as_slice()));
    assert_eq!(w.last().unwrap(), &words(&[5, 8]));
    assert!(!w.iter().any(|p| p.starts_with(b"<?xml")));
}

#[test]
fn cancellation_never_sends_a_command() {
    let writes = Arc::new(std::sync::Mutex::new(vec![]));
    let mock = Mock {
        rx: VecDeque::new(),
        writes: writes.clone(),
        partial: false,
    };
    let mut client = Client::new(
        mock,
        Options::default(),
        Arc::new(AtomicBool::new(true)),
        |_| Ok(()),
    );
    assert!(client.run(&BTreeMap::new()).is_err());
    assert_eq!(client.state, State::Cancelled);
    assert!(writes.lock().unwrap().is_empty());
}

#[test]
fn out_of_bounds_request_never_pads_or_transmits_image() {
    let writes = Arc::new(std::sync::Mutex::new(vec![]));
    let mock = Mock {
        rx: vec![
            hello(3),
            words(&[11, 8]),
            hello(3),
            words(&[3, 20, 13, 15, 2]),
        ]
        .into(),
        writes: writes.clone(),
        partial: false,
    };
    let mut client = Client::new(
        mock,
        Options {
            identity: false,
            upload: true,
            ..Default::default()
        },
        Arc::new(AtomicBool::new(false)),
        |_| Ok(()),
    );
    let error = client
        .run(&BTreeMap::from([(13, Arc::new(vec![1; 16]))]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("Invalid requested range"));
    assert_eq!(writes.lock().unwrap().len(), 3);
}

#[test]
fn partial_writes_resume_without_losing_bytes() {
    let writes = Arc::new(std::sync::Mutex::new(vec![]));
    let mock = Mock {
        rx: vec![
            hello(2),
            words(&[11, 8]),
            hello(2),
            words(&[3, 20, 13, 0, 1024]),
            words(&[4, 16, 13, 0]),
            words(&[6, 12, 1]),
        ]
        .into(),
        writes: writes.clone(),
        partial: true,
    };
    let mut client = Client::new(
        mock,
        Options {
            identity: false,
            upload: true,
            ..Default::default()
        },
        Arc::new(AtomicBool::new(false)),
        |_| Ok(()),
    );
    client
        .run(&BTreeMap::from([(13, Arc::new(vec![0xa5; 1024]))]))
        .unwrap();
    let bytes = writes
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.first() == Some(&0xa5))
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(bytes, vec![0xa5; 1024]);
}

#[test]
fn malformed_elf_inputs_return_errors_instead_of_panics() {
    for n in 0..128 {
        let bytes = vec![0; n];
        assert!(image::parse(&bytes, Path::new("synthetic")).is_err());
    }
    let mut bytes = vec![0; 64];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(image::parse(&bytes, Path::new("synthetic")).is_err());
}

#[test]
fn replay_transport_requires_exact_transmission() {
    let events = vec![Event::packet("TX", &[1, 2, 3], "expected")];
    let mut transport = ReplayTransport::from_events(&events).unwrap();
    assert!(transport.write(&[1, 2]).is_err());
    assert_eq!(transport.write(&[1, 2, 3]).unwrap(), 3);
    assert_eq!(transport.remaining(), 0);
}

#[test]
#[ignore = "Requires the original external firmware/capture fixtures; see Docs/Validation.md"]
fn real_melf_matches_established_five_image_and_signature_baseline() {
    assert!(
        programmer().is_file(),
        "Set SAHARA_BASELINE_PROGRAMMER to the original baseline file"
    );
    let p = Programmer::load(&programmer()).unwrap();
    assert_eq!(
        p.report.sha256,
        "42f4778ac22b22723ad9a8badf72bf0652d61e1d9efd63d94337c54ac4165aae"
    );
    assert_eq!(
        p.report.images.iter().map(|e| e.base).collect::<Vec<_>>(),
        vec![0, 131828, 352148, 1207156, 1502060]
    );
    for e in &p.report.images[3..] {
        let signing = e.segments.iter().find_map(|s| s.signing.as_ref()).unwrap();
        assert!(signing.image_signature.starts_with("Valid OEM"));
        assert_eq!(signing.oem_metadata.rollback, Some(1));
        assert!(
            signing
                .oem_certificates
                .iter()
                .all(|c| c.issuer_signature == "Valid")
        );
    }
    let signing = p.report.images[1]
        .segments
        .iter()
        .find_map(|s| s.signing.as_ref())
        .unwrap();
    assert!(signing.hash_entries[10].direct_match);
}

#[test]
#[ignore = "Requires the original external firmware/capture fixtures; see Docs/Validation.md"]
fn python_captures_preserve_all_payloads_and_replay_the_protocol_exactly() {
    assert!(
        programmer().is_file(),
        "Set SAHARA_BASELINE_PROGRAMMER to the original baseline file"
    );
    let p = Programmer::load(&programmer()).unwrap();
    for (name, requests, status) in [
        ("logs/session-20261117-083450-912063/events.jsonl", 3, 8),
        ("logs/session-20261117-084433-854527/events.jsonl", 24, 33),
    ] {
        let capture = fixture(name);
        assert!(
            capture.is_file(),
            "Set SAHARA_FIXTURE_ROOT to the original investigation folder"
        );
        let events = capture::load(&capture).unwrap();
        let checks = capture::verify_transfers(&events, &p.bytes);
        assert_eq!(checks.len(), requests);
        assert!(checks.iter().all(|c| c.matches));
        let replay = ReplayTransport::from_events(&events).unwrap();
        let mut client = Client::new(
            replay,
            Options {
                timeout_ms: 1,
                upload: true,
                ..Default::default()
            },
            Arc::new(AtomicBool::new(false)),
            |_| Ok(()),
        );
        let error = client
            .run(&BTreeMap::from([(13, p.bytes.clone())]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("status 0x{status:02x}")),
            "Unexpected replay failure: {error}"
        );
    }
}

#[test]
#[ignore = "Requires the original external firmware/capture fixtures; see Docs/Validation.md"]
fn live_native_capture_replays_without_any_hardware_or_python() {
    let capture = fixture("rust/sessions/session-20261117-093030-250263000.jsonl");
    let source = PathBuf::from(
        r"P:\OnePlus11\Chimera_OPLUS_files\OnePlus11Firehoses\OPPO_8Gen2_New_Chimera_V2.6.melf",
    );
    assert!(
        capture.is_file() && source.is_file(),
        "Original native capture and programmer fixtures are required"
    );
    let programmer = Programmer::load(&source).unwrap();
    let events = capture::load(&capture).unwrap();
    let checks = capture::verify_transfers(&events, &programmer.bytes);
    assert_eq!(checks.len(), 24);
    assert!(checks.iter().all(|c| c.matches));
    assert_eq!(checks.iter().map(|c| c.sent).sum::<usize>(), 1_192_368);
    let replay = ReplayTransport::from_events(&events).unwrap();
    let mut client = Client::new(
        replay,
        Options {
            timeout_ms: 1,
            upload: true,
            ..Default::default()
        },
        Arc::new(AtomicBool::new(false)),
        |_| Ok(()),
    );
    let error = client
        .run(&BTreeMap::from([(13, programmer.bytes)]))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("status 0x21"),
        "Unexpected native replay: {error}"
    );
    assert_eq!(client.state, State::Rejected);
}

#[test]
fn capture_audit_retains_missing_and_overwritten_responses() {
    let events = vec![
        Event::packet("RX", &words(&[3, 20, 13, 0, 4]), "first"),
        Event::packet("TX", &[1, 2, 3, 4], "complete"),
        Event::packet("RX", &words(&[3, 20, 13, 4, 4]), "unanswered"),
        Event::packet("RX", &words(&[3, 20, 13, 8, 4]), "new request"),
        Event::packet("TX", &[9, 10, 11, 12], "complete"),
        Event::packet("RX", &words(&[3, 20, 13, 0, 4]), "truncated capture"),
    ];
    let checks = capture::verify_transfers(&events, &(1..=12).collect::<Vec<u8>>());
    assert_eq!(checks.len(), 4);
    assert_eq!(
        checks.iter().map(|c| c.matches).collect::<Vec<_>>(),
        [true, false, true, false]
    );
    assert_eq!(checks[1].sent, 0);
}

#[test]
fn capture_audit_supports_split_read_bodies_and_reports_partial_payloads() {
    let events = vec![
        Event::packet("RX", &words(&[3, 20]), "header"),
        Event::packet("RX", &words(&[13, 0, 4]), "body"),
        Event::packet("TX", &[1, 2], "short"),
        Event::packet("RX", &words(&[18, 32]), "header"),
        Event::packet("RX", &words(&[13, 0, 4, 0, 4, 0]), "body"),
        Event::packet("TX", &[5, 6, 7, 8], "complete"),
    ];
    let checks = capture::verify_transfers(&events, &(1..=8).collect::<Vec<u8>>());
    assert_eq!(checks.len(), 2);
    assert!(!checks[0].matches);
    assert_eq!(checks[0].sent, 2);
    assert!(checks[1].matches);
}

fn synthetic_mbn() -> Vec<u8> {
    let mut bytes = words(&[13, 3, 0, 0x1000, 16, 16, 0x1010, 0, 0x1010, 0]);
    bytes.extend_from_slice(&[0xa5; 16]);
    bytes
}

#[test]
fn standalone_mbn_is_detected_by_content_and_checks_payload_bounds() {
    let bytes = synthetic_mbn();
    let report = image::parse(&bytes, Path::new("programmer.with_any_extension")).unwrap();
    assert_eq!(report.format_name(), "Standalone MBN");
    assert_eq!(report.mbn.as_ref().unwrap().version, 3);
    assert!(image::parse(&bytes[..bytes.len() - 1], Path::new("truncated")).is_err());
    let mut invalid = bytes.clone();
    invalid[16..20].copy_from_slice(&17u32.to_le_bytes());
    assert!(image::parse(&invalid, Path::new("bad.mbn")).is_err());
    assert!(image::parse(&[0x41; 100], Path::new("prog_firehose.mbn")).is_err());
}

struct TestFolder(PathBuf);
impl TestFolder {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sahara-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn folder_catalog_keeps_versions_and_companions_independent() {
    let temp = TestFolder::new();
    let folder = temp.0.join("SM8550_8Gen2_8_Gen2");
    std::fs::create_dir_all(&folder).unwrap();
    for name in ["prog_V2.6.unusual", "prog_V2.7"] {
        std::fs::write(folder.join(name), synthetic_mbn()).unwrap();
    }
    std::fs::write(folder.join("Digest2.bin"), [1, 2, 3]).unwrap();
    std::fs::write(folder.join("sig"), [4, 5, 6]).unwrap();
    let library = edl_core::catalog::scan(&temp.0).unwrap();
    assert!(library.warnings.is_empty());
    let entry = &library.folders[0];
    assert!(entry.matches_descriptor("sm8550"));
    assert!(!entry.matches_descriptor("SM855"));
    assert!(!entry.matches_descriptor(""));
    assert_eq!(entry.programmers.len(), 2);
    assert_eq!(entry.digests, [folder.join("Digest2.bin")]);
    assert_eq!(entry.verifications, [folder.join("sig")]);
    for candidate in &entry.programmers {
        let review = edl_core::catalog::review(
            &candidate.path,
            Some(&entry.digests[0]),
            Some(&entry.verifications[0]),
        )
        .unwrap();
        assert_eq!(review.files.len(), 3);
        assert!(review.relationship.contains("unverified"));
        assert_eq!(review.files[1].path, folder.join("Digest2.bin"));
    }
    assert_eq!(
        edl_core::catalog::descriptor_for_msm(0x001ca0e1),
        Some("SM8550")
    );
    assert_eq!(edl_core::catalog::descriptor_for_msm(519), None); // Linux socinfo ID is not a Sahara MSM ID.
    assert_eq!(edl_core::catalog::descriptor_for_msm(0xffffffff), None);
}

#[test]
fn legacy_mbn_and_aligned_common_headers_preserve_original_content() {
    let mut header = vec![0u32; 20];
    header[0] = 0x844bdcd1;
    header[1] = 0x73d71034;
    header[2] = 13;
    header[5] = 80;
    header[7] = 16;
    header[8] = 16;
    let mut bytes = words(&header);
    bytes.extend_from_slice(&[0xa5; 16]);
    let report = image::parse(&bytes, Path::new("prog_ddr_firehose.anything")).unwrap();
    assert_eq!(report.format_name(), "Legacy MBN (SBL)");
    assert_eq!(report.size, bytes.len());
    assert_eq!(report.sha256, image::sha256(&bytes));
    assert!(image::parse(&bytes[..95], Path::new("truncated")).is_err());
    let mut common = synthetic_mbn();
    common[20..24].copy_from_slice(&15u32.to_le_bytes());
    assert!(image::parse(&common, Path::new("aligned")).is_ok());
    assert!(image::parse(&common[..55], Path::new("missing padding")).is_err());
}

#[test]
fn bundled_library_separates_sm8550_versions_from_companions() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Firehoses");
    let library = edl_core::catalog::scan(&root).unwrap();
    assert!(library.warnings.is_empty(), "{:?}", library.warnings);
    let folder = library
        .folders
        .iter()
        .find(|f| f.matches_descriptor("SM8550"))
        .unwrap();
    assert_eq!(folder.programmers.len(), 2);
    assert!(
        folder.programmers[0]
            .path
            .to_string_lossy()
            .contains("V2.6")
    );
    assert!(
        folder.programmers[1]
            .path
            .to_string_lossy()
            .contains("V2.7")
    );
    assert!(folder.programmers.iter().all(|p| p.format == "MELF"));
    assert_eq!(folder.digests.len(), 2);
    assert_eq!(folder.verifications.len(), 1);
    let review = edl_core::catalog::review(
        &folder.programmers[0].path,
        Some(&folder.digests[0]),
        Some(&folder.verifications[0]),
    )
    .unwrap();
    assert_eq!(review.files.len(), 3);
}

#[test]
fn local_review_rejects_a_programmer_changed_after_loading() {
    let temp = TestFolder::new();
    let path = temp.0.join("programmer");
    let original = synthetic_mbn();
    std::fs::write(&path, &original).unwrap();
    let loaded = Programmer::load(&path).unwrap();
    let mut changed = original;
    changed[40] ^= 1;
    std::fs::write(&path, changed).unwrap();
    assert!(
        edl_core::catalog::review_loaded(&loaded, None, None)
            .unwrap_err()
            .to_string()
            .contains("changed on disk")
    );
}

#[test]
fn v3_identity_emits_the_sm8550_folder_descriptor_without_uploading() {
    let writes = Arc::new(std::sync::Mutex::new(vec![]));
    let mut chip = vec![0u8; 80];
    chip[36..40].copy_from_slice(&0x001ca0e1u32.to_le_bytes());
    let mock = Mock {
        rx: vec![
            hello(3),
            words(&[11, 8]),
            words(&[14, 16, 1, 4]),
            vec![1, 2, 3, 4],
            words(&[14, 16, 10, 80]),
            chip,
            hello(3),
        ]
        .into(),
        writes: writes.clone(),
        partial: false,
    };
    let mut events = vec![];
    let mut client = Client::new(
        mock,
        Options::default(),
        Arc::new(AtomicBool::new(false)),
        |e| {
            events.push(e);
            Ok(())
        },
    );
    assert_eq!(client.run(&BTreeMap::new()).unwrap(), State::Complete);
    assert!(events.iter().any(|e| {
        e.event == "DEVICE"
            && e.details
                .as_ref()
                .is_some_and(|d| d["descriptor"] == "SM8550")
    }));
    assert!(!writes.lock().unwrap().iter().any(|w| w == &words(&[5, 8])));
}
