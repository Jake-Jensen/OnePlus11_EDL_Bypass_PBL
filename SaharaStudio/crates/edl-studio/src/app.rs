use edl_core::{
    capture::{self, Event, Recorder, TransferCheck},
    catalog::{self, BundleReview, Library},
    image::{self, Comparison, Programmer},
    protocol::{Client, Options},
    transport::{self, PortInfo, SerialSettings, SerialTransport},
};
use eframe::egui::{self, Color32, RichText};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const ACCENT: Color32 = Color32::from_rgb(68, 206, 191);
const MUTED: Color32 = Color32::from_rgb(147, 162, 184);
const WARNING: Color32 = Color32::from_rgb(246, 189, 90);

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Session,
    Programmers,
    Replay,
    Diagnostics,
}
#[derive(Default, Serialize, Deserialize)]
struct Preferences {
    serial: SerialSettings,
    #[serde(default)]
    options: Options,
    #[serde(default)]
    programmers: Vec<PathBuf>,
    #[serde(default)]
    selected_programmer: Option<PathBuf>,
    #[serde(default)]
    library_root: Option<PathBuf>,
    #[serde(default)]
    digest: Option<PathBuf>,
    #[serde(default)]
    verification: Option<PathBuf>,
}
enum Message {
    Library(Result<Library, String>),
    Bundle(u64, Result<BundleReview, String>),
    Ports(Result<Vec<PortInfo>, String>),
    Image(Result<Programmer, String>),
    Compared(Comparison),
    Replay(PathBuf, Result<Vec<Event>, String>),
    Event(Event),
    Finished(Result<String, String>),
}

pub struct Studio {
    page: Page,
    root: PathBuf,
    data_dir: PathBuf,
    prefs: Preferences,
    ports: Vec<PortInfo>,
    programmers: Vec<Programmer>,
    selected: usize,
    compare_left: usize,
    compare_right: usize,
    comparison: Option<Comparison>,
    sender: mpsc::Sender<Message>,
    receiver: mpsc::Receiver<Message>,
    busy: bool,
    cancel: Arc<AtomicBool>,
    scan_at: Instant,
    scanning: bool,
    events: Vec<Event>,
    selected_event: Option<usize>,
    filter: String,
    follow: bool,
    state: String,
    last_error: Option<String>,
    session_path: Option<PathBuf>,
    session_programmer: Option<Programmer>,
    device: Vec<String>,
    transferred: u64,
    extent: u64,
    stage: String,
    session_started: Option<Instant>,
    session_elapsed: Option<Duration>,
    replay: Vec<Event>,
    replay_path: Option<PathBuf>,
    replay_cursor: usize,
    playing: bool,
    replay_speed: usize,
    replay_at: Instant,
    audit: Vec<TransferCheck>,
    notice: String,
    help: bool,
    loading: usize,
    library: Library,
    library_scanning: bool,
    folder_index: usize,
    candidate_index: usize,
    descriptor: String,
    bundle_review: Option<BundleReview>,
    review_generation: u64,
    reviewing: bool,
}

impl Studio {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.panel_fill = Color32::from_rgb(19, 25, 36);
        style.visuals.window_fill = Color32::from_rgb(23, 31, 44);
        style.visuals.selection.bg_fill = Color32::from_rgb(31, 91, 94);
        style.spacing.item_spacing = egui::vec2(10., 9.);
        style.spacing.button_padding = egui::vec2(12., 7.);
        cc.egui_ctx.set_style(style);
        let root = find_root();
        let data_dir = data_directory(&root);
        let _ = std::fs::create_dir_all(&data_dir);
        let prefs: Preferences = std::fs::read(data_dir.join("settings.json"))
            .ok()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        let (sender, receiver) = mpsc::channel();
        let mut app = Self {
            page: Page::Session,
            root,
            data_dir,
            prefs,
            ports: vec![],
            programmers: vec![],
            selected: 0,
            compare_left: 0,
            compare_right: 0,
            comparison: None,
            sender,
            receiver,
            busy: false,
            cancel: Arc::new(AtomicBool::new(false)),
            scan_at: Instant::now() - Duration::from_secs(5),
            scanning: false,
            events: vec![],
            selected_event: None,
            filter: String::new(),
            follow: true,
            state: "Ready".into(),
            last_error: None,
            session_path: None,
            session_programmer: None,
            device: vec![],
            transferred: 0,
            extent: 0,
            stage: "No transfer".into(),
            session_started: None,
            session_elapsed: None,
            replay: vec![],
            replay_path: None,
            replay_cursor: 0,
            playing: false,
            replay_speed: 10,
            replay_at: Instant::now(),
            audit: vec![],
            notice: "Select a programmer to inspect it, or run device identification.".into(),
            help: false,
            loading: 0,
            library: Library::default(),
            library_scanning: false,
            folder_index: 0,
            candidate_index: 0,
            descriptor: String::new(),
            bundle_review: None,
            review_generation: 0,
            reviewing: false,
        };
        let paths = app.prefs.programmers.clone();
        for path in paths {
            if path.is_file() {
                app.load_image(path);
            }
        }
        app.scan();
        let library_root = app
            .prefs
            .library_root
            .clone()
            .unwrap_or_else(|| app.root.join("Firehoses"));
        app.scan_library(library_root);
        app
    }
    fn scan_library(&mut self, root: PathBuf) {
        if self.library_scanning {
            return;
        }
        self.library_scanning = true;
        self.prefs.library_root = Some(root.clone());
        let tx = self.sender.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Message::Library(
                catalog::scan(&root).map_err(|e| format!("{e:#}")),
            ));
        });
    }
    fn select_image(&mut self, path: PathBuf) {
        self.bundle_review = None;
        self.review_generation += 1;
        self.reviewing = false;
        self.prefs.selected_programmer = Some(path.clone());
        if let Some(index) = self.programmers.iter().position(|p| p.report.path == path) {
            self.selected = index;
        } else {
            self.load_image(path);
        }
    }
    fn loader_ui(&mut self, ui: &mut egui::Ui) {
        let previous = (
            self.selected,
            self.prefs.digest.clone(),
            self.prefs.verification.clone(),
        );
        ui.add_enabled_ui(!self.busy, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Select programmer file…").clicked()
                    && let Some(path) = rfd::FileDialog::new().set_directory(self.root.join("Firehoses")).pick_file() {
                    self.select_image(path);
                }
                if ui.add_enabled(!self.library_scanning, egui::Button::new("Browse folder…")).clicked()
                    && let Some(path) = rfd::FileDialog::new().set_directory(self.root.join("Firehoses")).pick_folder() {
                    self.scan_library(path);
                }
                if ui.add_enabled(!self.library_scanning, egui::Button::new("Rescan")).clicked() {
                    self.scan_library(self.prefs.library_root.clone().unwrap_or_else(|| self.root.join("Firehoses")));
                }
                if self.library_scanning || self.loading > 0 { ui.spinner(); }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Device / folder descriptor:");
                ui.add(egui::TextEdit::singleline(&mut self.descriptor).hint_text("SM8550 (detected or manual)").desired_width(240.));
                if ui.button("Suggest matching folder").clicked() {
                    if let Some(index) = self.library.folders.iter().position(|f| f.matches_descriptor(&self.descriptor)) {
                        self.folder_index = index;
                        self.candidate_index = 0;
                    } else { self.notice = "No matching folder. Browse or select any programmer manually.".into(); }
                }
            });
            ui.label(RichText::new("Identify device queries the chipset. Folder matches are suggestions; every file and folder remains selectable.").small().color(MUTED));
            let old_folder = self.folder_index;
            egui::ComboBox::from_id_salt("library_folder").width(660.)
                .selected_text(self.library.folders.get(self.folder_index).map(|f| f.label()).unwrap_or_else(|| "No programmer folders found".into()))
                .show_ui(ui, |ui| {
                    for (index, folder) in self.library.folders.iter().enumerate() {
                        let prefix = if folder.matches_descriptor(&self.descriptor) { "Suggested · " } else { "" };
                        ui.selectable_value(&mut self.folder_index, index, format!("{prefix}{}", folder.label()));
                    }
                });
            if self.folder_index != old_folder { self.candidate_index = 0; }
            if let Some(folder) = self.library.folders.get(self.folder_index).cloned() {
                ui.label(RichText::new(folder.path.display().to_string()).small().color(MUTED));
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("library_programmer").width(480.)
                        .selected_text(folder.programmers.get(self.candidate_index).map(|p| format!("{} · {}", p.path.file_name().unwrap_or_default().to_string_lossy(), p.format)).unwrap_or_else(|| "No recognized programmer in this folder".into()))
                        .show_ui(ui, |ui| {
                            for (index, p) in folder.programmers.iter().enumerate() {
                                ui.selectable_value(&mut self.candidate_index, index, format!("{} · {}", p.path.file_name().unwrap_or_default().to_string_lossy(), p.format));
                            }
                        });
                    if ui.add_enabled(self.loading == 0 && !folder.programmers.is_empty(), egui::Button::new("Load programmer")).clicked()
                        && let Some(p) = folder.programmers.get(self.candidate_index) {
                        self.select_image(p.path.clone());
                    }
                });
                ui.label(RichText::new("Companion choices are independent of programmer versions. Choose them explicitly; changing 2.6 / 2.7 keeps your choices.").small().color(MUTED));
                companion_picker(ui, "Digest", &mut self.prefs.digest, &folder.digests, &folder.path);
                companion_picker(ui, "Verification", &mut self.prefs.verification, &folder.verifications, &folder.path);
                if !folder.other.is_empty() {
                    egui::CollapsingHeader::new(format!("{} unclassified files (select manually if needed)", folder.other.len())).show(ui, |ui| {
                        for path in &folder.other {
                            if ui.button(path.file_name().unwrap_or_default().to_string_lossy()).clicked() { self.select_image(path.clone()); }
                        }
                    });
                }
            } else {
                companion_picker(ui, "Digest", &mut self.prefs.digest, &[], &self.root);
                companion_picker(ui, "Verification", &mut self.prefs.verification, &[], &self.root);
            }
            ui.label(RichText::new("Sahara uploads the loaded programmer only. Companions are for local inspection.").small().color(MUTED));
            ui.horizontal_wrapped(|ui| {
                ui.label("Loaded programmer:");
                egui::ComboBox::from_id_salt("loaded_programmer").width(470.)
                    .selected_text(self.programmers.get(self.selected).map(|p| p.report.path.file_name().unwrap_or_default().to_string_lossy().into_owned()).unwrap_or_else(|| "None".into()))
                    .show_ui(ui, |ui| {
                        for (index, p) in self.programmers.iter().enumerate() {
                            ui.selectable_value(&mut self.selected, index, p.report.path.display().to_string());
                        }
                    });
                if ui.add_enabled(!self.reviewing && self.loading == 0 && !self.programmers.is_empty(), egui::Button::new("Verify selection locally")).clicked()
                    && let Some(p) = self.programmers.get(self.selected) {
                    self.bundle_review = None;
                    self.review_generation += 1;
                    self.reviewing = true;
                    let generation = self.review_generation;
                    let (programmer, digest, verification) = (p.clone(), self.prefs.digest.clone(), self.prefs.verification.clone());
                    let tx = self.sender.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(Message::Bundle(generation, catalog::review_loaded(&programmer, digest.as_deref(), verification.as_deref()).map_err(|e| format!("{e:#}"))));
                    });
                }
            });
            if previous != (self.selected, self.prefs.digest.clone(), self.prefs.verification.clone()) {
                self.bundle_review = None;
                self.review_generation += 1;
                self.reviewing = false;
            }
            if self.reviewing { ui.label("Inspecting files and embedded signatures…"); }
            if let Some(review) = &self.bundle_review {
                egui::CollapsingHeader::new("Local verification results").default_open(true).show(ui, |ui| {
                    for file in &review.files {
                        ui.label(format!("{}: {} · {}", file.role, file.path.display(), size(file.size as u64)));
                        ui.monospace(format!("SHA-256 {}", file.sha256));
                        ui.label(&file.inspection);
                    }
                    ui.colored_label(WARNING, &review.relationship);
                });
            }
            if !self.library.warnings.is_empty() {
                egui::CollapsingHeader::new("Folder scan warnings").show(ui, |ui| {
                    for warning in &self.library.warnings { ui.colored_label(WARNING, warning); }
                });
            }
        });
    }
    fn scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.scan_at = Instant::now();
        let tx = self.sender.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Message::Ports(
                transport::ports().map_err(|e| format!("{e:#}")),
            ));
        });
    }
    fn load_image(&mut self, path: PathBuf) {
        self.loading += 1;
        let tx = self.sender.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Message::Image(
                Programmer::load(&path).map_err(|e| format!("{}: {e:#}", path.display())),
            ));
        });
    }
    fn pump(&mut self) {
        while let Ok(message) = self.receiver.try_recv() {
            match message {
                Message::Library(result) => {
                    self.library_scanning = false;
                    match result {
                        Ok(library) => {
                            self.library = library;
                            self.folder_index = self
                                .library
                                .folders
                                .iter()
                                .position(|f| f.matches_descriptor(&self.descriptor))
                                .unwrap_or(0);
                            self.candidate_index = 0;
                            self.notice = format!(
                                "Found {} programmer folders; {} scan warning(s).",
                                self.library.folders.len(),
                                self.library.warnings.len()
                            );
                        }
                        Err(error) => self.last_error = Some(error),
                    }
                }
                Message::Bundle(generation, result) => {
                    if generation == self.review_generation {
                        self.reviewing = false;
                        match result {
                            Ok(review) => self.bundle_review = Some(review),
                            Err(error) => self.last_error = Some(error),
                        }
                    }
                }
                Message::Ports(result) => {
                    self.scanning = false;
                    match result {
                        Ok(p) => self.ports = p,
                        Err(e) => self.notice = format!("Port scan: {e}"),
                    }
                }
                Message::Image(result) => {
                    self.loading = self.loading.saturating_sub(1);
                    match result {
                        Ok(p) => {
                            if !self
                                .programmers
                                .iter()
                                .any(|x| x.report.path == p.report.path)
                            {
                                let preferred = self
                                    .prefs
                                    .selected_programmer
                                    .as_ref()
                                    .is_none_or(|path| path == &p.report.path);
                                self.programmers.push(p);
                                if preferred && !self.busy {
                                    self.selected = self.programmers.len() - 1;
                                }
                                if self.programmers.len() == 2 {
                                    self.compare_right = 1;
                                }
                                self.prefs.programmers = self
                                    .programmers
                                    .iter()
                                    .map(|p| p.report.path.clone())
                                    .collect();
                                self.notice =
                                    "Programmer parsed and signatures checked locally.".into();
                            }
                        }
                        Err(e) => self.last_error = Some(e),
                    }
                }
                Message::Compared(report) => self.comparison = Some(report),
                Message::Replay(path, result) => match result {
                    Ok(e) => {
                        self.replay = e;
                        self.replay_cursor = self.replay.len();
                        self.replay_path = Some(path);
                        self.audit.clear();
                        self.playing = false;
                        self.notice =
                            "Capture loaded. Replay is offline and never opens a serial port."
                                .into();
                    }
                    Err(e) => self.last_error = Some(e),
                },
                Message::Event(e) => {
                    match e.event.as_str() {
                        "STATE" => self.state = e.summary.clone(),
                        "DEVICE" => {
                            self.device.push(e.summary.clone());
                            if let Some(descriptor) =
                                e.details.as_ref().and_then(|d| d["descriptor"].as_str())
                            {
                                self.descriptor = descriptor.into();
                                if let Some(index) = self
                                    .library
                                    .folders
                                    .iter()
                                    .position(|f| f.matches_descriptor(descriptor))
                                {
                                    self.folder_index = index;
                                    self.candidate_index = 0;
                                }
                            }
                        }
                        "SESSION" => self.session_path = Some(PathBuf::from(&e.summary)),
                        "PROGRESS" => {
                            if let Some(ref d) = e.details {
                                self.transferred = d["transferred"].as_u64().unwrap_or(0);
                                self.extent = self.extent.max(d["end"].as_u64().unwrap_or(0));
                                if let Some(p) = self.session_programmer.as_ref() {
                                    self.stage =
                                        p.describe_offset(d["offset"].as_u64().unwrap_or(0));
                                }
                            }
                        }
                        _ => {}
                    }
                    self.events.push(e);
                    if self.events.len() > 10000 {
                        self.events.drain(..1000);
                        self.selected_event = None;
                    }
                }
                Message::Finished(result) => {
                    self.busy = false;
                    self.session_elapsed = self.session_started.map(|started| started.elapsed());
                    match result {
                        Ok(s) => {
                            self.notice = s;
                        }
                        Err(e) => {
                            self.state = if self.cancel.load(Ordering::Relaxed) {
                                "Cancelled".into()
                            } else if self.state == "Rejected" {
                                "Rejected".into()
                            } else {
                                "Stopped".into()
                            };
                            self.last_error = Some(e);
                        }
                    }
                }
            }
        }
    }
    fn start(&mut self, upload: bool) {
        if self.busy {
            return;
        }
        let selected = self.programmers.get(self.selected).cloned();
        self.session_programmer = selected.clone();
        if upload && (selected.is_none() || self.loading > 0) {
            self.last_error =
                Some("Finish loading and select a programmer before uploading.".into());
            return;
        }
        let mut options = self.prefs.options.clone();
        options.upload = upload;
        let settings = self.prefs.serial.clone();
        let companions = json!({"digest":self.prefs.digest,"verification":self.prefs.verification,"transmitted":false});
        let folder = self.data_dir.join("sessions");
        let tx = self.sender.clone();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.events.clear();
        self.selected_event = None;
        self.device.clear();
        self.last_error = None;
        self.transferred = 0;
        self.extent = 0;
        self.stage = "Waiting for target requests".into();
        self.busy = true;
        self.session_started = Some(Instant::now());
        self.session_elapsed = None;
        self.state = "Opening interface".into();
        self.session_path = None;
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<String> {
                let mut recorder = Recorder::create(&folder)?;
                let session_path = recorder.path.clone();
                let _ = tx.send(Message::Event(Event::message(
                    "SESSION",
                    session_path.display().to_string(),
                )));
                let configuration = json!({"serial":settings,"protocol":options,"programmer":selected.as_ref().map(|p|&p.report.path),"sha256":selected.as_ref().map(|p|&p.report.sha256),"storage_commands":false,"companions":companions});
                recorder.append(&Event {
                    details: Some(configuration),
                    ..Event::message("CONFIGURATION", "Reproducible session configuration")
                })?;
                let run = (|| -> anyhow::Result<String> {
                    let port = SerialTransport::open_wait(&settings, &cancel, |message| {
                        let event = Event::message("STATE", message);
                        recorder.append(&event)?;
                        let _ = tx.send(Message::Event(event));
                        Ok(())
                    })?;
                    let mut images = BTreeMap::new();
                    if let Some(p) = selected {
                        images.insert(13, p.bytes);
                    }
                    let mut client = Client::new(port, options, cancel, |event: Event| {
                        recorder.append(&event)?;
                        let _ = tx.send(Message::Event(event));
                        Ok(())
                    });
                    let state = client.run(&images)?;
                    Ok(format!(
                        "{state:?}. Recorded {}. No storage commands sent.",
                        session_path.display()
                    ))
                })();
                if let Err(ref e) = run {
                    let event = Event::message("ERROR", format!("{e:#}"));
                    recorder.append(&event)?;
                    let _ = tx.send(Message::Event(event));
                }
                run
            })();
            let _ = tx.send(Message::Finished(result.map_err(|e| format!("{e:#}"))));
        });
    }
    fn export(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("sahara-report.json")
            .add_filter("JSON report", &["json"])
            .save_file()
        {
            let report = json!({"application":"Sahara Studio 1.0.0","created":chrono::Local::now().to_rfc3339(),
                "serial":self.prefs.serial,"options":self.prefs.options,"programmers":self.programmers.iter().map(|p|&p.report).collect::<Vec<_>>(),
                "comparison":self.comparison,"capture":self.replay_path,"transfer_audit":self.audit,"session":self.session_path,"last_error":self.last_error,
                "bundle_review":self.bundle_review,"digest":self.prefs.digest,"verification":self.prefs.verification});
            match serde_json::to_vec_pretty(&report)
                .map_err(anyhow::Error::from)
                .and_then(|d| Ok(std::fs::write(&path, d)?))
            {
                Ok(()) => self.notice = format!("Report saved: {}", path.display()),
                Err(e) => self.last_error = Some(e.to_string()),
            }
        }
    }
    fn navigation(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("navigation")
            .exact_width(248.)
            .show(ctx, |ui| {
                ui.add_space(12.);
                ui.label(RichText::new("SAHARA").size(25.).strong().color(ACCENT));
                ui.label(RichText::new("STUDIO  /  1.0").small().color(MUTED));
                ui.add_space(25.);
                for (page, title) in [
                    (Page::Session, "Session"),
                    (Page::Programmers, "Programmers"),
                    (Page::Replay, "Capture replay"),
                    (Page::Diagnostics, "Diagnostics"),
                ] {
                    if ui
                        .add_sized(
                            [220., 36.],
                            egui::Button::new(title).selected(self.page == page),
                        )
                        .clicked()
                    {
                        self.page = page;
                        self.selected_event = None;
                    }
                }
                ui.add_space(24.);
                ui.separator();
                ui.label(RichText::new("DEVICE INTERFACE").small().color(MUTED));
                ui.add_enabled_ui(!self.busy, |ui| {
                    egui::ComboBox::from_id_salt("ports")
                        .width(210.)
                        .selected_text(&self.prefs.serial.port)
                        .show_ui(ui, |ui| {
                            for p in &self.ports {
                                ui.selectable_value(
                                    &mut self.prefs.serial.port,
                                    p.name.clone(),
                                    format!(
                                        "{}{}",
                                        p.name,
                                        if p.edl { " · Qualcomm EDL" } else { "" }
                                    ),
                                );
                            }
                        });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.prefs.serial.port)
                            .hint_text("COM interface")
                            .desired_width(210.),
                    );
                });
                if let Some(p) = self.ports.iter().find(|p| p.name == self.prefs.serial.port) {
                    ui.label(RichText::new(&p.description).small().color(MUTED));
                } else {
                    ui.label(
                        RichText::new("Interface not currently enumerated")
                            .small()
                            .color(WARNING),
                    );
                }
                if ui.button("Refresh devices").clicked() {
                    self.scan();
                }
                ui.add_space(16.);
                ui.separator();
                ui.label(RichText::new("SESSION CONTROLS").small().color(MUTED));
                if ui
                    .add_enabled(
                        !self.busy,
                        egui::Button::new("Identify device").min_size(egui::vec2(215., 34.)),
                    )
                    .clicked()
                {
                    self.start(false);
                }
                if ui
                    .add_enabled(
                        !self.busy && self.loading == 0 && !self.programmers.is_empty(),
                        egui::Button::new("Upload selected programmer")
                            .fill(Color32::from_rgb(26, 93, 90))
                            .min_size(egui::vec2(215., 36.)),
                    )
                    .clicked()
                {
                    self.start(true);
                }
                if ui
                    .add_enabled(self.busy, egui::Button::new("Cancel session"))
                    .clicked()
                {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                ui.add_space(12.);
                ui.label(
                    RichText::new("RAM upload and identification only.")
                        .small()
                        .color(ACCENT),
                );
                ui.label(
                    RichText::new("Storage writes, erase and provisioning are unavailable.")
                        .small()
                        .color(MUTED),
                );
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if ui.button("Help / protocol notes").clicked() {
                        self.help = true;
                    }
                    ui.label(
                        RichText::new("Native Rust · egui · offline analysis")
                            .small()
                            .color(MUTED),
                    );
                });
            });
    }
    fn session(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Programmer / digest / verification")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("session_loader")
                    .max_height(310.)
                    .show(ui, |ui| self.loader_ui(ui));
            });
        ui.heading("Live session");
        ui.label(
            RichText::new("Observe the exact exchange. Every full payload is retained on disk.")
                .color(MUTED),
        );
        ui.add_space(12.);
        egui::Frame::group(ui.style())
            .inner_margin(14.)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.state).size(22.).strong().color(ACCENT));
                    if self.busy {
                        ui.spinner();
                    }
                    if let Some(started) = self.session_started {
                        ui.label(format!(
                            "{:.1}s",
                            self.session_elapsed
                                .unwrap_or_else(|| started.elapsed())
                                .as_secs_f32()
                        ));
                    }
                });
                if let Some(p) = self
                    .session_programmer
                    .as_ref()
                    .or_else(|| self.programmers.get(self.selected))
                {
                    ui.label(p.report.path.display().to_string());
                    let progress =
                        (self.extent as f64 / p.report.size.max(1) as f64).clamp(0., 1.) as f32;
                    ui.add(egui::ProgressBar::new(progress).text(format!(
                        "{} supplied · highest requested extent {} / {}",
                        size(self.transferred),
                        size(self.extent),
                        size(p.report.size as u64)
                    )));
                }
                ui.label(&self.stage);
                for line in &self.device {
                    ui.label(line);
                }
            });
        ui.add_space(10.);
        self.activity(ui, false);
    }
    fn activity(&mut self, ui: &mut egui::Ui, replay: bool) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("PROTOCOL ACTIVITY").small().color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter events")
                    .desired_width(220.),
            );
            ui.checkbox(&mut self.follow, "Follow");
        });
        let events = if replay {
            &self.replay[..self.replay_cursor.min(self.replay.len())]
        } else {
            &self.events
        };
        let needle = self.filter.to_lowercase();
        let visible: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                needle.is_empty()
                    || e.event.to_lowercase().contains(&needle)
                    || e.summary.to_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        let height = (ui.available_height() - 180.).max(100.);
        egui::ScrollArea::vertical()
            .id_salt(if replay { "replay_log" } else { "live_log" })
            .max_height(height)
            .min_scrolled_height(height)
            .stick_to_bottom(self.follow)
            .show_rows(ui, 23., visible.len(), |ui, range| {
                for row in range {
                    ui.spacing_mut().button_padding = egui::vec2(3., 2.);
                    let i = visible[row];
                    let e = &events[i];
                    let color = match e.event.as_str() {
                        "ERROR" => Color32::LIGHT_RED,
                        "TX" | "TX_BEGIN" => Color32::from_rgb(126, 174, 251),
                        "STATE" | "COMPLETE" => ACCENT,
                        _ => MUTED,
                    };
                    let summary = e.summary.chars().take(160).collect::<String>();
                    let time = if e.time.chars().count() > 19 {
                        e.time.chars().skip(11).take(8).collect::<String>()
                    } else {
                        e.time.clone()
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(format!("{time}  {:<12} {summary}", e.event))
                                    .monospace()
                                    .color(color),
                            )
                            .wrap_mode(egui::TextWrapMode::Truncate)
                            .selected(self.selected_event == Some(i))
                            .frame(false),
                        )
                        .clicked()
                    {
                        self.selected_event = Some(i);
                        self.follow = false;
                    }
                }
            });
        ui.separator();
        if let Some(e) = self.selected_event.and_then(|i| events.get(i)) {
            ui.label(RichText::new(format!("{} · {} bytes", e.event, e.size)).strong());
            egui::ScrollArea::both()
                .id_salt("packet_details")
                .max_height(135.)
                .show(ui, |ui| {
                    ui.label(&e.summary);
                    if let Some(ref text) = e.hex {
                        let shown = &text[..text.len().min(8192)];
                        let formatted = shown
                            .as_bytes()
                            .chunks(64)
                            .enumerate()
                            .map(|(i, c)| format!("{:08x}  {}", i * 32, String::from_utf8_lossy(c)))
                            .collect::<Vec<_>>()
                            .join("\n");
                        ui.add(
                            egui::Label::new(RichText::new(formatted).monospace()).selectable(true),
                        );
                        if shown.len() < text.len() {
                            ui.label("Preview limited to 4096 bytes. Full data is in the capture.");
                        }
                    }
                });
        } else {
            ui.label(
                RichText::new("Select an event to inspect its decoded fields and payload.")
                    .color(MUTED),
            );
        }
    }
    fn programmers(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Programmer library and native file selection")
            .default_open(false)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("programmers_loader")
                    .max_height(310.)
                    .show(ui, |ui| self.loader_ui(ui));
            });
        ui.horizontal(|ui| {
            ui.heading("Programmers");
            if ui.button("Add files…").clicked()
                && let Some(paths) = rfd::FileDialog::new()
                    .set_directory(self.root.join("Firehoses"))
                    .pick_files()
            {
                for p in paths {
                    self.load_image(p);
                }
            }
            if self.loading > 0 {
                ui.spinner();
                ui.label(format!("Analyzing {} file(s)", self.loading));
            }
        });
        ui.label(
            RichText::new(
                "Read-only parsing and local cryptographic validation. No image is rewritten.",
            )
            .color(MUTED),
        );
        egui::ScrollArea::vertical().show(ui,|ui|{
            for (i,p) in self.programmers.iter().enumerate(){if ui.selectable_label(self.selected==i,format!("{} · {} · {}",p.report.path.file_name().unwrap_or_default().to_string_lossy(),size(p.report.size as u64),p.report.format_name())).clicked(){self.selected=i;self.bundle_review=None;self.review_generation+=1;self.reviewing=false;}}
            ui.separator();
            if let Some(p)=self.programmers.get(self.selected) {
                ui.label(p.report.path.display().to_string());ui.add(egui::Label::new(RichText::new(format!("SHA-256  {}",p.report.sha256)).monospace()).selectable(true));
                if let Some(mbn) = &p.report.mbn { signing_ui(ui, mbn); }
                for (i,e) in p.report.images.iter().enumerate() {
                    egui::CollapsingHeader::new(format!("ELF {} · {}-bit {} · base 0x{:x} · extent 0x{:x}",i+1,e.class,e.machine_name(),e.base,e.extent)).id_salt((self.selected,i)).default_open(i==0).show(ui,|ui|{
                        ui.label(format!("Entry 0x{:x} · flags 0x{:x} · {} program headers · {} section headers",e.entry,e.flags,e.segments.len(),e.section_count));
                        egui::ScrollArea::horizontal().id_salt(("ph",i)).show(ui,|ui|{
                            egui::Grid::new(("segments",self.selected,i)).striped(true).show(ui,|ui|{
                                for s in ["#","Type","File offset","Absolute","VA / PA","File / memory","Flags","Align"]{ui.strong(s);}ui.end_row();
                                for s in &e.segments {
                                    ui.label(s.index.to_string());ui.label(if s.kind==1{"LOAD"}else if s.kind==0{"NULL"}else{"Other"});
                                    ui.monospace(format!("0x{:x}",s.offset));ui.monospace(format!("0x{:x}",s.absolute));ui.monospace(format!("{:x} / {:x}",s.va,s.pa));
                                    ui.monospace(format!("{:x} / {:x}",s.file_size,s.memory_size));ui.monospace(format!("0x{:x}",s.flags));ui.colored_label(if s.aligned{MUTED}else{WARNING},format!("{}{}",s.alignment,if s.aligned{""}else{" !"}));ui.end_row();
                                }
                            });
                        });
                        for s in &e.segments {if let Some(ref signing)=s.signing {signing_ui(ui,signing);}}
                    });
                }
            }else{ui.add_space(30.);ui.label("Select a programmer file of any extension, or browse the bundled Firehoses folders.");}
            ui.add_space(18.);ui.separator();ui.heading("Binary comparison");
            ui.horizontal(|ui|{
                for (id,index) in [("left",&mut self.compare_left),("right",&mut self.compare_right)] {
                    egui::ComboBox::from_id_salt(id).width(280.).selected_text(self.programmers.get(*index).map(|p|p.report.path.file_name().unwrap_or_default().to_string_lossy().into_owned()).unwrap_or_else(||"Select file".into())).show_ui(ui,|ui|{for (i,p) in self.programmers.iter().enumerate(){ui.selectable_value(index,i,p.report.path.file_name().unwrap_or_default().to_string_lossy());}});
                }
                if ui.add_enabled(self.programmers.len()>1,egui::Button::new("Compare")).clicked() && let (Some(a),Some(b))=(self.programmers.get(self.compare_left).cloned(),self.programmers.get(self.compare_right).cloned()) {
                    let tx=self.sender.clone();std::thread::spawn(move||{let _=tx.send(Message::Compared(image::compare(&a,&b)));});
                }
            });
            if let Some(ref diff)=self.comparison {
                ui.label(format!("{} differing bytes across {} ranges",diff.differing_bytes,diff.total_ranges));
                for r in diff.ranges.iter().take(100){ui.monospace(format!("0x{:x}..0x{:x}  {} → {}  {}",r.start,r.end,r.left_preview,r.right_preview,r.location));}
                if diff.total_ranges>100{ui.label("Preview limited to 100 ranges. Export report includes up to 2000 ranges and the total count.");}
            }
        });
    }
    fn replay(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Capture replay");
            if ui.button("Open JSONL…").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_directory(self.data_dir.join("sessions"))
                    .add_filter("Session capture", &["jsonl"])
                    .pick_file()
            {
                let tx = self.sender.clone();
                std::thread::spawn(move || {
                    let result = capture::load(&path).map_err(|e| format!("{e:#}"));
                    let _ = tx.send(Message::Replay(path, result));
                });
            }
        });
        ui.label(
            RichText::new(
                "Offline playback · imports native recordings and existing Python captures",
            )
            .color(ACCENT),
        );
        if let Some(ref p) = self.replay_path {
            ui.label(p.display().to_string());
        }
        ui.horizontal(|ui| {
            if ui
                .button(if self.playing {
                    "Pause"
                } else {
                    "Play from start"
                })
                .clicked()
            {
                self.playing = !self.playing;
                if self.playing && self.replay_cursor >= self.replay.len() {
                    self.replay_cursor = 0;
                }
                self.replay_at = Instant::now();
            }
            if ui.button("Step").clicked() {
                self.playing = false;
                self.replay_cursor = (self.replay_cursor + 1).min(self.replay.len());
            }
            if ui.button("Show all").clicked() {
                self.playing = false;
                self.replay_cursor = self.replay.len();
            }
            ui.add(egui::Slider::new(&mut self.replay_cursor, 0..=self.replay.len()).text("Event"));
            ui.add(egui::Slider::new(&mut self.replay_speed, 1..=100).text("events / tick"));
        });
        if self.playing && self.replay_at.elapsed() > Duration::from_millis(100) {
            self.replay_cursor = (self.replay_cursor + self.replay_speed).min(self.replay.len());
            self.replay_at = Instant::now();
            if self.replay_cursor == self.replay.len() {
                self.playing = false;
            }
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.replay.is_empty() && !self.programmers.is_empty(),
                    egui::Button::new("Verify payloads against selected programmer"),
                )
                .clicked()
                && let Some(p) = self.programmers.get(self.selected)
            {
                self.audit = capture::verify_transfers(&self.replay, &p.bytes);
            }
            if !self.audit.is_empty() {
                let good = self.audit.iter().filter(|x| x.matches).count();
                ui.colored_label(
                    if good == self.audit.len() {
                        ACCENT
                    } else {
                        WARNING
                    },
                    format!("{good}/{} exact payload matches", self.audit.len()),
                );
            }
        });
        self.activity(ui, true);
    }
    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.heading("Diagnostics & experiment configuration");
        ui.label(RichText::new("All hardware operations use the selected interface and create a new immutable session capture.").color(MUTED));
        egui::ScrollArea::vertical().show(ui,|ui|{
            ui.add_enabled_ui(!self.busy,|ui|{
                egui::Grid::new("options").num_columns(2).show(ui,|ui|{
                    ui.label("Serial baud");ui.add(egui::DragValue::new(&mut self.prefs.serial.baud).range(9600..=4_000_000));ui.end_row();
                    ui.label("Wait for EDL interface (s)");ui.add(egui::DragValue::new(&mut self.prefs.serial.wait_seconds).range(0..=120));ui.end_row();
                    ui.label("Read deadline (ms)");ui.add(egui::DragValue::new(&mut self.prefs.options.timeout_ms).range(250..=30000));ui.end_row();
                    ui.label("Control lines");ui.horizontal(|ui|{ui.checkbox(&mut self.prefs.serial.dtr,"DTR");ui.checkbox(&mut self.prefs.serial.rts,"RTS");ui.checkbox(&mut self.prefs.serial.hardware_flow,"RTS/CTS flow control");});ui.end_row();
                    ui.label("Missed HELLO recovery");ui.checkbox(&mut self.prefs.options.missed_hello,"Verified HELLO_RSP v2, min2, command mode");ui.end_row();
                    ui.label("Recovered identity style");ui.checkbox(&mut self.prefs.options.recovered_v3,"V3 chip ID (SM8550); unchecked uses V2 HW-ID");ui.end_row();
                    ui.label("Read device identity");ui.checkbox(&mut self.prefs.options.identity,"Serial and supported chip information");ui.end_row();
                });
            });
            ui.add_space(15.);ui.heading("Offline programmer checks");
            if self.programmers.is_empty(){ui.label("Load programmers on the Programmers screen to run automatic parsing, hash and signature checks.");}
            for p in &self.programmers {
                egui::CollapsingHeader::new(p.report.path.display().to_string()).default_open(true).show(ui,|ui|{
                    ui.label(format!("{} · {} ELF extents; SHA-256 {}",p.report.format_name(),p.report.images.len(),p.report.sha256));
                    for (index,e) in p.report.images.iter().enumerate(){for s in &e.segments {
                        if s.kind==1 && !s.aligned{ui.colored_label(WARNING,format!("ELF {} segment {} has noncongruent alignment",index+1,s.index));}
                        if let Some(ref sign)=s.signing {
                            ui.label(format!("ELF {}: {}",index+1,sign.image_signature));
                            let mismatches:Vec<_>=sign.hash_entries.iter().filter(|h|!h.zero && !h.direct_match).map(|h|h.index).collect();
                            ui.colored_label(if mismatches.is_empty(){ACCENT}else{WARNING},format!("Nonzero hash-entry mismatches: {mismatches:?}"));
                            ui.label(format!("OEM rollback {:?}; target enforced counter is unknown",sign.oem_metadata.rollback));
                        }
                    }}
                });
            }
            ui.separator();ui.heading("Investigation baseline");
            ui.label("• Missing greeting recovers with a command-mode HELLO_RSP; no Firehose XML or streaming probes.");
            ui.label("• Each requested payload is supplied in one logical serial write; reported partial writes resume the remaining buffer.");
            ui.label("• Concatenated MELF uses image ID 13 and absolute file offsets. No image splitting or signed-byte changes.");
            ui.label("• Status 0x08: invalid received image-data size. Status 0x21: hash-table authentication failure.");
            ui.label("• Valid local signatures do not prove target trust, authorization, or rollback acceptance.");
            ui.label("• No Firehose/VIP commands or storage mutation API is implemented in this release.");
            ui.add_space(12.);if ui.button("Open session folder").clicked(){let folder=self.data_dir.join("sessions");let _=std::fs::create_dir_all(&folder);let _=std::process::Command::new("explorer.exe").arg(folder).spawn();}
        });
    }
}

impl eframe::App for Studio {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.pump();
        if self.scan_at.elapsed() > Duration::from_secs(3) {
            self.scan();
        }
        ctx.request_repaint_after(Duration::from_millis(if self.busy || self.playing {
            50
        } else {
            250
        }));
        if ctx.input(|i| i.key_pressed(egui::Key::F1)) {
            self.help = true;
        }
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("EDL  /  Sahara investigation workspace").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export report…").clicked() {
                        self.export();
                    }
                    ui.colored_label(ACCENT, "NON-DESTRUCTIVE");
                });
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(
                    if self.busy { ACCENT } else { MUTED },
                    if self.busy {
                        "● Session active"
                    } else {
                        "● Idle"
                    },
                );
                ui.separator();
                ui.label(&self.notice);
            });
        });
        self.navigation(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(error) = self.last_error.clone() {
                egui::Frame::group(ui.style())
                    .fill(Color32::from_rgb(61, 34, 36))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(Color32::LIGHT_RED, &error);
                            if ui.small_button("Dismiss").clicked() {
                                self.last_error = None;
                            }
                        });
                    });
                ui.add_space(10.);
            }
            match self.page {
                Page::Session => self.session(ui),
                Page::Programmers => self.programmers(ui),
                Page::Replay => self.replay(ui),
                Page::Diagnostics => self.diagnostics(ui),
            }
        });
        egui::Window::new("Sahara Studio help").open(&mut self.help).default_width(600.).show(ctx,|ui|{
            ui.heading("A native workspace for reproducible Sahara diagnostics");
            ui.label("1. Add unchanged programmers on the Programmers screen. Inspect their ELF components, certificates, signatures and hashes; compare two files.");
            ui.label("2. Select the enumerated Qualcomm COM interface. Identify device opens a bounded command session; Upload selected programmer also supplies only target-requested RAM image data.");
            ui.label("3. Reconnect the phone in EDL before a new hardware experiment after a rejection or cancellation. The application never silently resets the device.");
            ui.label("4. Captures record every complete payload and write result. Open a JSONL capture for offline replay and verify payloads against a selected programmer.");
            ui.label("5. Export report saves parsed metadata and comparison results. The original input images are never edited.");
            ui.colored_label(WARNING,"Upload can execute a supplied programmer in RAM. Select a trusted target-compatible programmer. Storage writes, erase, provisioning and security changes are unavailable.");
            ui.label("The existing SM8550 baseline reaches ELF 4's hash table and status 0x21. This is a target rejection; it does not identify a specific trust/rollback policy by itself.");
        });
    }
    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.cancel.store(true, Ordering::Relaxed);
        self.prefs.selected_programmer = self
            .programmers
            .get(self.selected)
            .map(|p| p.report.path.clone());
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.prefs) {
            let _ = std::fs::write(self.data_dir.join("settings.json"), bytes);
        }
    }
}

fn signing_ui(ui: &mut egui::Ui, s: &image::Signing) {
    ui.add_space(8.);
    ui.label(
        RichText::new(format!(
            "MBN v{} · software ID {:?} · hash algorithm {:?}",
            s.version, s.software_id, s.hash_algorithm
        ))
        .strong()
        .color(ACCENT),
    );
    ui.label(&s.image_signature);
    ui.label(format!(
        "OEM rollback {:?} · OEM {:?} · product {:?} · flags {:?}",
        s.oem_metadata.rollback,
        s.oem_metadata.oem_id,
        s.oem_metadata.product_id,
        s.oem_metadata.flags
    ));
    ui.label(format!(
        "{} segment-hash entries · {} padding bytes",
        s.hash_entries.len(),
        s.trailing_bytes
    ));
    egui::CollapsingHeader::new("Signing metadata, hashes and certificates").id_salt((s.software_id,s.version,s.header_words.clone())).show(ui,|ui|{
        ui.label("Cryptographic consistency is local. No fused trust anchor or enforced rollback counter was read.");
        for (authority,certs) in [("QTI",&s.qti_certificates),("OEM",&s.oem_certificates)] {for cert in certs {
            ui.label(RichText::new(format!("{authority}: {}",cert.subject)).strong());ui.label(format!("Issuer: {} · certificate signature: {}",cert.issuer,cert.issuer_signature));
            ui.monospace(format!("SHA-256 {}",cert.sha256));ui.label(format!("{} → {}",cert.valid_from,cert.valid_until));
        }}
        for h in &s.hash_entries{ui.monospace(format!("Segment {:>2}: {}  {}",h.index,if h.zero{"omitted / zero entry"}else if h.direct_match{"SHA-384 matches"}else{"SHA-384 mismatch"},h.stored));}
        if let Ok(mut report)=serde_json::to_string_pretty(s){ui.add(egui::TextEdit::multiline(&mut report).font(egui::TextStyle::Monospace).desired_rows(8).interactive(false));}
    });
}
fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / 1048576.)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.)
    } else {
        format!("{bytes} B")
    }
}
fn find_root() -> PathBuf {
    let executable_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    root_for_executable(&executable_dir)
}

fn root_for_executable(executable_dir: &Path) -> PathBuf {
    // A distribution must remain portable, even when started from a source checkout.
    if executable_dir.join("Firehoses").is_dir() {
        return executable_dir.into();
    }
    for path in executable_dir.ancestors() {
        if path.join("crates/edl-studio/Cargo.toml").is_file() {
            return path.into();
        }
    }
    executable_dir.into()
}

fn data_directory(root: &Path) -> PathBuf {
    if root.join("crates/edl-studio/Cargo.toml").is_file() {
        root.into()
    } else {
        root.join("data")
    }
}

fn companion_picker(
    ui: &mut egui::Ui,
    role: &str,
    selected: &mut Option<PathBuf>,
    candidates: &[PathBuf],
    directory: &Path,
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(role);
        egui::ComboBox::from_id_salt(("companion", role))
            .width(430.)
            .selected_text(
                selected
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "None (standalone)".into()),
            )
            .show_ui(ui, |ui| {
                ui.selectable_value(selected, None, "None (standalone)");
                for path in candidates {
                    ui.selectable_value(
                        selected,
                        Some(path.clone()),
                        path.file_name().unwrap_or_default().to_string_lossy(),
                    );
                }
            });
        if ui.button(format!("Browse {role}…")).clicked()
            && let Some(path) = rfd::FileDialog::new().set_directory(directory).pick_file()
        {
            *selected = Some(path);
        }
        if ui.small_button("Clear").clicked() {
            *selected = None;
        }
    });
}

#[cfg(test)]
mod path_tests {
    use super::*;
    #[test]
    fn cargo_launches_share_the_workspace_preferences() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(root_for_executable(&root.join("target/debug")), root);
        assert_eq!(data_directory(&root), root);
    }
    #[test]
    fn packaged_launches_use_the_executable_folder() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        // A non-workspace executable outside the source tree always uses its own data folder.
        let portable = std::env::temp_dir().join("sahara-portable-path-test");
        assert_eq!(root_for_executable(&portable), portable);
        assert_eq!(data_directory(&portable), portable.join("data"));
        assert_eq!(root_for_executable(&root), root);
    }
}
