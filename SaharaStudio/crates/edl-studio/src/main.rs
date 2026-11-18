#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod app;
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1380., 900.])
            .with_min_inner_size([1050., 700.])
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Sahara Studio",
        options,
        Box::new(|cc| Ok(Box::new(app::Studio::new(cc)))),
    )
}

fn app_icon() -> eframe::egui::IconData {
    let mut rgba = vec![0u8; 64 * 64 * 4];
    for y in 0..64usize {
        for x in 0..64usize {
            let wave = (12..22).contains(&y) && (16..50).contains(&x)
                || (27..37).contains(&y) && (10..44).contains(&x)
                || (42..52).contains(&y) && (16..50).contains(&x);
            rgba[(y * 64 + x) * 4..(y * 64 + x + 1) * 4].copy_from_slice(if wave {
                &[68, 206, 191, 255]
            } else {
                &[19, 25, 36, 255]
            });
        }
    }
    eframe::egui::IconData {
        rgba,
        width: 64,
        height: 64,
    }
}
