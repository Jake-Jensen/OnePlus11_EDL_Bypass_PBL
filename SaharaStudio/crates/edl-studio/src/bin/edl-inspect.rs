use anyhow::{Result, bail};
use edl_core::{capture, image::Programmer};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("catalog") if args.len() == 3 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&edl_core::catalog::scan(Path::new(&args[2]))?)?
            );
        }
        Some("review") if args.len() == 5 => {
            let review = edl_core::catalog::review(
                Path::new(&args[2]),
                optional(&args[3]),
                optional(&args[4]),
            )?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Some("inspect") if args.len() == 3 => {
            let p = Programmer::load(Path::new(&args[2]))?;
            println!("{}", serde_json::to_string_pretty(&p.report)?);
        }
        Some("compare") if args.len() == 4 => {
            let a = Programmer::load(Path::new(&args[2]))?;
            let b = Programmer::load(Path::new(&args[3]))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&edl_core::image::compare(&a, &b))?
            );
        }
        Some("verify") if args.len() == 4 => {
            let e = capture::load(Path::new(&args[2]))?;
            let p = Programmer::load(Path::new(&args[3]))?;
            let checks = capture::verify_transfers(&e, &p.bytes);
            println!("{}", serde_json::to_string_pretty(&checks)?);
            if checks.is_empty() || checks.iter().any(|x| !x.matches) {
                bail!("Capture payload verification failed");
            }
        }
        None | Some("--help" | "-h") => {
            println!(
                "edl-inspect inspect PROGRAMMER\nedl-inspect compare LEFT RIGHT\nedl-inspect verify CAPTURE.jsonl PROGRAMMER\nedl-inspect catalog FOLDER\nedl-inspect review PROGRAMMER DIGEST VERIFICATION\nUse - for an omitted companion. Read-only offline analysis; no device access."
            );
        }
        _ => bail!("Invalid arguments. Run edl-inspect --help for usage."),
    }
    Ok(())
}

fn optional(value: &str) -> Option<&Path> {
    (value != "-").then(|| Path::new(value))
}
