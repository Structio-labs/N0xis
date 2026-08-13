//! N0xHUD — a config-driven cheat companion for the n0xis engine, in the
//! a separate always-on-top window mold: a normal always-visible window listing the connected
//! target(s) and their cheats, toggled by mouse *or* by global hotkeys that
//! fire while the game is focused (no alt-tab needed), with the window
//! itself hidden/shown by its own hotkey. It deliberately does **not** draw
//! inside the game — a true in-game overlay needs process injection + a
//! graphics-API present-hook (ROADMAP Phase 6); this model works reliably
//! today, including for fullscreen games.
//!
//! See `docs/n0xhud/CONCEPT.md` / `docs/n0xhud/ROADMAP.md`.

//! Platform note: every module below is Windows-only — the global low-level
//! keyboard hook, the live-process engine, the show/hide of this crate's own
//! HWND. They are `cfg(windows)`-gated rather than simply absent so that
//! `cargo build --workspace` succeeds on Linux (where the rest of the toolkit
//! — static PE analysis, the decompiler, the LuaJIT reader — is fully usable)
//! and this binary degrades to the stub `main` at the bottom of the file.

#[cfg(windows)]
mod adapters;
#[cfg(windows)]
mod plugin_poll;
#[cfg(windows)]
mod config;
#[cfg(windows)]
mod engine;
#[cfg(windows)]
mod freeze;
#[cfg(windows)]
mod input;
#[cfg(windows)]
mod interception;
#[cfg(windows)]
mod menu;
#[cfg(windows)]
mod sequence;
#[cfg(windows)]
mod sound;
#[cfg(windows)]
mod watcher;

#[cfg(windows)]
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use eframe::egui;

#[cfg(windows)]
use config::HudConfig;
#[cfg(windows)]
use engine::Engine;

#[cfg(windows)]
struct HudApp {
    engine: Arc<Mutex<Engine>>,
    toggle_key_label: String,
}

#[cfg(windows)]
impl eframe::App for HudApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut e = self.engine.lock().unwrap();

        // Pull the few scalars the header/footer need, so those panels don't
        // hold a borrow that conflicts with the central panel's &mut render.
        let pid = e.pid();
        let process_name = e.config().watch.process_name.clone();
        let log: Vec<String> = e.log().to_vec();
        let toggle_key = self.toggle_key_label.clone();

        egui::TopBottomPanel::top("targets").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.heading("N0xHUD");
            ui.horizontal(|ui| match pid {
                Some(pid) => {
                    ui.colored_label(egui::Color32::from_rgb(80, 200, 120), "\u{25cf}");
                    ui.label(format!("{process_name} · running (pid {pid})"));
                }
                None => {
                    ui.colored_label(egui::Color32::GRAY, "\u{25cb}");
                    ui.label(format!("{process_name} · waiting…"));
                }
            });
            ui.add_space(4.0);
        });

        // Resizable so the log can be dragged taller when something is being
        // diagnosed, and scrollable so a long run stays readable from the start.
        egui::TopBottomPanel::bottom("hint").min_height(0.0).resizable(true).show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.weak(format!("{toggle_key} hides/shows this window · cheat hotkeys work in-game"));
                if !log.is_empty() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("clear").on_hover_text("Clear the log").clicked() {
                            e.clear_log();
                        }
                        if ui.small_button("copy").on_hover_text("Copy the whole log to the clipboard").clicked() {
                            ui.output_mut(|o| o.copied_text = log.join("\n"));
                        }
                    });
                }
            });
            if !log.is_empty() {
                ui.separator();
                // Sticks to the newest line, but scrolls back to the very first.
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .stick_to_bottom(true)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for line in &log {
                            ui.weak(line);
                        }
                    });
            }
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                menu::render(ui, ctx, &mut e);
            });
        });

        // Keep the UI reflecting watcher/hotkey changes made on other threads.
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    let root = n0xis_project::resolve()
        .expect("resolve .n0x/ project (run n0xis-hud from inside a game's .n0x/ project directory)");
    // Pin the project dir now, while the cwd is still correct — eframe/GL init
    // can change the process cwd, so anything loaded later must use this path.
    let project_dir = root.dir.clone();
    let cfg_path = root.dir.join("hud.toml");
    let config = HudConfig::load(&cfg_path).unwrap_or_else(|e| panic!("failed to load {}: {e}", cfg_path.display()));

    let toggle_key_label = config.menu.toggle_key.clone();
    let toggle_vk = input::parse_vk(&config.menu.toggle_key);
    let dark = !config.overlay.theme.eq_ignore_ascii_case("light");

    let engine = Arc::new(Mutex::new(Engine::new(config, project_dir)));
    input::spawn(toggle_vk, engine.clone());
    watcher::spawn(engine.clone());
    plugin_poll::spawn(engine.clone());

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("N0xHUD")
            .with_inner_size([360.0, 520.0])
            .with_min_inner_size([300.0, 300.0])
            .with_always_on_top(),
        ..Default::default()
    };

    eframe::run_native(
        "N0xHUD",
        native_options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(if dark { egui::Visuals::dark() } else { egui::Visuals::light() });
            Ok(Box::new(HudApp { engine, toggle_key_label }))
        }),
    )
}

/// Off Windows the crate builds but the binary cannot do its job: it exists to
/// drive a *live* process through Win32 and to own a global keyboard hook, and
/// there is no Linux `LiveProcess`/`Debugger` implementation behind the source
/// seam yet. Fail loudly rather than opening an empty window — and point at the
/// route that does work from here, since `remote-serve` lets a Linux host drive
/// a Windows target over stdio/SSH.
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("n0xis-hud: Windows-only — it needs the LiveProcess adapter and a global keyboard hook.");
    eprintln!("The static half of the toolkit works here: use `n0xis` (CLI) or `n0xis-mcp`.");
    eprintln!("To drive a Windows target from this machine, run `n0xis remote-serve` there and");
    eprintln!("point the CLI at it with `--remote-cmd`.");
    std::process::ExitCode::FAILURE
}
