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

mod adapters;
mod config;
mod engine;
mod freeze;
mod input;
mod menu;
mod sequence;
mod sound;
mod watcher;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;

use config::HudConfig;
use engine::Engine;

struct HudApp {
    engine: Arc<Mutex<Engine>>,
    toggle_key_label: String,
}

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

        egui::TopBottomPanel::bottom("hint").min_height(0.0).show(ctx, |ui| {
            ui.add_space(2.0);
            ui.weak(format!("{toggle_key} hides/shows this window · cheat hotkeys work in-game"));
            if !log.is_empty() {
                ui.separator();
                for line in &log {
                    ui.weak(line);
                }
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
