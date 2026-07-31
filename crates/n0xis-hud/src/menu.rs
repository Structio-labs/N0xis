//! Rendering of the cheat list over the shared [`Engine`]. Pure UI: it reads
//! engine state to draw checkboxes/labels and calls back into the engine to
//! toggle or rebind. All logic and state live in `engine.rs`.

use eframe::egui;
use n0xis_contracts::TableEntry;

use crate::engine::Engine;

pub fn render(ui: &mut egui::Ui, ctx: &egui::Context, engine: &mut Engine) {
    let mut groups: Vec<String> = Vec::new();
    let mut rows: Vec<(String, TableEntry)> = Vec::new();
    for table in engine.tables() {
        for entry in &table.entries {
            let group = entry.groups.first().cloned().unwrap_or_else(|| "General".to_string());
            if !groups.contains(&group) {
                groups.push(group.clone());
            }
            rows.push((table.name.clone(), entry.clone()));
        }
    }

    let pid = engine.pid();
    for group in &groups {
        egui::CollapsingHeader::new(egui::RichText::new(group).strong()).default_open(true).show(ui, |ui| {
            for (table_name, entry) in rows.iter().filter(|(_, e)| {
                e.groups.first() == Some(group) || (e.groups.is_empty() && group == "General")
            }) {
                render_row(ui, engine, pid, table_name, entry);
            }
        });
        ui.add_space(4.0);
    }

    render_sequences(ui, engine, pid);
    render_stratagems(ui, engine, pid);

    if rows.is_empty() && engine.config().sequences.combo.is_empty() {
        ui.weak("No entries. Check hud.toml's `tables = [...]` / `[[sequences.combo]]`.");
    }

    if let Some((table_name, entry_name)) = engine.rebind_capture.clone() {
        render_rebind_popup(ctx, engine, &table_name, &entry_name);
    }
    if let Some(name) = engine.seq_rebind_capture.clone() {
        render_seq_rebind_popup(ctx, engine, &name);
    }
    if let Some(name) = engine.stratagem_rebind.clone() {
        render_stratagem_rebind_popup(ctx, engine, &name);
    }
}

/// Stratagem input macros (Ctrl-held direction code, sent via Interception —
/// the game ignores SendInput). Speed (hold/gap) and hotkey are both runtime-
/// adjustable, same shape as the Combo Solver panel below, but as their own
/// independent settings (a stratagem code has no wrong-input penalty, so it
/// wants to run much faster than the combo solver's deliberately-conservative
/// per-mine timing).
fn render_stratagems(ui: &mut egui::Ui, engine: &mut Engine, pid: Option<u32>) {
    let macros = engine.config().stratagem.clone();
    if macros.is_empty() {
        return;
    }
    egui::CollapsingHeader::new(egui::RichText::new("Stratagems").strong()).default_open(true).show(ui, |ui| {
        let mut hold = engine.stratagem_hold_ms();
        let mut gap = engine.stratagem_gap_ms();
        ui.horizontal(|ui| {
            ui.weak("key hold");
            if ui.add(egui::DragValue::new(&mut hold).suffix(" ms").range(1..=500).speed(1.0)).changed() {
                engine.set_stratagem_hold_ms(hold);
            }
            ui.add_space(8.0);
            ui.weak("gap");
            if ui.add(egui::DragValue::new(&mut gap).suffix(" ms").range(1..=500).speed(1.0)).changed() {
                engine.set_stratagem_gap_ms(gap);
            }
        });
        ui.add_space(2.0);
        for m in &macros {
            let hotkey = engine.stratagem_hotkey(&m.name);
            ui.horizontal(|ui| {
                if ui.add_enabled(pid.is_some(), egui::Button::new("\u{25B6}")).on_hover_text("Run now").clicked() {
                    engine.run_stratagem_macro(&m.name);
                }
                ui.label(&m.name).on_hover_text(m.steps.join(" · "));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("\u{2699}").on_hover_text("Bind / unbind a hotkey").clicked() {
                        engine.stratagem_rebind = Some(m.name.clone());
                        engine.rebind_conflict = None;
                    }
                    if let Some(hk) = &hotkey {
                        ui.label(egui::RichText::new(format!(" {hk} ")).monospace().background_color(
                            ui.visuals().widgets.inactive.bg_fill,
                        ));
                    }
                });
            });
        }
    });
    ui.add_space(4.0);
}

fn render_stratagem_rebind_popup(ctx: &egui::Context, engine: &mut Engine, name: &str) {
    let mut done = false;
    let current = engine.stratagem_hotkey(name);
    egui::Window::new(format!("Bind key: {name}")).collapsible(false).resizable(false).show(ctx, |ui| {
        ui.label("Press a key...");
        if let Some(hk) = &current {
            ui.weak(format!("Currently bound to {hk}."));
        }
        if let Some(conflict) = &engine.rebind_conflict {
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), conflict);
        }
        let pressed = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Key { key, pressed: true, .. } => key_name(*key),
                _ => None,
            })
        });
        if let Some(k) = pressed {
            match engine.try_set_stratagem_hotkey(name, k) {
                Ok(()) => done = true,
                Err(e) => engine.rebind_conflict = Some(e),
            }
        }
        ui.horizontal(|ui| {
            if current.is_some() && ui.button("Unbind").clicked() {
                engine.clear_stratagem_hotkey(name);
                done = true;
            }
            if ui.button("Cancel").clicked() {
                done = true;
            }
        });
    });
    if done {
        engine.stratagem_rebind = None;
        engine.rebind_conflict = None;
    }
}

/// The "Combinations" group: input-macro combos (variant A). Each row has a
/// Run button, a gear to bind a hotkey, and an editable per-step delay (ms) —
/// the "execution speed" setting.
fn render_sequences(ui: &mut egui::Ui, engine: &mut Engine, pid: Option<u32>) {
    let seq = engine.config().sequences.clone();
    if seq.combo.is_empty() {
        return;
    }
    egui::CollapsingHeader::new(egui::RichText::new(&seq.group).strong()).default_open(true).show(ui, |ui| {
        for combo in &seq.combo {
            let name = combo.name.clone();
            let hotkey = engine.seq_hotkey(&name);
            let mut delay = engine.seq_delay(&name);

            ui.horizontal(|ui| {
                if ui.add_enabled(pid.is_some(), egui::Button::new("\u{25B6}")).on_hover_text("Run now").clicked() {
                    engine.run_sequence(&name);
                }
                ui.label(&name).on_hover_text(combo.steps.join(" · "));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("\u{2699}").on_hover_text("Bind / unbind a hotkey").clicked() {
                        engine.seq_rebind_capture = Some(name.clone());
                        engine.rebind_conflict = None;
                    }
                    if let Some(hk) = &hotkey {
                        ui.label(egui::RichText::new(format!(" {hk} ")).monospace().background_color(
                            ui.visuals().widgets.inactive.bg_fill,
                        ));
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                ui.weak("speed");
                if ui.add(egui::DragValue::new(&mut delay).suffix(" ms").range(0..=1000).speed(1.0)).changed() {
                    engine.set_seq_delay(&name, delay);
                }
            });
            ui.add_space(2.0);
        }
    });
    ui.add_space(4.0);
}

fn render_row(ui: &mut egui::Ui, engine: &mut Engine, pid: Option<u32>, table_name: &str, entry: &TableEntry) {
    let mut on = engine.is_on(table_name, entry);
    let was_on = on;

    let bg = if on {
        ui.visuals().selection.bg_fill.linear_multiply(0.25)
    } else {
        egui::Color32::TRANSPARENT
    };

    egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(4.0, 3.0)).show(ui, |ui| {
        ui.horizontal(|ui| {
            let cb = ui.add_enabled(pid.is_some(), egui::Checkbox::new(&mut on, &entry.name));
            if let Some(desc) = &entry.description {
                cb.on_hover_text(desc);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("\u{2699}").on_hover_text("Bind / unbind a hotkey").clicked() {
                    engine.rebind_capture = Some((table_name.to_string(), entry.name.clone()));
                    engine.rebind_conflict = None;
                }
                if let Some(hk) = &entry.hotkey {
                    ui.label(egui::RichText::new(format!(" {hk} ")).monospace().background_color(
                        ui.visuals().widgets.inactive.bg_fill,
                    ));
                }
            });
        });
    });

    if on != was_on {
        engine.apply_toggle(table_name, entry, on);
    }
}

fn render_rebind_popup(ctx: &egui::Context, engine: &mut Engine, table_name: &str, entry_name: &str) {
    let mut done = false;
    let current_hotkey =
        engine.tables().iter().find(|t| t.name == table_name).and_then(|t| t.entries.iter().find(|e| e.name == entry_name)).and_then(|e| e.hotkey.clone());

    egui::Window::new(format!("Bind key: {entry_name}")).collapsible(false).resizable(false).show(ctx, |ui| {
        ui.label("Press a key...");
        if let Some(hk) = &current_hotkey {
            ui.weak(format!("Currently bound to {hk}."));
        }
        if let Some(conflict) = &engine.rebind_conflict {
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), conflict);
        }

        let pressed = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Key { key, pressed: true, .. } => key_name(*key),
                _ => None,
            })
        });
        if let Some(name) = pressed {
            match engine.try_set_hotkey(table_name, entry_name, name) {
                Ok(()) => done = true,
                Err(e) => engine.rebind_conflict = Some(e),
            }
        }

        ui.horizontal(|ui| {
            if current_hotkey.is_some() && ui.button("Unbind").clicked() {
                engine.clear_hotkey(table_name, entry_name);
                done = true;
            }
            if ui.button("Cancel").clicked() {
                done = true;
            }
        });
    });
    if done {
        engine.rebind_capture = None;
        engine.rebind_conflict = None;
    }
}

fn render_seq_rebind_popup(ctx: &egui::Context, engine: &mut Engine, name: &str) {
    let mut done = false;
    let current = engine.seq_hotkey(name);
    egui::Window::new(format!("Bind key: {name}")).collapsible(false).resizable(false).show(ctx, |ui| {
        ui.label("Press a key...");
        if let Some(hk) = &current {
            ui.weak(format!("Currently bound to {hk}."));
        }
        if let Some(conflict) = &engine.rebind_conflict {
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), conflict);
        }
        let pressed = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Key { key, pressed: true, .. } => key_name(*key),
                _ => None,
            })
        });
        if let Some(k) = pressed {
            match engine.try_set_seq_hotkey(name, k) {
                Ok(()) => done = true,
                Err(e) => engine.rebind_conflict = Some(e),
            }
        }
        ui.horizontal(|ui| {
            if current.is_some() && ui.button("Unbind").clicked() {
                engine.clear_seq_hotkey(name);
                done = true;
            }
            if ui.button("Cancel").clicked() {
                done = true;
            }
        });
    });
    if done {
        engine.seq_rebind_capture = None;
        engine.rebind_conflict = None;
    }
}

/// Map an egui key to the same name-string vocabulary `input::parse_vk`
/// understands (`"F5"`, `"A"`, `"1"`, ...).
fn key_name(key: egui::Key) -> Option<String> {
    use egui::Key::*;
    Some(match key {
        F1 => "F1".into(), F2 => "F2".into(), F3 => "F3".into(), F4 => "F4".into(),
        F5 => "F5".into(), F6 => "F6".into(), F7 => "F7".into(), F8 => "F8".into(),
        F9 => "F9".into(), F10 => "F10".into(), F11 => "F11".into(), F12 => "F12".into(),
        A => "A".into(), B => "B".into(), C => "C".into(), D => "D".into(), E => "E".into(),
        F => "F".into(), G => "G".into(), H => "H".into(), I => "I".into(), J => "J".into(),
        K => "K".into(), L => "L".into(), M => "M".into(), N => "N".into(), O => "O".into(),
        P => "P".into(), Q => "Q".into(), R => "R".into(), S => "S".into(), T => "T".into(),
        U => "U".into(), V => "V".into(), W => "W".into(), X => "X".into(), Y => "Y".into(),
        Z => "Z".into(),
        Num0 => "0".into(), Num1 => "1".into(), Num2 => "2".into(), Num3 => "3".into(),
        Num4 => "4".into(), Num5 => "5".into(), Num6 => "6".into(), Num7 => "7".into(),
        Num8 => "8".into(), Num9 => "9".into(),
        ArrowUp => "Up".into(), ArrowDown => "Down".into(), ArrowLeft => "Left".into(), ArrowRight => "Right".into(),
        Space => "Space".into(),
        _ => return None,
    })
}
