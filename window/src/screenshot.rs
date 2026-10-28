//! Select a region of immutable PNG pixels supplied by the trusted host helper.
//! No display capture, clipboard access, file writes or late recapture here.
use std::io::{Read, Write};

use crate::i18n::{text as tr, Key as UiKey, Language};
use iced::keyboard::{key, Key};
use iced::mouse;
use iced::widget::{button, canvas, column, container, row, text};
use iced::{
    Color, Element, Length, Point, Rectangle, Renderer, Size, Subscription, Task, Theme, Vector,
};

const LIMIT: usize = 64 << 20;
fn label(key: UiKey) -> &'static str {
    tr(Language::default(), key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Crop {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

fn crop_between(a: Point, b: Point, w: u32, h: u32) -> Option<Crop> {
    if ![a.x, a.y, b.x, b.y].into_iter().all(f32::is_finite) {
        return None;
    }
    let x = a.x.min(b.x).floor().clamp(0.0, w as f32) as u32;
    let y = a.y.min(b.y).floor().clamp(0.0, h as f32) as u32;
    let right = a.x.max(b.x).ceil().clamp(0.0, w as f32) as u32;
    let bottom = a.y.max(b.y).ceil().clamp(0.0, h as f32) as u32;
    (right > x && bottom > y).then_some(Crop {
        x,
        y,
        w: right - x,
        h: bottom - y,
    })
}

fn encode(image: &crate::thumb::Thumb, crop: Crop) -> Result<Vec<u8>, String> {
    if crop.w == 0
        || crop.h == 0
        || crop.x.checked_add(crop.w).is_none_or(|n| n > image.width)
        || crop.y.checked_add(crop.h).is_none_or(|n| n > image.height)
    {
        return Err("invalid crop".into());
    }
    let mut pixels = Vec::with_capacity(crop.w as usize * crop.h as usize * 4);
    for y in crop.y..crop.y + crop.h {
        let at = (y as usize * image.width as usize + crop.x as usize) * 4;
        pixels.extend_from_slice(&image.rgba[at..at + crop.w as usize * 4]);
    }
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, crop.w, crop.h);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
        writer
            .write_image_data(&pixels)
            .map_err(|e| e.to_string())?;
    }
    if output.len() > LIMIT {
        return Err("encoded crop exceeds budget".into());
    }
    Ok(output)
}

struct Editor {
    pixels: crate::thumb::Thumb,
    image: iced::widget::image::Handle,
    crop: Option<Crop>,
    error: Option<String>,
    focused: bool,
    touched: std::time::Instant,
}
#[derive(Debug, Clone)]
enum Msg {
    Crop(Option<Crop>),
    Confirm,
    Cancel,
    Focus(bool),
    Activity,
    Hold,
    Tick,
}

impl Editor {
    fn ready(&self) -> bool {
        self.focused && self.touched.elapsed() >= std::time::Duration::from_millis(1500)
    }
    fn update(&mut self, message: Msg) -> Task<Msg> {
        match message {
            Msg::Crop(crop) => {
                self.crop = crop;
                self.error = None;
                self.touched = std::time::Instant::now();
            }
            Msg::Focus(focused) => {
                self.focused = focused;
                self.touched = std::time::Instant::now();
            }
            Msg::Activity if !self.ready() => self.touched = std::time::Instant::now(),
            Msg::Hold => self.touched = std::time::Instant::now(),
            Msg::Activity | Msg::Tick => {}
            Msg::Cancel => std::process::exit(1),
            Msg::Confirm if !self.ready() => self.touched = std::time::Instant::now(),
            Msg::Confirm => {
                if let Some(crop) = self.crop {
                    match encode(&self.pixels, crop) {
                        Ok(bytes) => {
                            let mut stdout = std::io::stdout().lock();
                            let status = if stdout
                                .write_all(&bytes)
                                .and_then(|_| stdout.flush())
                                .is_ok()
                            {
                                0
                            } else {
                                1
                            };
                            std::process::exit(status);
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
            }
        }
        Task::none()
    }
    fn subscription(&self) -> Subscription<Msg> {
        Subscription::batch([
            if self.focused && !self.ready() {
                Subscription::run(ticks)
            } else {
                Subscription::none()
            },
            iced::event::listen_with(|event, _, _| match event {
                iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key: Key::Named(key::Named::Enter),
                    repeat: false,
                    ..
                }) => Some(Msg::Confirm),
                iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key: Key::Named(key::Named::Escape),
                    ..
                }) => Some(Msg::Cancel),
                iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { .. }) => Some(Msg::Hold),
                iced::Event::Mouse(mouse::Event::ButtonPressed(_)) => Some(Msg::Activity),
                iced::Event::Window(iced::window::Event::Focused) => Some(Msg::Focus(true)),
                iced::Event::Window(iced::window::Event::Unfocused) => Some(Msg::Focus(false)),
                iced::Event::Window(iced::window::Event::CloseRequested) => Some(Msg::Cancel),
                _ => None,
            }),
        ])
    }
    fn view(&self) -> Element<'_, Msg> {
        let dimensions = if self.ready() {
            self.crop
                .map(|r| format!("{} × {}", r.w, r.h))
                .unwrap_or_default()
        } else {
            label(UiKey::Wait).to_owned()
        };
        let toolbar = row![
            text(label(UiKey::ScreenshotSelect)),
            text(dimensions),
            button(text(label(UiKey::ScreenshotCopy)))
                .on_press_maybe(self.crop.filter(|_| self.ready()).map(|_| Msg::Confirm)),
            button(text(label(UiKey::Cancel))).on_press(Msg::Cancel)
        ]
        .spacing(16)
        .align_y(iced::Alignment::Center);
        let canvas = canvas::Canvas::new(Picture { editor: self })
            .width(Length::Fill)
            .height(Length::Fill);
        let mut content = column![
            toolbar,
            text(label(UiKey::ScreenshotInspect)).size(12),
            canvas
        ]
        .spacing(12);
        if self.error.is_some() {
            content = content.push(text(label(UiKey::ScreenshotFailed)));
        }
        container(content)
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

struct Picture<'a> {
    editor: &'a Editor,
}
#[derive(Default)]
struct Drag {
    start: Option<Point>,
    cursor: Option<Point>,
    view: View,
    pan: Option<(Point, Vector)>,
}

#[derive(Clone, Copy)]
struct View {
    zoom: f32,
    offset: Vector,
}
impl Default for View {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            offset: Vector::ZERO,
        }
    }
}
impl View {
    fn rect(self, size: Size, w: u32, h: u32) -> Rectangle {
        let base = fitted(size, w, h);
        Rectangle {
            x: base.x + self.offset.x,
            y: base.y + self.offset.y,
            width: base.width * self.zoom,
            height: base.height * self.zoom,
        }
    }
    fn clamp(&mut self, size: Size, w: u32, h: u32) {
        let base = fitted(size, w, h);
        let rect = self.rect(size, w, h);
        self.offset.x = if rect.width <= size.width {
            (size.width - rect.width) / 2.0 - base.x
        } else {
            rect.x.clamp(size.width - rect.width, 0.0) - base.x
        };
        self.offset.y = if rect.height <= size.height {
            (size.height - rect.height) / 2.0 - base.y
        } else {
            rect.y.clamp(size.height - rect.height, 0.0) - base.y
        };
    }
    fn zoom_at(&mut self, size: Size, w: u32, h: u32, cursor: Point, amount: f32) {
        if !amount.is_finite() || !cursor.x.is_finite() || !cursor.y.is_finite() {
            return;
        }
        let before = self.rect(size, w, h);
        let next = (self.zoom * (amount.clamp(-10.0, 10.0) * 0.15).exp()).clamp(1.0, 32.0);
        let ratio = next / self.zoom;
        self.offset = Vector::new(
            cursor.x - (cursor.x - before.x) * ratio - fitted(size, w, h).x,
            cursor.y - (cursor.y - before.y) * ratio - fitted(size, w, h).y,
        );
        self.zoom = next;
        self.clamp(size, w, h);
    }
}

fn fitted(size: Size, w: u32, h: u32) -> Rectangle {
    let scale = (size.width / w as f32)
        .min(size.height / h as f32)
        .max(0.001);
    let (width, height) = (w as f32 * scale, h as f32 * scale);
    Rectangle {
        x: (size.width - width) / 2.0,
        y: (size.height - height) / 2.0,
        width,
        height,
    }
}

impl canvas::Program<Msg> for Picture<'_> {
    type State = Drag;
    fn mouse_interaction(
        &self,
        state: &Drag,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if !cursor.is_over(bounds) {
            mouse::Interaction::None
        } else if state.pan.is_some() {
            mouse::Interaction::Grabbing
        } else {
            mouse::Interaction::Crosshair
        }
    }
    fn update(
        &self,
        state: &mut Drag,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Msg>> {
        let image = &self.editor.pixels;
        let rect = state.view.rect(bounds.size(), image.width, image.height);
        // Use each motion's own position. The toolkit can batch a press and
        // several motions with `cursor` already at the newest position.
        if let canvas::Event::Mouse(mouse::Event::CursorMoved { position }) = event {
            state.cursor = Some(Point::new(position.x - bounds.x, position.y - bounds.y));
        }
        let local = state.cursor.or_else(|| cursor.position_in(bounds));
        let point = local.map(|p| {
            Point::new(
                ((p.x - rect.x) / rect.width * image.width as f32).clamp(0.0, image.width as f32),
                ((p.y - rect.y) / rect.height * image.height as f32)
                    .clamp(0.0, image.height as f32),
            )
        });
        match event {
            canvas::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: Key::Character(c),
                ..
            }) if c == "0" => {
                state.view = View::default();
                state.pan = None;
                state.start = None;
                Some(canvas::Action::request_redraw().and_capture())
            }
            canvas::Event::Mouse(mouse::Event::WheelScrolled { delta })
                if state.start.is_none() && state.pan.is_none() =>
            {
                let anchor = local?;
                if !Rectangle::with_size(bounds.size()).contains(anchor) {
                    return None;
                }
                let amount = match delta {
                    mouse::ScrollDelta::Lines { y, .. } => *y,
                    mouse::ScrollDelta::Pixels { y, .. } => *y / 40.0,
                };
                state
                    .view
                    .zoom_at(bounds.size(), image.width, image.height, anchor, amount);
                Some(canvas::Action::request_redraw().and_capture())
            }
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Middle))
                if state.start.is_none() =>
            {
                let at = local?;
                if !Rectangle::with_size(bounds.size()).contains(at) {
                    return None;
                }
                state.pan = Some((at, state.view.offset));
                Some(canvas::Action::request_redraw().and_capture())
            }
            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Middle)) => {
                state.pan.take()?;
                Some(canvas::Action::request_redraw().and_capture())
            }
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                if state.pan.is_some() {
                    return None;
                }
                let cursor = local?;
                if !rect.contains(cursor) {
                    return None;
                }
                state.start = point;
                Some(canvas::Action::publish(Msg::Crop(None)).and_capture())
            }
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if let Some((from, offset)) = state.pan {
                    state.view.offset = offset + (local? - from);
                    state.view.clamp(bounds.size(), image.width, image.height);
                    return Some(canvas::Action::request_redraw().and_capture());
                }
                let (a, b) = (state.start?, point?);
                Some(
                    canvas::Action::publish(Msg::Crop(crop_between(
                        a,
                        b,
                        image.width,
                        image.height,
                    )))
                    .and_capture(),
                )
            }
            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                let a = state.start.take()?;
                Some(
                    canvas::Action::publish(Msg::Crop(crop_between(
                        a,
                        point?,
                        image.width,
                        image.height,
                    )))
                    .and_capture(),
                )
            }
            _ => None,
        }
    }
    fn draw(
        &self,
        state: &Drag,
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        _: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let pixels = &self.editor.pixels;
        let image = state.view.rect(bounds.size(), pixels.width, pixels.height);
        frame.with_clip(Rectangle::with_size(bounds.size()), |frame| {
            frame.draw_image(image, &self.editor.image);
            if let Some(crop) = self.editor.crop {
                let scale = image.width / pixels.width as f32;
                let selected = Rectangle {
                    x: image.x + crop.x as f32 * scale,
                    y: image.y + crop.y as f32 * scale,
                    width: crop.w as f32 * scale,
                    height: crop.h as f32 * scale,
                };
                let dim = Color::from_rgba(0.0, 0.0, 0.0, 0.55);
                for rect in [
                    Rectangle {
                        height: selected.y - image.y,
                        ..image
                    },
                    Rectangle {
                        y: selected.y + selected.height,
                        height: image.y + image.height - selected.y - selected.height,
                        ..image
                    },
                    Rectangle {
                        x: image.x,
                        y: selected.y,
                        width: selected.x - image.x,
                        height: selected.height,
                    },
                    Rectangle {
                        x: selected.x + selected.width,
                        y: selected.y,
                        width: image.x + image.width - selected.x - selected.width,
                        height: selected.height,
                    },
                ] {
                    frame.fill_rectangle(Point::new(rect.x, rect.y), rect.size(), dim);
                }
                frame.stroke(
                    &canvas::Path::rectangle(Point::new(selected.x, selected.y), selected.size()),
                    canvas::Stroke::default()
                        .with_width(2.0)
                        .with_color(Color::from_rgb(0.2, 0.9, 0.8)),
                );
            }
        });
        vec![frame.into_geometry()]
    }
}

fn ticks() -> impl iced::futures::Stream<Item = Msg> {
    let (sender, receiver) = iced::futures::channel::mpsc::unbounded();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if sender.unbounded_send(Msg::Tick).is_err() {
            break;
        }
    });
    receiver
}

pub fn run(whole: bool) -> iced::Result {
    let mut input = Vec::new();
    if std::io::stdin()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > LIMIT
    {
        std::process::exit(3);
    }
    let Ok(pixels) = crate::thumb::full_png(&input) else {
        std::process::exit(3)
    };
    let handle =
        iced::widget::image::Handle::from_rgba(pixels.width, pixels.height, pixels.rgba.clone());
    let crop = whole.then_some(Crop {
        x: 0,
        y: 0,
        w: pixels.width,
        h: pixels.height,
    });
    let boot = std::sync::Mutex::new(Some(Editor {
        pixels,
        image: handle,
        crop,
        error: None,
        focused: false,
        touched: std::time::Instant::now(),
    }));
    iced::application(
        move || (boot.lock().unwrap().take().unwrap(), Task::none()),
        Editor::update,
        Editor::view,
    )
    .title(label(UiKey::ScreenshotFrozen))
    .subscription(Editor::subscription)
    .window(iced::window::Settings {
        fullscreen: true,
        exit_on_close_request: false,
        size: Size::new(1100.0, 760.0),
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "cellward-screenshot".into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zoom_stays_under_the_pointer_and_panning_cannot_lose_the_image() {
        let size = Size::new(1000.0, 800.0);
        let mut view = View::default();
        let cursor = Point::new(250.0, 200.0);
        view.zoom_at(size, 1000, 800, cursor, 2.0_f32.ln() / 0.15);
        let rect = view.rect(size, 1000, 800);
        assert!(((cursor.x - rect.x) / rect.width * 1000.0 - 250.0).abs() < 0.001);
        assert!(((cursor.y - rect.y) / rect.height * 800.0 - 200.0).abs() < 0.001);
        view.offset = Vector::new(-100000.0, 100000.0);
        view.clamp(size, 1000, 800);
        let rect = view.rect(size, 1000, 800);
        assert!(rect.x <= 0.0 && rect.x + rect.width >= size.width);
        assert!(rect.y <= 0.0 && rect.y + rect.height >= size.height);
        view.zoom_at(size, 1000, 800, cursor, -10.0);
        assert_eq!(view.zoom, 1.0);
        assert_eq!(view.offset, Vector::ZERO);
    }

    #[test]
    fn zoomed_selection_uses_original_pixel_coordinates() {
        use iced::widget::canvas::Program;
        let editor = Editor {
            pixels: crate::thumb::Thumb {
                width: 1000,
                height: 800,
                rgba: vec![0; 1000 * 800 * 4],
            },
            image: iced::widget::image::Handle::from_rgba(1, 1, vec![0; 4]),
            crop: None,
            error: None,
            focused: true,
            touched: std::time::Instant::now(),
        };
        let picture = Picture { editor: &editor };
        let mut drag = Drag {
            view: View {
                zoom: 2.0,
                offset: Vector::new(-250.0, -200.0),
            },
            ..Default::default()
        };
        let bounds = Rectangle::with_size(Size::new(1000.0, 800.0));
        let cursor = mouse::Cursor::Available(Point::new(550.0, 500.0));
        let motion = |x, y| {
            canvas::Event::Mouse(mouse::Event::CursorMoved {
                position: Point::new(x, y),
            })
        };
        let _ = picture.update(&mut drag, &motion(150.0, 100.0), bounds, cursor);
        let _ = picture.update(
            &mut drag,
            &canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
            bounds,
            cursor,
        );
        let action = picture
            .update(&mut drag, &motion(550.0, 500.0), bounds, cursor)
            .unwrap();
        let (Some(Msg::Crop(crop)), _, _) = action.into_inner() else {
            panic!()
        };
        assert_eq!(
            crop,
            Some(Crop {
                x: 200,
                y: 150,
                w: 200,
                h: 200
            })
        );
    }
    #[test]
    fn a_background_or_just_focused_preview_cannot_confirm_a_copy() {
        let mut editor = Editor {
            pixels: crate::thumb::Thumb {
                width: 1,
                height: 1,
                rgba: vec![0; 4],
            },
            image: iced::widget::image::Handle::from_rgba(1, 1, vec![0; 4]),
            crop: Some(Crop {
                x: 0,
                y: 0,
                w: 1,
                h: 1,
            }),
            error: None,
            focused: false,
            touched: std::time::Instant::now() - std::time::Duration::from_secs(2),
        };
        assert!(!editor.ready());
        let _ = editor.update(Msg::Confirm); // Must not exit or write stdout.
        let _ = editor.update(Msg::Focus(true));
        assert!(!editor.ready());
        editor.touched -= std::time::Duration::from_secs(2);
        assert!(editor.ready());
        let _ = editor.update(Msg::Hold);
        assert!(!editor.ready());
        let _ = editor.update(Msg::Focus(false));
        assert!(!editor.ready());
    }
    #[test]
    fn fast_drag_keeps_the_press_position_when_cursor_events_are_batched() {
        use iced::widget::canvas::Program;
        let editor = Editor {
            pixels: crate::thumb::Thumb {
                width: 1000,
                height: 800,
                rgba: vec![0; 1000 * 800 * 4],
            },
            image: iced::widget::image::Handle::from_rgba(1, 1, vec![0; 4]),
            crop: None,
            error: None,
            focused: true,
            touched: std::time::Instant::now(),
        };
        let picture = Picture { editor: &editor };
        let mut drag = Drag::default();
        let bounds = Rectangle {
            x: 10.0,
            y: 20.0,
            width: 1000.0,
            height: 800.0,
        };
        let newest = mouse::Cursor::Available(Point::new(910.0, 720.0));
        let motion = |x, y| {
            canvas::Event::Mouse(mouse::Event::CursorMoved {
                position: Point::new(x, y),
            })
        };
        let _ = picture.update(&mut drag, &motion(110.0, 140.0), bounds, newest);
        let _ = picture.update(
            &mut drag,
            &canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
            bounds,
            newest,
        );
        let action = picture
            .update(&mut drag, &motion(910.0, 720.0), bounds, newest)
            .unwrap();
        let (Some(Msg::Crop(crop)), _, _) = action.into_inner() else {
            panic!()
        };
        assert_eq!(
            crop,
            Some(Crop {
                x: 100,
                y: 120,
                w: 800,
                h: 580
            })
        );
    }
    #[test]
    fn backwards_and_outside_drag_crop_only_the_frozen_pixels() {
        let crop = crop_between(Point::new(3.9, 2.1), Point::new(-4.0, 1.0), 4, 3).unwrap();
        assert_eq!(
            crop,
            Crop {
                x: 0,
                y: 1,
                w: 4,
                h: 2
            }
        );
        let image = crate::thumb::Thumb {
            width: 4,
            height: 3,
            rgba: (0..48).collect(),
        };
        let encoded = encode(&image, crop).unwrap();
        let decoded = crate::thumb::full_png(&encoded).unwrap();
        assert_eq!((decoded.width, decoded.height), (4, 2));
        assert_eq!(decoded.rgba, image.rgba[16..]);
        assert!(crop_between(Point::ORIGIN, Point::ORIGIN, 4, 3).is_none());
        assert!(crop_between(Point::new(f32::NAN, 1.0), Point::ORIGIN, 4, 3).is_none());
    }
}
