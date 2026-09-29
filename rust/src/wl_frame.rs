//! The zone frame, drawn by the Wayland proxy (`docs/WINDOW-FRAME.md` §5,
//! stage 2): a coloured band of [`crate::frame`]'s width around every
//! toplevel of the program, in its zone's colour, and a title strip of the
//! same colour along its top with `<zone> · <container>` on it
//! (`crate::wl_title` draws the text).
//!
//! **The "trailer" scheme (§5.1).** The border is four subsurfaces of the
//! program's own root surface — top, bottom, left, right —, each one pixel
//! of the colour stretched by `wp_viewport` to its strip; the title strip is
//! a fifth, with the text a subsurface of it. The root surface does not
//! move, so nothing the program knows in surface coordinates changes:
//! pointer and touch positions, text input, pointer constraints, activation
//! are its own as before. What changes is what is relative to the WINDOW
//! GEOMETRY (§5.2), and the proxy translates exactly that — with `B` the
//! border and `T` the title strip when it takes room (mode `always`, not in
//! fullscreen; else 0):
//!
//! | the program says / is told           | the compositor is told / said        |
//! |--------------------------------------|--------------------------------------|
//! | `set_window_geometry(x, y, w, h)`    | `(x−B, y−B−T, w+2B, h+2B+T)`         |
//! | `configure(w, h)`, `configure_bounds` ← | `(w−2B, h−2B−T)`; 0 stays 0       |
//! | `set_min_size`/`set_max_size`        | non-zero `+2B`, `+2B+T`              |
//! | `show_window_menu(x, y)`             | `(x+B, y+B+T)`                       |
//! | a popup's anchor rect, parent size   | `+B`, `+B+T`; `+2B`, `+2B+T` (for the call only) |
//! | `xdg_popup.configure(x, y)` ←        | `(x−B, y−B−T)`                       |
//! | `xdg_toplevel_drag.attach(x, y)`     | `(x+B, y+B+T)`                       |
//!
//! So the frame lies INSIDE the geometry the compositor sees (§1): niri with
//! `clip-to-geometry` and sway, which clips every tiled window, show it, and
//! a compositor that sizes the window gets exactly the size it asked for —
//! the program draws in what is left. Geometry and size limits are
//! double-buffered state of the program's next commit, so the proxy keeps
//! them and sends the translated values just before that commit, together
//! with the strips' new place and size: the strips are synchronized
//! subsurfaces, and the program's commit applies all of it at once — a
//! resize never shows a frame of the old size (§5.3). A program that sets
//! no geometry has the size of its root surface for one (buffer, scale,
//! transform, viewport), and the strips go around that.
//!
//! **Fullscreen** (§5.7). The border stays (the owner's answer, §11), the
//! title strip goes, and its room with it: the configure that says
//! fullscreen is answered less the border only. Which state a commit is of
//! is the configure the program acked last — kept by serial from the
//! compositor's configure to the program's `ack_configure`, so the geometry
//! and the strip laid before a commit match the size the program drew. But
//! whether the strip SHOWS is not the program's alone: it is hidden only
//! while the compositor's latest configure says fullscreen too. A program
//! that acks the fullscreen configure and never the one that ends it is
//! shown out of fullscreen by the compositor all the same; its strip then
//! comes out at once, over the top of its content (its commits have no room
//! for it), until it acks ([`Window::title_wanted`]).
//!
//! **Hover** (§0а). In mode `hover` the strip takes no room: it lies over the
//! top of the program's content, hidden, and comes out while the pointer is
//! at the very top of the window (the top border, the first
//! [`HOVER_EDGE`] pixels of the content) or on the strip itself — seen on the
//! program's own `wl_pointer`, to which the compositor sends the pointer's
//! events over the proxy's surfaces too. Shown and hidden at once, not at the
//! program's next commit: the strip is desynchronized for its own commit and
//! synchronized again ([`TitleParts::apply_now`]); so is the text drawn anew
//! at a new scale.
//!
//! **Buttons, moving, resizing** (stage 3, 2026-09-27; §5.4, §5.5, §5.11).
//! At the look's end of the title strip (`crate::wl_title::buttons_look`:
//! stage 3's at the right end, menu ≡, network ⇄, close ×; macOS's at the
//! left) the buttons are a subsurface of
//! the strip, like the text — placed anew with the strip at every resize,
//! hidden with it (mode `hover`, fullscreen), and not there when the strip
//! is too narrow for them ([`title_layout`]). The pointer over the frame is
//! seen on the program's own `wl_pointer` (the events the filters below drop
//! for the program): the cursor is set by `wp_cursor_shape_v1` when there is
//! one — an arrow of the edges over the border, the default one elsewhere —,
//! the button under the pointer is lit, and the left button acts. Down on
//! the title, `xdg_toplevel.move` goes upstream with the press's serial; on
//! the border, `xdg_toplevel.resize` with the edges of the side, both of a
//! corner within [`CORNER`] of it ([`edges`]): the compositor issued that
//! serial to this connection and takes the request as the program's. A
//! button acts on its release, pressed and let go on it: close is the
//! program's own `xdg_toplevel.close` event, as a server-side decoration's;
//! menu and network are asked of the supervisor ([`Ask`]), which starts
//! `cellward window-menu` for the launch. Only what the compositor sends
//! reaches this: the program cannot name the proxy's surfaces, nor send the
//! events of a pointer. No double click (it would take a clock).
//!
//! **Looks** (2026-09-28, `crate::wl_title::Look`). The style: `full` is
//! the above, the zone's colour itself; `soft` its calmer tones, the border
//! two rings of strips nested one in the other ([`ring_strips`]: darker
//! outside, the title's tone inside); `tag` no border at all — the title's
//! row stays, clear (an ARGB pixel of nothing) and clear to the pointer too:
//! its input region is the tag alone, a tab at its left end with the label
//! and the buttons ([`crate::wl_title::tag_layout`]) —, so a press beside
//! the tag is not the frame's and moves nothing. The buttons' end, order,
//! cells and margin are the look's, and so is where the pointer finds them
//! ([`title_layout`], `ButtonsLook::at`). Round corners: four small
//! surfaces over the corners of the program's content ([`corner_rects`]),
//! the title's colour where the corner is cut off and clear inside a
//! quarter circle, drawn at the scale like the text; clear to input (an
//! empty input region: a click there is the program's). Not with the tag:
//! without a border there is nothing for them to blend into.
//!
//! **Scale.** The strips are a single pixel stretched to a size in logical
//! pixels: at any scale, fractional included, the compositor fills whole
//! device pixels with one colour — nothing to blur, no buffer per scale, no
//! redraw on a resize, only `set_destination` and `set_position`. The text
//! is drawn at the scale the compositor prefers for it —
//! `wp_fractional_scale_v1` when it offers that to the restricted client,
//! `wl_surface.preferred_buffer_scale` when not — and given its logical size
//! by `wp_viewport`; a resize only cuts it (the viewport's source), never
//! draws it again (§6.3). The default width and the strip's height are a
//! whole number of pixels at the usual scales ([`crate::frame::DEFAULT_WIDTH`],
//! [`TITLE_HEIGHT`]). The pixel is the middle one of a 3×3 buffer of the
//! colour (`set_source(1, 1, 1, 1)`): a compositor that scales bilinearly
//! without clamping to the texture's edge — wlroots' pixman renderer does,
//! at a fractional scale — blends it with its neighbours, and a lone 1×1
//! would fade into transparency at the strip's edges; these neighbours are
//! the same colour.
//!
//! **What the program cannot do** (§10). Every object here is the proxy's
//! own: it has an id upstream only, none in the program's table, so the
//! program cannot name it — not destroy it, not attach to it, not move it,
//! not draw in it. Its own new subsurfaces would stack above the frame; each
//! time the stacking of the root's children changes, the strips and the
//! title are put back on top (§5.9). Input on them is not the program's: the
//! compositor sends it to the connection, and the filters below drop it —
//! enter, motion, buttons, axes and their frame of the pointer, touches that
//! began there, a tablet tool near it, gestures begun on it, a drag over it.
//! What decides "not the program's" is that the surface has no id in the
//! program's table: a strip, or a surface the program has already destroyed.
//! (Relative pointer motion carries no surface and passes: over a strip it
//! tells the program only that the pointer moves.)
//!
//! The frame is NOT a trust boundary (§5.9): a popup of the program can lie
//! over it, a fullscreen program draws what it likes, and in mode `hover` a
//! program can draw a strip of another zone's name where ours is hidden. It
//! is a convenience and a reminder.
//!
//! **Never worse than stage 1.** The proxy binds what it needs with a
//! registry of its own — `wl_compositor`, `wl_subcompositor`, `wl_shm`,
//! `wp_viewporter`, and `wp_fractional_scale_manager_v1` when there is one;
//! the program is shown no new global, ever. When one of the first four is
//! missing, windows go without a frame and the proxy says so once; nothing
//! about them is translated then. A window is only given a frame once the
//! proxy knows (its registry has been answered: always before the
//! compositor's first configure of a window, which comes later on the same
//! connection), and from then on for its whole life. Without a font the
//! title strip is there without its text.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::{HashSet, VecDeque};
use std::os::fd::OwnedFd;
use std::rc::{Rc, Weak};

use wl_proxy::client::Client;
use wl_proxy::fixed::Fixed;
use wl_proxy::object::{ConcreteObject, Object, ObjectCoreApi, ObjectRcUtils, ObjectUtils};
use wl_proxy::protocols::cursor_shape_v1::wp_cursor_shape_device_v1::{
    WpCursorShapeDeviceV1, WpCursorShapeDeviceV1Shape,
};
use wl_proxy::protocols::cursor_shape_v1::wp_cursor_shape_manager_v1::WpCursorShapeManagerV1;
use wl_proxy::protocols::drm::wl_drm::{WlDrm, WlDrmHandler};
use wl_proxy::protocols::fractional_scale_v1::wp_fractional_scale_manager_v1::WpFractionalScaleManagerV1;
use wl_proxy::protocols::fractional_scale_v1::wp_fractional_scale_v1::{
    WpFractionalScaleV1, WpFractionalScaleV1Handler,
};
use wl_proxy::protocols::linux_dmabuf_v1::zwp_linux_buffer_params_v1::{
    ZwpLinuxBufferParamsV1, ZwpLinuxBufferParamsV1Flags, ZwpLinuxBufferParamsV1Handler,
};
use wl_proxy::protocols::linux_dmabuf_v1::zwp_linux_dmabuf_v1::{
    ZwpLinuxDmabufV1, ZwpLinuxDmabufV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_hold_v1::{
    ZwpPointerGestureHoldV1, ZwpPointerGestureHoldV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_pinch_v1::{
    ZwpPointerGesturePinchV1, ZwpPointerGesturePinchV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gesture_swipe_v1::{
    ZwpPointerGestureSwipeV1, ZwpPointerGestureSwipeV1Handler,
};
use wl_proxy::protocols::pointer_gestures_unstable_v1::zwp_pointer_gestures_v1::{
    ZwpPointerGesturesV1, ZwpPointerGesturesV1Handler,
};
use wl_proxy::protocols::single_pixel_buffer_v1::wp_single_pixel_buffer_manager_v1::{
    WpSinglePixelBufferManagerV1, WpSinglePixelBufferManagerV1Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_manager_v2::{
    ZwpTabletManagerV2, ZwpTabletManagerV2Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_seat_v2::{ZwpTabletSeatV2, ZwpTabletSeatV2Handler};
use wl_proxy::protocols::tablet_v2::zwp_tablet_tool_v2::{
    ZwpTabletToolV2, ZwpTabletToolV2ButtonState, ZwpTabletToolV2Handler,
};
use wl_proxy::protocols::tablet_v2::zwp_tablet_v2::ZwpTabletV2;
use wl_proxy::protocols::viewporter::wp_viewport::{WpViewport, WpViewportHandler};
use wl_proxy::protocols::viewporter::wp_viewporter::{WpViewporter, WpViewporterHandler};
use wl_proxy::protocols::wayland::wl_buffer::{WlBuffer, WlBufferHandler};
use wl_proxy::protocols::wayland::wl_callback::{WlCallback, WlCallbackHandler};
use wl_proxy::protocols::wayland::wl_compositor::{WlCompositor, WlCompositorHandler};
use wl_proxy::protocols::wayland::wl_data_device::{WlDataDevice, WlDataDeviceHandler};
use wl_proxy::protocols::wayland::wl_data_device_manager::{
    WlDataDeviceManager, WlDataDeviceManagerHandler,
};
use wl_proxy::protocols::wayland::wl_data_offer::WlDataOffer;
use wl_proxy::protocols::wayland::wl_data_source::WlDataSource;
use wl_proxy::protocols::wayland::wl_keyboard::{
    WlKeyboard, WlKeyboardHandler, WlKeyboardKeyState,
};
use wl_proxy::protocols::wayland::wl_output::WlOutputTransform;
use wl_proxy::protocols::wayland::wl_pointer::{
    WlPointer, WlPointerAxis, WlPointerAxisRelativeDirection, WlPointerAxisSource,
    WlPointerButtonState, WlPointerHandler,
};
use wl_proxy::protocols::wayland::wl_registry::{WlRegistry, WlRegistryHandler};
use wl_proxy::protocols::wayland::wl_seat::{WlSeat, WlSeatHandler};
use wl_proxy::protocols::wayland::wl_shm::{WlShm, WlShmFormat, WlShmHandler};
use wl_proxy::protocols::wayland::wl_shm_pool::{WlShmPool, WlShmPoolHandler};
use wl_proxy::protocols::wayland::wl_subcompositor::{WlSubcompositor, WlSubcompositorHandler};
use wl_proxy::protocols::wayland::wl_subsurface::{WlSubsurface, WlSubsurfaceHandler};
use wl_proxy::protocols::wayland::wl_surface::{WlSurface, WlSurfaceHandler};
use wl_proxy::protocols::wayland::wl_touch::{WlTouch, WlTouchHandler};
use wl_proxy::protocols::xdg_shell::xdg_popup::{XdgPopup, XdgPopupHandler};
use wl_proxy::protocols::xdg_shell::xdg_positioner::{
    XdgPositioner, XdgPositionerAnchor, XdgPositionerConstraintAdjustment, XdgPositionerGravity,
    XdgPositionerHandler,
};
use wl_proxy::protocols::xdg_shell::xdg_surface::{XdgSurface, XdgSurfaceHandler};
use wl_proxy::protocols::xdg_shell::xdg_toplevel::{
    XdgToplevel, XdgToplevelHandler, XdgToplevelResizeEdge,
};
use wl_proxy::protocols::xdg_shell::xdg_wm_base::{XdgWmBase, XdgWmBaseHandler};
use wl_proxy::protocols::xdg_toplevel_drag_v1::xdg_toplevel_drag_manager_v1::{
    XdgToplevelDragManagerV1, XdgToplevelDragManagerV1Handler,
};
use wl_proxy::protocols::xdg_toplevel_drag_v1::xdg_toplevel_drag_v1::{
    XdgToplevelDragV1, XdgToplevelDragV1Handler,
};
use wl_proxy::protocols::ObjectInterface;

use crate::frame::TitleMode;
use crate::wl_proxy::Border;
use crate::wl_title::{Button, ButtonsLook, End, Lease, Lit, Look, Pixels, Square, Text};

// --- THE ARITHMETIC ---------------------------------------------------------
// What the frame takes of a window is its [`Insets`]: the border all round,
// and the title strip under the top border when it takes room. All zero is
// "no frame", and every function is then the identity. Saturating: a
// program's nonsense near i32::MAX stays nonsense, it does not wrap into
// something plausible.

/// A rectangle in a surface's coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// What the frame takes of a window: `border` on every side, and `title`
/// more at the top (0 when the strip takes no room: hover, off, fullscreen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Insets {
    pub border: i32,
    pub title: i32,
}

impl Insets {
    /// Above the program's geometry: the border and the strip.
    pub fn top(self) -> i32 {
        self.border.max(0).saturating_add(self.title.max(0))
    }

    /// Taken of the width: the border twice.
    pub fn across(self) -> i32 {
        self.border.max(0).saturating_mul(2)
    }

    /// Taken of the height: the border twice and the strip.
    pub fn down(self) -> i32 {
        self.across().saturating_add(self.title.max(0))
    }
}

/// The program's window geometry → the compositor's: grown by the insets,
/// the frame inside it.
pub(crate) fn geometry_up(g: Rect, i: Insets) -> Rect {
    Rect {
        x: g.x.saturating_sub(i.border.max(0)),
        y: g.y.saturating_sub(i.top()),
        w: g.w.saturating_add(i.across()),
        h: g.h.saturating_add(i.down()),
    }
}

/// A size the compositor asks for (`configure`, `configure_bounds`) → the
/// size the program is told: what is left inside the frame, which takes `d`
/// of it ([`Insets::across`], [`Insets::down`]). 0 is "you decide" and
/// stays so; what is left is never below 1, which would be 0.
pub(crate) fn size_down(v: i32, d: i32) -> i32 {
    if v <= 0 || d <= 0 {
        v
    } else {
        v.saturating_sub(d).max(1)
    }
}

/// A size limit of the program (`set_min_size`, `set_max_size`) → the
/// compositor's. 0 is "no limit" and stays so.
pub(crate) fn size_up(v: i32, d: i32) -> i32 {
    if v <= 0 || d <= 0 {
        v
    } else {
        v.saturating_add(d)
    }
}

/// A point relative to the program's geometry → relative to the
/// compositor's (`show_window_menu`, a popup's anchor rect): `d` is the
/// frame before it, [`Insets::border`] across or [`Insets::top`] down.
pub(crate) fn point_up(v: i32, d: i32) -> i32 {
    v.saturating_add(d.max(0))
}

/// A point relative to the compositor's geometry → the program's
/// (`xdg_popup.configure`).
pub(crate) fn point_down(v: i32, d: i32) -> i32 {
    v.saturating_sub(d.max(0))
}

/// The four strips of the border around the program's geometry `g` and the
/// title strip above it, in the root surface's coordinates: top and bottom
/// the whole width with the corners, left and right between them. They do
/// not overlap each other, the title strip, nor `g`.
pub(crate) fn strips(g: Rect, i: Insets) -> [Rect; 4] {
    let outer = geometry_up(g, i);
    let b = i.border.max(0);
    let t = i.title.max(0);
    [
        Rect {
            x: outer.x,
            y: outer.y,
            w: outer.w,
            h: b,
        },
        Rect {
            x: outer.x,
            y: g.y.saturating_add(g.h),
            w: outer.w,
            h: b,
        },
        Rect {
            x: outer.x,
            y: g.y.saturating_sub(t),
            w: b,
            h: g.h.saturating_add(t),
        },
        Rect {
            x: g.x.saturating_add(g.w),
            y: g.y.saturating_sub(t),
            w: b,
            h: g.h.saturating_add(t),
        },
    ]
}

/// Where the title strip is, over the program's geometry `g`: in the room
/// the insets keep for it, above `g`; or, `over` the content (hover), along
/// the top of `g` — never taller than `g` — when there is a frame (a
/// border) to have it. `None`: no strip.
pub(crate) fn title_strip(g: Rect, i: Insets, over: bool) -> Option<Rect> {
    title_row(g, i, over && i.border > 0)
}

/// Where the tag's row is (`crate::wl_title::Look::tag`): as the title
/// strip, but the tag has no border to go by — it is the whole frame, and
/// `over` the content whenever the frame lays it there.
pub(crate) fn tag_row(g: Rect, i: Insets, over: bool) -> Option<Rect> {
    title_row(g, i, over)
}

/// The row along the top of `g`, the window's whole width: in the title's
/// room, or over the content.
fn title_row(g: Rect, i: Insets, over: bool) -> Option<Rect> {
    if i.title > 0 {
        Some(Rect {
            x: g.x,
            y: g.y.saturating_sub(i.title),
            w: g.w,
            h: i.title,
        })
    } else if over {
        Some(Rect {
            x: g.x,
            y: g.y,
            w: g.w,
            h: TITLE_HEIGHT.min(g.h),
        })
    } else {
        None
    }
}

/// Where the text and the buttons go on a title strip, by the look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TitleLayout {
    /// The text's place on the strip, and the room it has — its pad at
    /// both ends included, as [`text_shown`] takes it.
    pub text_x: i32,
    pub room: i32,
    /// The buttons' place on the strip; `None` when the strip is too narrow
    /// for them and a little of itself to drag the window by.
    pub buttons: Option<i32>,
}

/// [`TitleLayout`] of a strip `w` wide, with the buttons of `look` at its
/// end, the look's margin between them and the end: the text keeps
/// [`TITLE_PAD`] clear of them.
pub(crate) fn title_layout(w: i32, look: &ButtonsLook) -> TitleLayout {
    let row = look.width_all();
    let margin = look.margin.max(0);
    let taken = row.saturating_add(margin);
    if row <= 0 || w < taken.saturating_add(TITLE_PAD.saturating_mul(2)) {
        return TitleLayout {
            text_x: TITLE_PAD,
            room: w,
            buttons: None,
        };
    }
    match look.end {
        End::Right => TitleLayout {
            text_x: TITLE_PAD,
            room: w - taken,
            buttons: Some(w - taken),
        },
        End::Left => TitleLayout {
            text_x: taken + TITLE_PAD,
            room: w - taken,
            buttons: Some(margin),
        },
    }
}

/// The strips of a border of rings `widths` wide (from the outside in)
/// around the program's geometry `g` and the title's room above it: each
/// ring's four, in the order of [`strips`], the outermost ring's first.
/// Each ring hugs the ones inside it, so they tile the band of the whole
/// border without overlapping, and meet at each corner on its diagonal —
/// the outer ring's top strip takes the corner's outer part, the inner
/// ring's the inner. One ring of the whole width is [`strips`] exactly.
pub(crate) fn ring_strips(g: Rect, i: Insets, widths: &[i32]) -> Vec<Rect> {
    let mut rest: i32 = widths
        .iter()
        .map(|w| (*w).max(0))
        .fold(0, i32::saturating_add);
    let mut out = Vec::with_capacity(widths.len() * 4);
    for &w in widths {
        let w = w.max(0);
        rest = rest.saturating_sub(w);
        // Inside this ring: the program, the title's room, the rings
        // further in.
        let inside = geometry_up(
            g,
            Insets {
                border: rest,
                title: i.title,
            },
        );
        out.extend(strips(
            inside,
            Insets {
                border: w,
                title: 0,
            },
        ));
    }
    out
}

/// The edges a press at (`x`, `y`) on `strip` — a strip of any ring of the
/// border, on its `side` — resizes: as [`edges`] says of the same point of
/// the whole border's strip of that side, `outer` ([`strips`]). Every ring
/// of a side resizes alike, and a corner is a corner of the window.
pub(crate) fn ring_edges(side: Side, strip: Rect, outer: Rect, border: i32, x: f64, y: f64) -> u32 {
    let x = x + f64::from(strip.x) - f64::from(outer.x);
    let y = y + f64::from(strip.y) - f64::from(outer.y);
    edges(side, outer, border, x, y)
}

/// Where the round corners go over the program's geometry `g`: squares of
/// `radius` in its four corners — top left, top right, bottom left, bottom
/// right, as `crate::wl_title::render_corners` draws them —, smaller on a
/// window too small for them (never over its middle). `None`: no room for
/// any.
pub(crate) fn corner_rects(g: Rect, radius: i32) -> Option<[Rect; 4]> {
    let r = radius.min(g.w / 2).min(g.h / 2);
    if r <= 0 {
        return None;
    }
    let (right, bottom) = (g.x.saturating_add(g.w - r), g.y.saturating_add(g.h - r));
    let at = |x: i32, y: i32| Rect { x, y, w: r, h: r };
    Some([
        at(g.x, g.y),
        at(right, g.y),
        at(g.x, bottom),
        at(right, bottom),
    ])
}

/// A strip of the border, by the side it is on — in the order of
/// [`strips`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Top,
    Bottom,
    Left,
    Right,
}

impl Side {
    const ALL: [Side; 4] = [Side::Top, Side::Bottom, Side::Left, Side::Right];

    fn index(self) -> usize {
        match self {
            Side::Top => 0,
            Side::Bottom => 1,
            Side::Left => 2,
            Side::Right => 3,
        }
    }
}

/// `xdg_toplevel.resize_edge`, as bits.
pub(crate) const EDGE_TOP: u32 = 1;
pub(crate) const EDGE_BOTTOM: u32 = 2;
pub(crate) const EDGE_LEFT: u32 = 4;
pub(crate) const EDGE_RIGHT: u32 = 8;

/// How far from a corner of the window, along either edge, the border
/// resizes both edges of that corner, logical pixels.
pub(crate) const CORNER: i32 = 16;

/// The edges a press at (`x`, `y`) on the border's strip `strip` (on its
/// `side`, of a border `border` wide; surface-local) resizes: its own, and
/// the one across it within [`CORNER`] of a corner of the window. The side
/// strips begin under the top strip and end above the bottom one, `border`
/// from the corners.
pub(crate) fn edges(side: Side, strip: Rect, border: i32, x: f64, y: f64) -> u32 {
    let (own, along, len, from, before, after) = match side {
        Side::Top => (EDGE_TOP, x, strip.w, 0, EDGE_LEFT, EDGE_RIGHT),
        Side::Bottom => (EDGE_BOTTOM, x, strip.w, 0, EDGE_LEFT, EDGE_RIGHT),
        Side::Left => (EDGE_LEFT, y, strip.h, border, EDGE_TOP, EDGE_BOTTOM),
        Side::Right => (EDGE_RIGHT, y, strip.h, border, EDGE_TOP, EDGE_BOTTOM),
    };
    let from = f64::from(from.max(0));
    // From the window's corner, and the whole edge.
    let at = along + from;
    let whole = f64::from(len) + 2.0 * from;
    let corner = f64::from(CORNER);
    if at < corner {
        own | before
    } else if at >= whole - corner {
        own | after
    } else {
        own
    }
}

/// What a point on the frame is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hit {
    Nothing,
    /// The title strip or its text: pressed, it moves the window.
    Title,
    Button(Button),
    /// The border: pressed, it resizes the window by these edges.
    Edge(u32),
}

/// The cursor over `hit`: an arrow of the edges over the border, the
/// default one over the title and the buttons (the owner, 2026-09-27: no
/// hand over them — they light up instead).
pub(crate) fn cursor_for(hit: Hit) -> WpCursorShapeDeviceV1Shape {
    use WpCursorShapeDeviceV1Shape as Shape;
    match hit {
        Hit::Edge(edges) => match edges {
            EDGE_TOP => Shape::N_RESIZE,
            EDGE_BOTTOM => Shape::S_RESIZE,
            EDGE_LEFT => Shape::W_RESIZE,
            EDGE_RIGHT => Shape::E_RESIZE,
            e if e == EDGE_TOP | EDGE_LEFT => Shape::NW_RESIZE,
            e if e == EDGE_TOP | EDGE_RIGHT => Shape::NE_RESIZE,
            e if e == EDGE_BOTTOM | EDGE_LEFT => Shape::SW_RESIZE,
            e if e == EDGE_BOTTOM | EDGE_RIGHT => Shape::SE_RESIZE,
            _ => Shape::DEFAULT,
        },
        Hit::Nothing | Hit::Title | Hit::Button(_) => Shape::DEFAULT,
    }
}

/// The format of a buffer of the frame, as the look keeps its pixels.
fn shm_format(pixels: Pixels) -> WlShmFormat {
    match pixels {
        Pixels::Opaque => WlShmFormat::XRGB8888,
        Pixels::Alpha => WlShmFormat::ARGB8888,
    }
}

/// How much of a line `text` wide a strip `strip` wide shows: all of it
/// after [`TITLE_PAD`], or what is left when the strip is narrower, keeping
/// [`TITLE_PAD`] clear at its end too. 0: none.
pub(crate) fn text_shown(strip: i32, text: i32) -> i32 {
    strip
        .saturating_sub(TITLE_PAD.saturating_mul(2))
        .min(text)
        .max(0)
}

/// `shown` logical pixels of a line `text` wide, in the pixels of a buffer
/// `buffer` wide that holds the whole line: the width of the viewport's
/// source. Never past the buffer.
pub(crate) fn source_width(shown: i32, text: i32, buffer: i32) -> i32 {
    if text <= 0 || shown >= text {
        return buffer.max(0);
    }
    let px = (i64::from(shown.max(0)) * i64::from(buffer) + i64::from(text) / 2) / i64::from(text);
    (px as i32).clamp(0, buffer.max(0))
}

/// Whether the pointer at `y` on the program's surface (`g` its geometry)
/// wants a hover strip shown (`Some(true)`), hidden (`Some(false)`), or as
/// it is: at the very top of the window it comes out; under where it would
/// be, it goes.
pub(crate) fn hover_at(g: Rect, y: f64) -> Option<bool> {
    let top = f64::from(g.y);
    if y < top + f64::from(HOVER_EDGE) {
        Some(true)
    } else if y >= top + f64::from(TITLE_HEIGHT) {
        Some(false)
    } else {
        None
    }
}

/// The logical size of a surface from its committed state (wl_surface and
/// wp_viewport): the destination if set, else the source, else the buffer
/// divided by its scale and turned by its transform. `None` when there is no
/// buffer, or its size is not known.
fn surface_size(s: &Committed) -> Option<(i32, i32)> {
    if let Some(dest) = s.destination {
        return Some(dest);
    }
    let (bw, bh) = s.buffer?;
    if let Some(src) = s.source {
        return Some(src);
    }
    let scale = s.scale.max(1);
    let (w, h) = (bw / scale, bh / scale);
    // 90° and 270°, flipped or not, are the odd ones.
    Some(if s.transform % 2 == 1 { (h, w) } else { (w, h) })
}

// --- THE CONNECTION'S SHARE -------------------------------------------------

/// The frame of one connection: what the proxy bound for it upstream, and
/// what it draws with. Every handler below holds it.
pub(crate) struct Frames {
    width: i32,
    /// The title strip's mode, the launch's.
    mode: TitleMode,
    /// The look — the style, the buttons, the round corners —, the
    /// launch's.
    look: Look,
    /// The colours, a 3×3 square each in a sealed memfd, made before the
    /// proxy confined itself (`wl_proxy::pixels`): the same for every
    /// connection of the launch — one zone, one colour, its tones.
    pixel: Rc<OwnedFd>,
    /// What each square of it is ([`Look::squares`]): its buffer's format.
    squares: Vec<Square>,
    /// The title's line and the memfd of its pixels (`crate::wl_title`), the
    /// launch's too. `None`: the strip goes without its text.
    text: Option<Rc<Text>>,
    own: RefCell<Own>,
    /// The scale (120ths) the compositor last preferred for a title of this
    /// connection: a new window's text is drawn at it first.
    scale: Cell<u32>,
    /// Whether "cannot draw" has been said: once per proxy.
    warned: Rc<Cell<bool>>,
    /// Windows of this connection with a frame now ([`Framed`]).
    framed: Rc<Cell<usize>>,
    /// What the frame's buttons ask of the supervisor, the proxy's for all
    /// its connections: its loop sends them.
    asks: Rc<Asks>,
    /// The serial of the pointer event the frame acted on last: every
    /// `wl_pointer` of the program on a seat hears the same event, and one
    /// of them acts on it ([`Frames::first`]).
    acted: Cell<Option<u32>>,
    /// The window whose ≡ dropdown is open ([`Dropdown`]): one at a time on
    /// a connection. Its keys come here.
    menu_on: RefCell<Option<Weak<RefCell<Window>>>>,
    /// The launch's windows always think they have the focus (3d of
    /// `docs/PERMISSIONS.md` §11.15): `activated` kept in every configure,
    /// `suspended` taken out, the keyboard's and the pointer's leave held
    /// back — the keys and buttons down let go of first, so nothing sticks.
    always_focused: bool,
}

/// What a click on the frame asks of the supervisor (`crate::wl_proxy`),
/// over the channel the two share: the proxy starts nothing itself (no
/// `exec`, no `connect` in its filter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ask {
    /// The launch's window menu.
    Menu,
    /// Another network for the container: switched live where its
    /// instance can be, else its restart with a network chosen (stage 5 of
    /// the container design).
    Network,
    /// The launch restarted with a network chosen (`window-menu
    /// --restart`): a row of the ≡'s dropdown.
    Restart,
}

/// Asks the proxy's loop has not sent yet. A few at most: a click is one,
/// and the proxy sends them after every round of its loop.
#[derive(Default)]
pub(crate) struct Asks(RefCell<VecDeque<Ask>>);

/// Asks kept at once; more in one round are not the person's clicks.
const MAX_ASKS: usize = 4;

impl Asks {
    fn push(&self, ask: Ask) {
        let mut asks = self.0.borrow_mut();
        if asks.len() < MAX_ASKS {
            asks.push_back(ask);
        }
    }

    /// The asks to send, in their order; none are left.
    pub(crate) fn take(&self) -> Vec<Ask> {
        self.0.borrow_mut().drain(..).collect()
    }
}

/// One framed window's share of [`Frames::framed`], given back when its frame
/// goes (or with the connection).
///
/// A frame is the proxy's own objects upstream — four strips of three, the
/// title and its text of about eight — which the program's table does not
/// hold, so `wl_proxy`'s cap on the program's objects does not count them:
/// three objects of the program (a surface, its xdg_surface, a toplevel)
/// and a commit without a buffer make about twenty in the compositor
/// (review 2026-09-25); with the looks of 2026-09-28 — the soft border's
/// eight strips, the buttons, four round corners and their buffers — about
/// fifty. `wl_proxy` counts these at every dispatch and ends a connection
/// with too many ([`MAX_FRAMED`]).
struct Framed(Rc<Cell<usize>>);

impl Framed {
    fn new(count: &Rc<Cell<usize>>) -> Self {
        count.set(count.get().saturating_add(1));
        Self(count.clone())
    }
}

impl Drop for Framed {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// Framed windows one connection may have at once: a program shows a few,
/// a big one a few dozen. Past this it is refused like one with too many
/// objects — never served without a frame. 2048 since 2026-09-28 (4096
/// before): a frame is about twice the objects it was, and what a program
/// can make the compositor hold this way stays near the 100 000 of its own
/// it may make.
pub(crate) const MAX_FRAMED: usize = 2048;

#[derive(Default)]
struct Own {
    /// The registry has been answered: what is missing now is missing.
    complete: bool,
    compositor: Option<Rc<WlCompositor>>,
    subcompositor: Option<Rc<WlSubcompositor>>,
    shm: Option<Rc<WlShm>>,
    viewporter: Option<Rc<WpViewporter>>,
    /// For the title's text, when the compositor offers it to the restricted
    /// client; without it, `wl_surface.preferred_buffer_scale`.
    fractional: Option<Rc<WpFractionalScaleManagerV1>>,
    /// For the cursor over the frame, when the compositor offers it; without
    /// it the cursor over the frame is whatever it was.
    cursor_shape: Option<Rc<WpCursorShapeManagerV1>>,
    /// For the ≡'s dropdown, an `xdg_popup` of the proxy's own; without it
    /// the ≡ asks for the window menu as before.
    wm_base: Option<Rc<XdgWmBase>>,
    /// A buffer of each square of the colours' memfd, in its order.
    pixels: Vec<Rc<WlBuffer>>,
    /// The pool of the title's pixels: the launch's memfd, this connection's
    /// pool of it.
    text_pool: Option<Rc<WlShmPool>>,
}

/// A colour's buffer: a square of this side, in XRGB8888 — ARGB8888 for the
/// clear one (`wl_proxy::pixels` makes them).
pub(crate) const PIXEL_SIDE: i32 = 3;
pub(crate) const PIXEL_BYTES: i32 = PIXEL_SIDE * PIXEL_SIDE * 4;

/// The title strip's height and the space before its text, logical pixels
/// (`crate::wl_title`).
pub(crate) const TITLE_HEIGHT: i32 = crate::wl_title::HEIGHT;
pub(crate) const TITLE_PAD: i32 = crate::wl_title::PAD;
/// How near the top of the program's geometry the pointer brings a hover
/// strip out, logical pixels: the border above it does too.
pub(crate) const HOVER_EDGE: i32 = 2;
/// Configures remembered until the program acks them: a program acks the
/// last it has seen, and a hostile one may never ack — bounded.
const MAX_CONFIGURES: usize = 32;
/// `xdg_toplevel.state.fullscreen`.
const FULLSCREEN: u32 = 2;

/// An object of the proxy's own: whatever the compositor sends it is not the
/// program's (it could not be passed on anyway — the object has no id in the
/// program's table).
fn quiet<T: Object + ?Sized>(object: &T) {
    object.set_forward_to_client(false);
}

/// Whether input on `surface` is the program's: it has an id in its table.
/// The proxy's strips never have one, nor has a surface the program has
/// already destroyed.
fn programs(surface: &Rc<WlSurface>) -> bool {
    surface.client_id().is_some()
}

impl Frames {
    /// Windows of this connection with a frame now: `wl_proxy` refuses the
    /// connection past [`MAX_FRAMED`].
    pub(crate) fn framed(&self) -> usize {
        self.framed.get()
    }

    /// Whether the pointer event of `serial` is heard here first. The
    /// compositor sends an event to every `wl_pointer` the program made of
    /// the seat, each with the same serial: the frame acts on it once — one
    /// click, one move, one close.
    fn first(&self, serial: u32) -> bool {
        self.acted.replace(Some(serial)) != Some(serial)
    }

    /// Start the frame on a new connection, before any request of the
    /// program is read: a registry of the proxy's own and a sync after it,
    /// whose answer says the globals are all in.
    pub(crate) fn install(
        client: &Rc<Client>,
        border: &Border,
        warned: Rc<Cell<bool>>,
        asks: Rc<Asks>,
    ) -> Rc<Self> {
        let frames = Rc::new(Self {
            width: border.width,
            mode: border.title,
            look: border.look,
            pixel: border.pixel.clone(),
            squares: border.squares.clone(),
            text: border.text.clone(),
            own: RefCell::default(),
            scale: Cell::new(crate::wl_title::MIN_SCALE),
            warned,
            framed: Rc::default(),
            asks,
            acted: Cell::new(None),
            menu_on: RefCell::new(None),
            always_focused: border.always_focused,
        });
        let display = client.display();
        let registry = display.new_send_get_registry();
        quiet(&*registry);
        registry.set_handler(OwnRegistry {
            frames: frames.clone(),
        });
        let sync = display.new_send_sync();
        quiet(&*sync);
        sync.set_handler(OwnSync {
            frames: frames.clone(),
        });
        frames
    }

    /// A global the program has just bound: the objects whose messages the
    /// frame has to translate or filter get their handlers.
    pub(crate) fn watch(self: &Rc<Self>, id: &Rc<dyn Object>) {
        let f = self.clone();
        if let Some(o) = id.try_downcast::<WlCompositor>() {
            o.set_handler(Compositor { f });
        } else if let Some(o) = id.try_downcast::<XdgWmBase>() {
            o.set_handler(WmBase { f });
        } else if let Some(o) = id.try_downcast::<WlSubcompositor>() {
            o.set_handler(Subcompositor);
        } else if let Some(o) = id.try_downcast::<WpViewporter>() {
            o.set_handler(Viewporter);
        } else if let Some(o) = id.try_downcast::<WlSeat>() {
            o.set_handler(Seat { f });
        } else if let Some(o) = id.try_downcast::<WlShm>() {
            o.set_handler(Shm);
        } else if let Some(o) = id.try_downcast::<ZwpLinuxDmabufV1>() {
            o.set_handler(Dmabuf);
        } else if let Some(o) = id.try_downcast::<WlDrm>() {
            o.set_handler(Drm);
        } else if let Some(o) = id.try_downcast::<WpSinglePixelBufferManagerV1>() {
            o.set_handler(SinglePixel);
        } else if let Some(o) = id.try_downcast::<WlDataDeviceManager>() {
            o.set_handler(DataDeviceManager);
        } else if let Some(o) = id.try_downcast::<ZwpPointerGesturesV1>() {
            o.set_handler(Gestures);
        } else if let Some(o) = id.try_downcast::<ZwpTabletManagerV2>() {
            o.set_handler(TabletManager);
        } else if let Some(o) = id.try_downcast::<XdgToplevelDragManagerV1>() {
            o.set_handler(DragManager { f });
        }
    }

    /// The registry has been answered: make a buffer of each colour the
    /// strips show (in `full`, the one of stage 2), and the pool the title's
    /// text comes from.
    fn finish(&self) {
        let mut own = self.own.borrow_mut();
        own.complete = true;
        let Some(shm) = own.shm.clone() else {
            return;
        };
        let count = i32::try_from(self.squares.len()).unwrap_or(0);
        let pool = shm.new_send_create_pool(&self.pixel, PIXEL_BYTES.saturating_mul(count));
        quiet(&*pool);
        own.pixels = (0..count)
            .zip(&self.squares)
            .map(|(k, square)| {
                let buffer = pool.new_send_create_buffer(
                    PIXEL_BYTES * k,
                    PIXEL_SIDE,
                    PIXEL_SIDE,
                    PIXEL_SIDE * 4,
                    shm_format(square.pixels()),
                );
                quiet(&*buffer);
                buffer
            })
            .collect();
        pool.send_destroy();
        if let Some(text) = &self.text {
            let pool = shm.new_send_create_pool(&text.fd, text.pool_size());
            quiet(&*pool);
            own.text_pool = Some(pool);
        }
    }

    /// Whether windows of this connection can have a frame; said once per
    /// proxy when not.
    fn can_draw(&self) -> bool {
        let own = self.own.borrow();
        let missing: Vec<&str> = [
            ("wl_compositor", own.compositor.is_some()),
            ("wl_subcompositor", own.subcompositor.is_some()),
            ("wl_shm", !own.pixels.is_empty()),
            ("wp_viewporter", own.viewporter.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, there)| (!there).then_some(name))
        .collect();
        if !missing.is_empty() && !self.warned.replace(true) {
            eprintln!(
                "wl-sandbox: the compositor offers no {} — windows go without the zone's border",
                missing.join(", ")
            );
        }
        missing.is_empty()
    }

    /// The border's width in this look: none for the tag.
    fn border_width(&self) -> i32 {
        if self.look.tag() {
            0
        } else {
            self.width
        }
    }

    /// The strips of a new bordered window, four a ring of the look's
    /// ([`Look::rings`]; none for the tag), above `top` (the program's
    /// topmost layer on `root`). Attached, not committed: they show with the
    /// first layout, which the program's commit applies.
    fn make_strips(
        &self,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        me: &Weak<RefCell<Window>>,
    ) -> Option<Vec<Strip>> {
        let own = self.own.borrow();
        let (Some(compositor), Some(subcompositor), Some(viewporter), false) = (
            &own.compositor,
            &own.subcompositor,
            &own.viewporter,
            own.pixels.is_empty(),
        ) else {
            return None;
        };
        let rings = self.look.rings(self.border_width());
        let mut strips = Vec::with_capacity(rings.len() * 4);
        for (ring, &(_, square)) in rings.iter().enumerate() {
            let buffer = own.pixels.get(square)?;
            for side in Side::ALL {
                let surface = compositor.new_send_create_surface();
                quiet(&*surface);
                surface.set_handler(Mine {
                    window: me.clone(),
                    part: Part::Border(side, ring),
                });
                let sub = subcompositor.new_send_get_subsurface(&surface, root);
                quiet(&*sub);
                let viewport = viewporter.new_send_get_viewport(&surface);
                quiet(&*viewport);
                // The middle pixel of the square.
                let one = Fixed::from_i32_saturating(1);
                viewport.send_set_source(one, one, one, one);
                sub.send_place_above(top);
                attach_pixel(&surface, buffer);
                strips.push(Strip {
                    surface,
                    sub,
                    viewport,
                });
            }
        }
        Some(strips)
    }

    /// The title strip of a new window, above `top`: the colour's pixel
    /// stretched like a strip of the border (not attached yet: a hover strip
    /// starts hidden), and the text and the buttons subsurfaces of it — so
    /// that they go where the strip goes, and are hidden with it. The
    /// buttons are drawn with the text's font, and are there only with it
    /// (and with a look that has some).
    ///
    /// The tag's row (`Look::tag`) is the clear square stretched, and takes
    /// the pointer only where the tag is: its input region. The tag itself
    /// is the text's image (`crate::wl_title::render_tag`), over it at its
    /// left end; beside it a press is not the frame's — no move, no enter —
    /// but what is under: the program's CSD shadow, or another window.
    fn make_title(
        self: &Rc<Self>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        me: &Weak<RefCell<Window>>,
    ) -> Option<TitleParts> {
        let own = self.own.borrow();
        let tag = self.text.as_ref().and_then(|text| text.tag());
        let (Some(compositor), Some(subcompositor), Some(viewporter), Some(buffer)) = (
            &own.compositor,
            &own.subcompositor,
            &own.viewporter,
            own.pixels.get(self.look.title_square(tag.is_some())),
        ) else {
            return None;
        };
        let own_surface = |part: Part| {
            let surface = compositor.new_send_create_surface();
            quiet(&*surface);
            surface.set_handler(Mine {
                window: me.clone(),
                part,
            });
            surface
        };
        let surface = own_surface(Part::Title);
        let sub = subcompositor.new_send_get_subsurface(&surface, root);
        quiet(&*sub);
        sub.send_place_above(top);
        let view = viewporter.new_send_get_viewport(&surface);
        quiet(&*view);
        let one = Fixed::from_i32_saturating(1);
        view.send_set_source(one, one, one, one);
        if let Some(tag) = tag {
            // The row's input region: the tag, and nothing of the clear
            // rest (the compositor clips it to the row). Applied with the
            // strip's first commit.
            let region = compositor.new_send_create_region();
            quiet(&*region);
            region.send_add(0, 0, tag.width, TITLE_HEIGHT);
            surface.send_set_input_region(Some(&region));
            region.send_destroy();
        }
        let (text, buttons) = match (&self.text, &own.text_pool) {
            (Some(text), Some(pool)) => {
                let text_surface = own_surface(Part::Text);
                let text_sub = subcompositor.new_send_get_subsurface(&text_surface, &surface);
                quiet(&*text_sub);
                text_sub.send_set_position(TITLE_PAD, 0);
                let text_view = viewporter.new_send_get_viewport(&text_surface);
                quiet(&*text_view);
                let fraction = own.fractional.as_ref().map(|manager| {
                    let fraction = manager.new_send_get_fractional_scale(&text_surface);
                    quiet(&*fraction);
                    fraction.set_handler(Scale {
                        f: self.clone(),
                        window: me.clone(),
                    });
                    fraction
                });
                // The buttons, when the look has any: the row at its
                // logical size, whatever scale it is drawn at; placed by the
                // strip's layout.
                let row = self.look.buttons.width_all();
                let buttons = (row > 0).then(|| {
                    let buttons_surface = own_surface(Part::Buttons);
                    let buttons_sub =
                        subcompositor.new_send_get_subsurface(&buttons_surface, &surface);
                    quiet(&*buttons_sub);
                    let buttons_view = viewporter.new_send_get_viewport(&buttons_surface);
                    quiet(&*buttons_view);
                    buttons_view.send_set_destination(row, TITLE_HEIGHT);
                    ButtonParts {
                        text: text.clone(),
                        pool: pool.clone(),
                        surface: buttons_surface,
                        sub: buttons_sub,
                        view: buttons_view,
                        scale: self.scale.get(),
                        at: None,
                        lit: None,
                        current: None,
                        retired: Vec::new(),
                    }
                });
                (
                    Some(TextParts {
                        text: text.clone(),
                        pool: pool.clone(),
                        surface: text_surface,
                        sub: text_sub,
                        view: text_view,
                        fraction,
                        scale: self.scale.get(),
                        drawn: None,
                        current: None,
                        retired: Vec::new(),
                        shown: 0,
                        x: TITLE_PAD,
                    }),
                    buttons,
                )
            }
            _ => (None, None),
        };
        Some(TitleParts {
            pixel: buffer.clone(),
            surface,
            sub,
            view,
            shown: false,
            text,
            buttons,
        })
    }

    /// The round corners of a new window (`Look::corners`), above `top` —
    /// under the title, which is placed above `top` before them and so ends
    /// above them: a hover strip lies over the top corners. Clear to input.
    /// Their scale is the text's when the window has one (`fractional`
    /// false), else their own: a `wp_fractional_scale_v1` of the first.
    /// None without the title's memfd (no font: no corners either).
    fn make_corners(
        self: &Rc<Self>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        me: &Weak<RefCell<Window>>,
        fractional: bool,
    ) -> Option<CornerParts> {
        let own = self.own.borrow();
        let (Some(compositor), Some(subcompositor), Some(viewporter), Some(text), Some(pool)) = (
            &own.compositor,
            &own.subcompositor,
            &own.viewporter,
            &self.text,
            &own.text_pool,
        ) else {
            return None;
        };
        let pieces: Vec<Strip> = (0..4)
            .map(|_| {
                let surface = compositor.new_send_create_surface();
                quiet(&*surface);
                surface.set_handler(Mine {
                    window: me.clone(),
                    part: Part::Corner,
                });
                let sub = subcompositor.new_send_get_subsurface(&surface, root);
                quiet(&*sub);
                sub.send_place_above(top);
                let viewport = viewporter.new_send_get_viewport(&surface);
                quiet(&*viewport);
                // An empty input region: a click on the window's corner is
                // the program's, as without them.
                let region = compositor.new_send_create_region();
                quiet(&*region);
                surface.send_set_input_region(Some(&region));
                region.send_destroy();
                Strip {
                    surface,
                    sub,
                    viewport,
                }
            })
            .collect();
        let fraction = if fractional {
            own.fractional.as_ref().map(|manager| {
                let fraction = manager.new_send_get_fractional_scale(&pieces[0].surface);
                quiet(&*fraction);
                fraction.set_handler(Scale {
                    f: self.clone(),
                    window: me.clone(),
                });
                fraction
            })
        } else {
            None
        };
        Some(CornerParts {
            text: text.clone(),
            pool: pool.clone(),
            pieces,
            fraction,
            scale: self.scale.get(),
            laid: None,
            current: Vec::new(),
            retired: Vec::new(),
        })
    }
}

/// Attach the colour's square to one of the proxy's surfaces.
fn attach_pixel(surface: &Rc<WlSurface>, buffer: &Rc<WlBuffer>) {
    surface.send_attach(Some(buffer), 0, 0);
    if surface.version() >= 4 {
        surface.send_damage_buffer(0, 0, PIXEL_SIDE, PIXEL_SIDE);
    } else {
        surface.send_damage(0, 0, 1 << 15, 1 << 15);
    }
}

/// The proxy's own registry: the globals it draws with, the first of each,
/// at the lowest version that has what it uses.
struct OwnRegistry {
    frames: Rc<Frames>,
}

fn bind<T: ConcreteObject>(registry: &Rc<WlRegistry>, name: u32, version: u32) -> Rc<T> {
    let object = registry.state().create_object::<T>(version.max(1));
    quiet(&*object);
    registry.send_bind(name, object.clone());
    object
}

impl WlRegistryHandler for OwnRegistry {
    fn handle_global(
        &mut self,
        slf: &Rc<WlRegistry>,
        name: u32,
        interface: ObjectInterface,
        version: u32,
    ) {
        let mut own = self.frames.own.borrow_mut();
        match interface {
            // v4: damage_buffer; v6: preferred_buffer_scale, the title's
            // scale where there is no fractional one.
            ObjectInterface::WlCompositor if own.compositor.is_none() => {
                own.compositor = Some(bind(slf, name, version.min(6)));
            }
            ObjectInterface::WlSubcompositor if own.subcompositor.is_none() => {
                own.subcompositor = Some(bind(slf, name, 1));
            }
            ObjectInterface::WlShm if own.shm.is_none() => {
                own.shm = Some(bind(slf, name, 1));
            }
            ObjectInterface::WpViewporter if own.viewporter.is_none() => {
                own.viewporter = Some(bind(slf, name, 1));
            }
            ObjectInterface::WpFractionalScaleManagerV1 if own.fractional.is_none() => {
                own.fractional = Some(bind(slf, name, 1));
            }
            ObjectInterface::WpCursorShapeManagerV1 if own.cursor_shape.is_none() => {
                own.cursor_shape = Some(bind(slf, name, 1));
            }
            ObjectInterface::XdgWmBase if own.wm_base.is_none() => {
                let wm_base: Rc<XdgWmBase> = bind(slf, name, 1);
                wm_base.set_handler(OwnWmBase);
                own.wm_base = Some(wm_base);
            }
            _ => {}
        }
    }

    fn handle_global_remove(&mut self, _slf: &Rc<WlRegistry>, _name: u32) {}
}

struct OwnSync {
    frames: Rc<Frames>,
}

impl WlCallbackHandler for OwnSync {
    fn handle_done(&mut self, _slf: &Rc<WlCallback>, _callback_data: u32) {
        self.frames.finish();
    }
}

/// What one of the proxy's surfaces is, for the input that comes to it and
/// for its scale: a strip of the border — its side, and its ring from the
/// outside in (the top ones bring a hover title out, each resizes the
/// window by its edge) —, the title strip, its text and its buttons, or a
/// round corner (it takes no input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Border(Side, usize),
    Title,
    Text,
    Buttons,
    Corner,
    /// The ≡'s dropdown ([`Dropdown`]).
    Menu,
}

impl Part {
    /// Drawn at a scale, or the parent of what is: the title strip, its
    /// text and buttons, the round corners (the border is one stretched
    /// pixel).
    fn titled(self) -> bool {
        matches!(
            self,
            Part::Title | Part::Text | Part::Buttons | Part::Corner
        )
    }
}

/// The handler of the proxy's own surfaces: which window, which part.
struct Mine {
    window: Weak<RefCell<Window>>,
    part: Part,
}

impl WlSurfaceHandler for Mine {
    /// The integer scale, `wl_compositor` v6: the text's, the buttons' and
    /// the corners' where the compositor offers no fractional one.
    fn handle_preferred_buffer_scale(&mut self, _slf: &Rc<WlSurface>, factor: i32) {
        if !self.part.titled() {
            return;
        }
        if let Some(window) = self.window.upgrade() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.integer_scale(factor);
            }
        }
    }
}

/// The text's `wp_fractional_scale_v1`.
struct Scale {
    f: Rc<Frames>,
    window: Weak<RefCell<Window>>,
}

impl WpFractionalScaleV1Handler for Scale {
    fn handle_preferred_scale(&mut self, _slf: &Rc<WpFractionalScaleV1>, scale: u32) {
        let scale = crate::wl_title::clamp_scale(scale);
        self.f.scale.set(scale);
        if let Some(window) = self.window.upgrade() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.rescale(scale);
            }
        }
    }
}

/// A buffer of the title's memfd — of its text or its buttons: its hold on
/// the region of the memfd it shows, until the compositor releases it.
/// Destroyed once released and no longer attached (`retired`).
struct TextBuffer {
    lease: Option<Lease>,
    retired: bool,
    destroyed: bool,
}

impl TextBuffer {
    fn destroy(&mut self, slf: &Rc<WlBuffer>) {
        if !self.destroyed {
            self.destroyed = true;
            slf.send_destroy();
        }
    }
}

impl WlBufferHandler for TextBuffer {
    fn handle_release(&mut self, slf: &Rc<WlBuffer>) {
        self.lease = None;
        if self.retired {
            self.destroy(slf);
        }
    }
}

// --- WINDOWS ------------------------------------------------------------------

struct Strip {
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    viewport: Rc<WpViewport>,
}

/// The title strip of a window: the colour stretched, the text and the
/// buttons on it.
struct TitleParts {
    pixel: Rc<WlBuffer>,
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    view: Rc<WpViewport>,
    /// The colour is attached: the strip is shown.
    shown: bool,
    text: Option<TextParts>,
    buttons: Option<ButtonParts>,
}

impl TitleParts {
    /// Attach the colour or nothing; the caller commits.
    fn show(&mut self, on: bool) {
        if on {
            attach_pixel(&self.surface, &self.pixel);
        } else {
            self.surface.send_attach(None, 0, 0);
        }
        self.shown = on;
    }

    /// Show what is pending of the strip, its text and its buttons now,
    /// without waiting for the program's commit (§5.3): the strip is a
    /// synchronized subsurface, whose state the root's commit applies, and
    /// the program may not commit for a long while — a text drawn at a new
    /// scale, a hover strip coming out, a button lit. Desynchronized for its
    /// own commit, and synchronized again at once. Its pending state holds
    /// nothing else: the proxy lays it out only right before the program's
    /// commit.
    fn apply_now(&self) {
        self.sub.send_set_desync();
        self.surface.send_commit();
        self.sub.send_set_sync();
    }

    fn destroy(self) {
        if let Some(text) = self.text {
            text.destroy();
        }
        if let Some(buttons) = self.buttons {
            buttons.destroy();
        }
        self.view.send_destroy();
        self.sub.send_destroy();
        self.surface.send_destroy();
    }
}

/// Attach a buffer of `width` × `height` to one of the proxy's surfaces,
/// all of it damaged.
fn attach_whole(surface: &Rc<WlSurface>, buffer: &Rc<WlBuffer>, width: i32, height: i32) {
    surface.send_attach(Some(buffer), 0, 0);
    if surface.version() >= 4 {
        surface.send_damage_buffer(0, 0, width, height);
    } else {
        surface.send_damage(0, 0, 1 << 15, 1 << 15);
    }
}

/// A buffer of the title's memfd, `width` × `height` at `offset`, in the
/// format of `pixels`: its hold on the region (`lease`) goes with it
/// ([`TextBuffer`]).
fn memfd_buffer(
    pool: &Rc<WlShmPool>,
    (width, height): (i32, i32),
    offset: i32,
    lease: Lease,
    pixels: Pixels,
) -> Rc<WlBuffer> {
    let buffer = pool.new_send_create_buffer(offset, width, height, width * 4, shm_format(pixels));
    quiet(&*buffer);
    buffer.set_handler(TextBuffer {
        lease: Some(lease),
        retired: false,
        destroyed: false,
    });
    buffer
}

/// The buffer attached until now (`current`) is not any more: it joins
/// `retired`, and whatever of those the compositor has released is
/// destroyed (at once when it has).
fn retire(current: &mut Option<Rc<WlBuffer>>, retired: &mut Vec<Rc<WlBuffer>>) {
    if let Some(old) = current.take() {
        retired.push(old);
    }
    sweep(retired);
}

/// Every buffer of `retired` is not attached any more: those the
/// compositor has released are destroyed, the rest when it does.
fn sweep(retired: &mut Vec<Rc<WlBuffer>>) {
    retired.retain(|buffer| {
        let Ok(mut h) = buffer.try_get_handler_mut::<TextBuffer>() else {
            return false;
        };
        h.retired = true;
        if h.lease.is_none() {
            h.destroy(buffer);
        }
        !h.destroyed
    });
}

/// A surface of these buffers is gone: nothing of them is shown any more.
fn destroy_buffers(current: Option<Rc<WlBuffer>>, retired: Vec<Rc<WlBuffer>>) {
    for buffer in current.into_iter().chain(retired) {
        if let Ok(mut h) = buffer.try_get_handler_mut::<TextBuffer>() {
            h.destroy(&buffer);
            h.lease = None;
        }
    }
}

/// The text on a title strip: a buffer of the line at the scale the
/// compositor prefers, the viewport cutting it to what the strip shows.
struct TextParts {
    text: Rc<Text>,
    pool: Rc<WlShmPool>,
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    view: Rc<WpViewport>,
    fraction: Option<Rc<WpFractionalScaleV1>>,
    /// The scale asked for (120ths), and the size of the buffer attached.
    scale: u32,
    drawn: Option<(i32, i32)>,
    current: Option<Rc<WlBuffer>>,
    /// Buffers no longer attached that the compositor has not released yet.
    retired: Vec<Rc<WlBuffer>>,
    /// How much of the line the strip shows, logical pixels.
    shown: i32,
    /// Where on the strip it is: after the pad, or after buttons at the left
    /// end ([`title_layout`]).
    x: i32,
}

impl TextParts {
    /// Attach the line at `self.scale` and commit (cached: the strip's
    /// commit applies it). False when there is nothing to draw it in.
    fn draw(&mut self) -> bool {
        let Some(drawn) = self.text.at(self.scale) else {
            return false;
        };
        let (width, height, offset) = (drawn.width, drawn.height, drawn.offset);
        let pixels = self.text.pixels();
        let buffer = memfd_buffer(&self.pool, (width, height), offset, drawn.lease, pixels);
        attach_whole(&self.surface, &buffer, width, height);
        retire(&mut self.current, &mut self.retired);
        self.current = Some(buffer);
        self.drawn = Some((width, height));
        self.crop();
        self.surface.send_commit();
        true
    }

    /// The viewport: `shown` logical pixels of the line, from the buffer's
    /// left, the strip's height.
    fn crop(&self) {
        let Some((width, height)) = self.drawn else {
            return;
        };
        let source = source_width(self.shown, self.text.width(), width);
        let zero = Fixed::from_i32_saturating(0);
        self.view.send_set_source(
            zero,
            zero,
            Fixed::from_i32_saturating(source),
            Fixed::from_i32_saturating(height),
        );
        self.view.send_set_destination(self.shown, TITLE_HEIGHT);
    }

    /// Put the text at `x` on the strip and fit it to `room` there (its pads
    /// included); committed (cached) when that changed what it shows. Its
    /// place is the strip's state, applied with the strip.
    fn fit(&mut self, x: i32, room: i32) {
        let shown = text_shown(room, self.text.width());
        self.place(x, shown);
    }

    /// Put the line's image at `x` on the strip, `shown` logical pixels of
    /// it (the tag's: as much of it as the row has room for).
    fn place(&mut self, x: i32, shown: i32) {
        if x != self.x {
            self.sub.send_set_position(x, 0);
            self.x = x;
        }
        if shown == self.shown && (shown <= 0 || self.drawn.is_some()) {
            return;
        }
        self.shown = shown;
        if shown <= 0 {
            self.surface.send_attach(None, 0, 0);
            retire(&mut self.current, &mut self.retired);
            self.drawn = None;
            self.surface.send_commit();
        } else if self.drawn.is_none() {
            self.draw();
        } else {
            self.crop();
            self.surface.send_commit();
        }
    }

    fn destroy(mut self) {
        if let Some(fraction) = &self.fraction {
            fraction.send_destroy();
        }
        self.view.send_destroy();
        self.sub.send_destroy();
        self.surface.send_destroy();
        destroy_buffers(self.current.take(), std::mem::take(&mut self.retired));
    }
}

/// The buttons on a title strip (§5.11): the row of the launch's look
/// (`Text::look`) at the scale
/// the compositor prefers, in the image of the state it is in — at rest, a
/// button under the pointer, a button pressed. Another state is another
/// buffer of the same region of the memfd, drawn once for the scale; the
/// viewport gives it the row's logical size.
struct ButtonParts {
    text: Rc<Text>,
    pool: Rc<WlShmPool>,
    surface: Rc<WlSurface>,
    sub: Rc<WlSubsurface>,
    view: Rc<WpViewport>,
    /// The scale asked for (120ths).
    scale: u32,
    /// Where on the strip the row is; `None`: the strip is too narrow for
    /// it, and it is not there.
    at: Option<i32>,
    /// The button lit, and whether pressed.
    lit: Option<Lit>,
    current: Option<Rc<WlBuffer>>,
    retired: Vec<Rc<WlBuffer>>,
}

impl ButtonParts {
    /// Attach the row in its state at `self.scale` and commit (cached: the
    /// strip's commit applies it). False when there is nothing to draw it
    /// in.
    fn draw(&mut self) -> bool {
        let Some(drawn) = self.text.buttons_at(self.scale) else {
            return false;
        };
        let (width, height) = (drawn.width, drawn.height);
        let image = width.saturating_mul(height).saturating_mul(4);
        let variant = i32::try_from(self.text.look().buttons.variant(self.lit)).unwrap_or(0);
        let offset = drawn.offset.saturating_add(image.saturating_mul(variant));
        let buffer = memfd_buffer(
            &self.pool,
            (width, height),
            offset,
            drawn.lease,
            Pixels::Opaque,
        );
        attach_whole(&self.surface, &buffer, width, height);
        retire(&mut self.current, &mut self.retired);
        self.current = Some(buffer);
        self.surface.send_commit();
        true
    }

    /// Put the row at `at` on the strip, or take it away (`None`: no room).
    /// Its place is the strip's state, applied with the strip; its buffer is
    /// committed (cached) when that changes.
    fn fit(&mut self, at: Option<i32>) {
        match at {
            Some(x) => {
                if self.at != Some(x) {
                    self.sub.send_set_position(x, 0);
                }
                self.at = Some(x);
                if self.current.is_none() {
                    self.draw();
                }
            }
            None => {
                self.at = None;
                self.lit = None;
                if self.current.is_some() {
                    self.surface.send_attach(None, 0, 0);
                    retire(&mut self.current, &mut self.retired);
                    self.surface.send_commit();
                }
            }
        }
    }

    /// The row in state `lit`, committed (cached) when it is there and that
    /// changed its image. Whether it did: the caller shows it now.
    fn light(&mut self, lit: Option<Lit>) -> bool {
        if self.lit == lit {
            return false;
        }
        self.lit = lit;
        self.at.is_some() && self.draw()
    }

    /// Drawn anew at `scale` when it is there. Whether it was.
    fn rescale(&mut self, scale: u32) -> bool {
        if self.scale == scale && (self.at.is_none() || self.current.is_some()) {
            return false;
        }
        self.scale = scale;
        self.at.is_some() && self.draw()
    }

    fn destroy(mut self) {
        self.view.send_destroy();
        self.sub.send_destroy();
        self.surface.send_destroy();
        destroy_buffers(self.current.take(), std::mem::take(&mut self.retired));
    }
}

/// The window's round corners (`Look::corners`): four subsurfaces of the
/// program's root over the corners of its content ([`corner_rects`]), each
/// a buffer of the region of the title's memfd that holds the four at the
/// scale — the title's colour where the window's corner is cut off, clear
/// inside the quarter circle —, the viewport giving it its logical size.
/// Synchronized, like the strips: their place and size go with the
/// program's commit; a new scale shows at once (desync, commit, sync).
struct CornerParts {
    text: Rc<Text>,
    pool: Rc<WlShmPool>,
    /// Top left, top right, bottom left, bottom right.
    pieces: Vec<Strip>,
    /// Their own scale, when the window has no text to take it from.
    fraction: Option<Rc<WpFractionalScaleV1>>,
    /// The scale asked for (120ths).
    scale: u32,
    /// The side they are laid at, logical pixels; `None`: not laid (a
    /// window too small for them).
    laid: Option<i32>,
    /// The buffers attached, one a corner; none before the first layout.
    current: Vec<Rc<WlBuffer>>,
    retired: Vec<Rc<WlBuffer>>,
}

impl CornerParts {
    /// Attach the four at `self.scale` and commit each (cached: the root's
    /// commit applies them). False when there is nothing to draw them in.
    fn draw(&mut self) -> bool {
        let Some(drawn) = self.text.corners_at(self.scale) else {
            return false;
        };
        let (width, height) = (drawn.width, drawn.height);
        let image = width.saturating_mul(height).saturating_mul(4);
        let old = std::mem::take(&mut self.current);
        for (corner, piece) in (0i32..).zip(&self.pieces) {
            let offset = drawn.offset.saturating_add(image.saturating_mul(corner));
            let buffer = memfd_buffer(
                &self.pool,
                (width, height),
                offset,
                drawn.lease.another(),
                Pixels::Alpha,
            );
            attach_whole(&piece.surface, &buffer, width, height);
            piece.surface.send_commit();
            self.current.push(buffer);
        }
        self.retired.extend(old);
        sweep(&mut self.retired);
        true
    }

    /// Lay them over the corners of `g` at `radius` (cached, applied with
    /// the program's commit), drawn the first time; a window too small for
    /// them has none.
    fn lay(&mut self, g: Rect, radius: i32) {
        let Some(rects) = corner_rects(g, radius) else {
            if !self.current.is_empty() {
                for piece in &self.pieces {
                    piece.surface.send_attach(None, 0, 0);
                    piece.surface.send_commit();
                }
                self.retired.append(&mut self.current);
                sweep(&mut self.retired);
            }
            self.laid = None;
            return;
        };
        for (piece, r) in self.pieces.iter().zip(rects) {
            piece.sub.send_set_position(r.x, r.y);
            piece.viewport.send_set_destination(r.w, r.h);
            piece.surface.send_commit();
        }
        self.laid = Some(rects[0].w);
        if self.current.is_empty() {
            self.draw();
        }
    }

    /// Drawn anew at `scale` when they are laid. Whether they were.
    fn rescale(&mut self, scale: u32) -> bool {
        if self.scale == scale && (self.laid.is_none() || !self.current.is_empty()) {
            return false;
        }
        self.scale = scale;
        self.laid.is_some() && self.draw()
    }

    /// Show what is pending of them now, as `TitleParts::apply_now` the
    /// title: each desynchronized for its own commit, and synchronized
    /// again at once.
    fn apply_now(&self) {
        for piece in &self.pieces {
            piece.sub.send_set_desync();
            piece.surface.send_commit();
            piece.sub.send_set_sync();
        }
    }

    fn destroy(mut self) {
        if let Some(fraction) = &self.fraction {
            fraction.send_destroy();
        }
        for piece in &self.pieces {
            piece.viewport.send_destroy();
            piece.sub.send_destroy();
            piece.surface.send_destroy();
        }
        let mut all = std::mem::take(&mut self.current);
        all.append(&mut self.retired);
        destroy_buffers(None, all);
    }
}

/// One xdg_surface of the program, toplevel or not. Weak references to the
/// program's objects: their handlers hold this, and a cycle would keep a
/// closed window's objects for the connection's life.
struct Window {
    /// Itself, for the handlers of the proxy's surfaces.
    me: Weak<RefCell<Window>>,
    xdg: Weak<XdgSurface>,
    root: Weak<WlSurface>,
    toplevel: Option<Weak<XdgToplevel>>,
    /// The launch's title mode.
    mode: TitleMode,
    /// The launch's look.
    look: Look,
    /// Decided once, when the proxy knows whether it can draw: whether the
    /// window has a frame (a border, or in the tag look the tag alone).
    bordered: Option<bool>,
    /// The program's geometry, and what the compositor was last told.
    geometry: Option<Rect>,
    sent_geometry: Option<Rect>,
    min: Option<(i32, i32)>,
    sent_min: Option<(i32, i32)>,
    max: Option<(i32, i32)>,
    sent_max: Option<(i32, i32)>,
    /// The border's strips, four a ring (none in the tag look: the frame
    /// has been made all the same).
    strips: Option<Vec<Strip>>,
    title: Option<TitleParts>,
    corners: Option<CornerParts>,
    /// Counted among the connection's framed windows while it has strips.
    counted: Option<Framed>,
    /// Fullscreen, as of the configure the program acked last: its next
    /// commit is of that state, and so is the frame laid before it (the
    /// title strip takes no room in fullscreen, §5.7). The configure the
    /// compositor sent last says `next_fullscreen` — the strip hides only
    /// while both say it ([`Self::title_wanted`]) —, and those not acked yet
    /// are kept by serial.
    fullscreen: bool,
    next_fullscreen: bool,
    configures: VecDeque<(u32, bool)>,
    /// The pointer is at the top of the window: a hover strip is wanted.
    hover: bool,
    /// What the frame is laid around now: the area, the insets, the strip.
    laid: Option<(Rect, Insets, Option<Rect>)>,
    /// The button the left pointer button went down on, until it comes up:
    /// a button acts when both happen on it.
    pressed: Option<Button>,
    /// The ≡'s dropdown, while it is open.
    menu: Option<Dropdown>,
}

impl Window {
    fn new(
        xdg: &Rc<XdgSurface>,
        root: &Rc<WlSurface>,
        me: Weak<RefCell<Window>>,
        mode: TitleMode,
        look: Look,
    ) -> Self {
        Self {
            me,
            xdg: Rc::downgrade(xdg),
            root: Rc::downgrade(root),
            toplevel: None,
            mode,
            look,
            bordered: None,
            geometry: None,
            sent_geometry: None,
            min: None,
            sent_min: None,
            max: None,
            sent_max: None,
            strips: None,
            title: None,
            corners: None,
            counted: None,
            fullscreen: false,
            next_fullscreen: false,
            configures: VecDeque::new(),
            hover: false,
            laid: None,
            pressed: None,
            menu: None,
        }
    }

    /// Whether this window has a frame now: not anything but a toplevel,
    /// nor until the proxy knows whether it can draw.
    fn framed(&mut self, f: &Frames) -> bool {
        if self.toplevel.is_none() {
            return false;
        }
        if self.bordered.is_none() && f.own.borrow().complete {
            self.bordered = Some(f.can_draw());
        }
        self.bordered == Some(true)
    }

    /// What the frame takes of the window in a state `fullscreen` or not:
    /// the border (none in the tag look), and the title strip — or the tag's
    /// row — when it takes room: always, not in fullscreen.
    fn insets(&mut self, f: &Frames, fullscreen: bool) -> Insets {
        if !self.framed(f) {
            return Insets::default();
        }
        let title = if self.mode == TitleMode::Always && !fullscreen {
            TITLE_HEIGHT
        } else {
            0
        };
        Insets {
            border: f.border_width(),
            title,
        }
    }

    /// The insets of the state the program's next commit is of.
    fn current(&mut self, f: &Frames) -> Insets {
        let fullscreen = self.fullscreen;
        self.insets(f, fullscreen)
    }

    /// The area the frame is laid around now, if it is.
    fn area(&self) -> Option<Rect> {
        self.laid.map(|(area, _, _)| area)
    }

    /// Just before the program's commit of its root surface: the geometry and
    /// the size limits it set, translated, and the frame laid around what
    /// the commit makes the window — all applied by that one commit.
    fn before_commit(
        &mut self,
        f: &Rc<Frames>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        size: Option<(i32, i32)>,
    ) {
        let i = self.current(f);
        if let (Some(g), Some(xdg)) = (self.geometry, self.xdg.upgrade()) {
            let want = geometry_up(g, i);
            if self.sent_geometry != Some(want) {
                xdg.send_set_window_geometry(want.x, want.y, want.w, want.h);
                self.sent_geometry = Some(want);
            }
        }
        if let Some(toplevel) = self.toplevel.as_ref().and_then(Weak::upgrade) {
            if let Some((w, h)) = self.min {
                let want = (size_up(w, i.across()), size_up(h, i.down()));
                if self.sent_min != Some(want) {
                    toplevel.send_set_min_size(want.0, want.1);
                    self.sent_min = Some(want);
                }
            }
            if let Some((w, h)) = self.max {
                let want = (size_up(w, i.across()), size_up(h, i.down()));
                if self.sent_max != Some(want) {
                    toplevel.send_set_max_size(want.0, want.1);
                    self.sent_max = Some(want);
                }
            }
        }
        if !self.framed(f) {
            return;
        }
        if self.strips.is_none() {
            self.strips = f.make_strips(root, top, &self.me);
            if self.strips.is_some() {
                self.counted = Some(Framed::new(&f.framed));
            }
            self.laid = None;
        }
        let area = self
            .geometry
            .or_else(|| size.map(|(w, h)| Rect { x: 0, y: 0, w, h }));
        let (Some(strips), Some(area)) = (&self.strips, area) else {
            return;
        };
        if area.w <= 0 || area.h <= 0 {
            return;
        }
        // Where the title goes: in its room when the insets keep one, else
        // over the top of the content — in mode `hover`, and in `always`
        // while the program's state is fullscreen: laid there hidden, so
        // that it can come out at once when the compositor takes the window
        // out of fullscreen before the program acks that
        // ([`Self::title_wanted`]).
        let over = self.mode != TitleMode::Off;
        let strip = if self.look.tag() {
            tag_row(area, i, over)
        } else {
            title_strip(area, i, over)
        };
        if self.laid == Some((area, i, strip)) {
            // Nothing moves; whether the strip shows may still change (the
            // program acked fullscreen, or its end).
            self.show_title(false);
            return;
        }
        let widths: Vec<i32> = self
            .look
            .rings(i.border)
            .into_iter()
            .map(|(w, _)| w)
            .collect();
        for (s, r) in strips.iter().zip(ring_strips(area, i, &widths)) {
            s.sub.send_set_position(r.x, r.y);
            s.viewport.send_set_destination(r.w, r.h);
            s.surface.send_commit();
        }
        self.laid = Some((area, i, strip));
        self.lay_title(f, root, top, strip);
        self.lay_corners(f, root, top, area);
    }

    /// The round corners over `area`'s, before the program's commit: made
    /// the first time, after the title (so, under it).
    fn lay_corners(
        &mut self,
        f: &Rc<Frames>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        area: Rect,
    ) {
        let radius = self.look.corners();
        if radius <= 0 {
            return;
        }
        if self.corners.is_none() {
            // Their own scale only when there is no text to take it from.
            let fractional = self
                .title
                .as_ref()
                .and_then(|t| t.text.as_ref())
                .is_some_and(|text| text.fraction.is_some());
            self.corners = f.make_corners(root, top, &self.me, !fractional);
        }
        if let Some(corners) = &mut self.corners {
            corners.lay(area, radius);
        }
    }

    /// Whether the title strip shows now: it is laid somewhere; in mode
    /// `hover` the pointer wants it; and fullscreen hides it only while BOTH
    /// the configure the program acked last and the one the compositor sent
    /// last say fullscreen (review 2026-09-25). The program decides when it
    /// acks: a hostile one acks the fullscreen configure and never the one
    /// that ends it, keeps committing (xdg-shell allows that), and the
    /// compositor shows the window in its normal place anyway (sway, after
    /// its transaction's timeout) — with the ack alone deciding, the strip
    /// would stay hidden for the window's life, and the program would draw
    /// another zone's in its place. Fail-closed: the compositor's word
    /// brings it out, over the top of the content (it has no room: the
    /// program's commits are still of the fullscreen size).
    fn title_wanted(&self) -> bool {
        let placed = self.laid.is_some_and(|(_, _, strip)| strip.is_some());
        let fullscreen = self.fullscreen && self.next_fullscreen;
        placed && !fullscreen && (self.mode == TitleMode::Always || self.hover)
    }

    /// Show or hide the title strip as [`Self::title_wanted`] says: `now`
    /// (the pointer, the compositor's configure — the program may not
    /// commit for a long while), or with the program's commit that comes
    /// next.
    fn show_title(&mut self, now: bool) {
        let want = self.title_wanted();
        let Some(t) = &mut self.title else {
            return;
        };
        if t.shown != want {
            t.show(want);
            if now {
                t.apply_now();
            } else {
                t.surface.send_commit();
            }
        }
    }

    /// The title strip at `strip` (or none), before the program's commit.
    fn lay_title(
        &mut self,
        f: &Rc<Frames>,
        root: &Rc<WlSurface>,
        top: &Rc<WlSurface>,
        strip: Option<Rect>,
    ) {
        let Some(r) = strip else {
            self.show_title(false);
            return;
        };
        if self.title.is_none() {
            self.title = f.make_title(root, top, &self.me);
        }
        let want = self.title_wanted();
        let Some(t) = &mut self.title else {
            return;
        };
        t.sub.send_set_position(r.x, r.y);
        t.view.send_set_destination(r.w, r.h);
        if t.shown != want {
            t.show(want);
        }
        let row = self.look.buttons.width_all();
        let tag = t.text.as_ref().and_then(|text| text.text.tag());
        if let Some(tag) = tag {
            // The tag at the row's left end, as much of it as the row has
            // room for; its buttons on it where they fit whole.
            if let Some(buttons) = &mut t.buttons {
                buttons.fit(tag.buttons.filter(|&x| x.saturating_add(row) <= r.w));
            }
            if let Some(text) = &mut t.text {
                text.place(0, tag.width.min(r.w).max(0));
            }
        } else {
            // The buttons at the look's end when there is room for them,
            // the text in what is left.
            let layout = title_layout(r.w, &self.look.buttons);
            if let Some(buttons) = &mut t.buttons {
                buttons.fit(layout.buttons);
            }
            if let Some(text) = &mut t.text {
                text.fit(layout.text_x, layout.room);
            }
        }
        t.surface.send_commit();
    }

    /// The compositor prefers `scale` (120ths) for the title's text: it,
    /// the buttons beside it and the round corners are drawn at it, and
    /// shown now.
    fn rescale(&mut self, scale: u32) {
        let scale = crate::wl_title::clamp_scale(scale);
        if let Some(t) = &mut self.title {
            let mut drawn = false;
            if let Some(text) = &mut t.text {
                if text.scale != scale || text.drawn.is_none() {
                    text.scale = scale;
                    drawn |= text.shown > 0 && text.draw();
                }
            }
            if let Some(buttons) = &mut t.buttons {
                drawn |= buttons.rescale(scale);
            }
            if drawn {
                t.apply_now();
            }
        }
        if let Some(corners) = &mut self.corners {
            if corners.rescale(scale) {
                corners.apply_now();
            }
        }
    }

    /// `wl_surface.preferred_buffer_scale` of the text (or the corners): its
    /// scale where the compositor offers no fractional one.
    fn integer_scale(&mut self, factor: i32) {
        let fractional = self
            .title
            .as_ref()
            .and_then(|t| t.text.as_ref())
            .is_some_and(|text| text.fraction.is_some())
            || self.corners.as_ref().is_some_and(|c| c.fraction.is_some());
        if !fractional {
            self.rescale(u32::try_from(factor.clamp(1, 4)).unwrap_or(1) * 120);
        }
    }

    /// The pointer wants a hover strip out or in (§0а): shown now, not at the
    /// program's next commit. Nothing in another mode, nor in fullscreen.
    fn set_hover(&mut self, on: bool) {
        if self.mode != TitleMode::Hover || self.hover == on {
            return;
        }
        self.hover = on;
        self.show_title(true);
    }

    /// The compositor's configure says fullscreen or not: the strip comes
    /// out (or goes) now when that changes what [`Self::title_wanted`]
    /// says — a program that stops committing must not keep it hidden
    /// either.
    fn configured(&mut self, fullscreen: bool) {
        self.next_fullscreen = fullscreen;
        self.show_title(true);
    }

    /// What a point (`x`, `y`, surface-local) on the frame's `part` is for
    /// ([`Hit`]): the title (or the tag) moves the window, the border — any
    /// ring of it — resizes it, a button is a button of the look's row; a
    /// round corner nothing (it takes no input anyway) — and nothing while
    /// the compositor has the window fullscreen (there is nothing to move
    /// it to), nor before the frame is laid out.
    fn hit(&self, part: Part, x: f64, y: f64) -> Hit {
        let Some((area, i, _)) = self.laid else {
            return Hit::Nothing;
        };
        match part {
            Part::Buttons => self.look.buttons.at(x, y).map_or(Hit::Nothing, Hit::Button),
            Part::Corner | Part::Menu => Hit::Nothing,
            _ if self.next_fullscreen => Hit::Nothing,
            Part::Title | Part::Text => Hit::Title,
            Part::Border(side, ring) => {
                let widths: Vec<i32> = self
                    .look
                    .rings(i.border)
                    .into_iter()
                    .map(|(w, _)| w)
                    .collect();
                let Some(&strip) = ring_strips(area, i, &widths).get(ring * 4 + side.index())
                else {
                    return Hit::Nothing;
                };
                let outer = strips(area, i)[side.index()];
                Hit::Edge(ring_edges(side, strip, outer, i.border, x, y))
            }
        }
    }

    /// The buttons in state `lit`, shown now: the pointer does not wait for
    /// the program's commit.
    fn light(&mut self, lit: Option<Lit>) {
        let Some(t) = &mut self.title else {
            return;
        };
        if t.buttons.as_mut().is_some_and(|b| b.light(lit)) {
            t.apply_now();
        }
    }

    /// The pointer is over the button `under`, or over none of them: that
    /// one is lit — pressed while it is the one the pointer button went down
    /// on.
    fn hover_button(&mut self, under: Option<Button>) {
        let lit = under.map(|button| Lit {
            button,
            pressed: self.pressed == Some(button),
        });
        self.light(lit);
    }

    /// The left pointer button went down (`down`) or up over `hit`, the
    /// event of `serial` on `seat` (§5.11). Down on the title the window is
    /// moved, on the border resized — by the compositor, which issued the
    /// serial to this connection and so takes the request as the program's;
    /// down on a button it is pressed, and up on the same button it acts.
    fn click(&mut self, f: &Frames, hit: Hit, down: bool, seat: Option<&Rc<WlSeat>>, serial: u32) {
        let toplevel = self.toplevel.as_ref().and_then(Weak::upgrade);
        if down {
            self.pressed = None;
            match (hit, &toplevel, seat) {
                (Hit::Title, Some(toplevel), Some(seat)) => toplevel.send_move(seat, serial),
                (Hit::Edge(edges), Some(toplevel), Some(seat)) if edges != 0 => {
                    toplevel.send_resize(seat, serial, XdgToplevelResizeEdge(edges))
                }
                (Hit::Button(button), _, _) => {
                    self.pressed = Some(button);
                    self.hover_button(Some(button));
                }
                _ => {}
            }
            return;
        }
        let pressed = self.pressed.take();
        let Hit::Button(button) = hit else {
            return;
        };
        self.hover_button(Some(button));
        if pressed != Some(button) {
            return;
        }
        match button {
            // What a server-side decoration's "close" is: the program's own
            // close event; it may ask whether to save.
            Button::Close => {
                if let Some(toplevel) = &toplevel {
                    toplevel.send_close();
                }
            }
            // The dropdown where it can be (step 3c); else the window menu
            // as before.
            Button::Menu => {
                if !self.open_menu(f, seat, serial) {
                    f.asks.push(Ask::Menu);
                }
            }
            Button::Network => f.asks.push(Ask::Network),
        }
    }

    /// Put the strips, the title and the round corners on top of the root's
    /// stack again, above `top`. Each goes right above `top`, so the last
    /// placed is the lowest of them: the corners under the title — a hover
    /// strip lies over the top corners.
    fn raise(&self, top: &Rc<WlSurface>) {
        for strip in self.strips.iter().flatten() {
            strip.sub.send_place_above(top);
        }
        if let Some(t) = &self.title {
            t.sub.send_place_above(top);
        }
        for piece in self.corners.iter().flat_map(|c| &c.pieces) {
            piece.sub.send_place_above(top);
        }
    }

    /// The window is gone (its toplevel or xdg_surface destroyed): so is its
    /// frame, at once — a subsurface's destruction does not wait for a
    /// commit.
    fn drop_strips(&mut self) {
        self.close_menu();
        for strip in self.strips.take().into_iter().flatten() {
            strip.viewport.send_destroy();
            strip.sub.send_destroy();
            strip.surface.send_destroy();
        }
        if let Some(t) = self.title.take() {
            t.destroy();
        }
        if let Some(corners) = self.corners.take() {
            corners.destroy();
        }
        self.counted = None;
        self.laid = None;
    }
}

// --- THE ≡'S DROPDOWN (step 3c of docs/PERMISSIONS.md §11.15) ---------------

/// The ≡'s dropdown: an `xdg_popup` of the program's window, a surface of the
/// proxy's own — the program cannot name it, draw in it, nor hear what is
/// done in it. Its rows are `wl_title::MENU_LABELS`, drawn in the title's
/// memfd ([`Text::menu_at`]) with every state an image: a row lights under
/// the pointer (a new buffer of the same region, no drawing) and acts on the
/// release of the left button over it; ↑ ↓ light another, Enter or Space
/// acts, Esc closes. The popup takes the grab with the click's serial: the
/// keyboard is its while it is open, and the compositor closes it on a click
/// elsewhere (`popup_done`). Where it cannot be — no `xdg_wm_base` of the
/// proxy's own, no font, no row of buttons laid —, the ≡ asks for the
/// window menu as it did.
struct Dropdown {
    surface: Rc<WlSurface>,
    view: Rc<WpViewport>,
    xdg: Rc<XdgSurface>,
    popup: Rc<XdgPopup>,
    text: Rc<Text>,
    pool: Rc<WlShmPool>,
    /// The buttons' scale when it opened (120ths).
    scale: u32,
    /// Logical pixels, and the rows.
    size: (i32, i32),
    rows: usize,
    lit: Option<usize>,
    /// The compositor configured it: it may be drawn.
    configured: bool,
    current: Option<Rc<WlBuffer>>,
    retired: Vec<Rc<WlBuffer>>,
}

impl Dropdown {
    /// Its image in its state, attached and committed; false when there is
    /// nothing to draw it in.
    fn draw(&mut self) -> bool {
        let Some(drawn) = self.text.menu_at(self.scale) else {
            return false;
        };
        let (width, height) = (drawn.width, drawn.height);
        let image = width.saturating_mul(height).saturating_mul(4);
        let variant = self.lit.map_or(0, |row| row.saturating_add(1));
        let offset = drawn
            .offset
            .saturating_add(image.saturating_mul(i32::try_from(variant).unwrap_or(0)));
        let buffer = memfd_buffer(
            &self.pool,
            (width, height),
            offset,
            drawn.lease,
            Pixels::Opaque,
        );
        attach_whole(&self.surface, &buffer, width, height);
        self.view.send_set_destination(self.size.0, self.size.1);
        retire(&mut self.current, &mut self.retired);
        self.current = Some(buffer);
        self.surface.send_commit();
        true
    }

    /// `row` lit (none: nothing), shown at once where it changed.
    fn light(&mut self, row: Option<usize>) {
        let row = row.filter(|r| *r < self.rows);
        if self.lit == row {
            return;
        }
        self.lit = row;
        if self.configured {
            self.draw();
        }
    }

    /// Gone: the popup first, then its role and its surface.
    fn destroy(mut self) {
        self.popup.send_destroy();
        self.xdg.send_destroy();
        self.view.send_destroy();
        self.surface.send_destroy();
        destroy_buffers(self.current.take(), std::mem::take(&mut self.retired));
    }
}

/// Where the ≡ is, in the geometry the compositor was told (§5.2) — what a
/// popup's anchor is relative to: the strip `strip` and the row of buttons
/// `at` pixels into it (root surface coordinates, as the program's own
/// geometry `geometry` sent), the ≡ its cell of the look.
pub(crate) fn menu_anchor(
    strip: Rect,
    at: i32,
    geometry: Rect,
    look: &ButtonsLook,
) -> Option<Rect> {
    let cell = look.order.iter().position(|b| b.button == Button::Menu)?;
    let x = strip
        .x
        .saturating_add(at)
        .saturating_add(look.width.saturating_mul(i32::try_from(cell).ok()?));
    Some(Rect {
        x: x.saturating_sub(geometry.x),
        y: strip.y.saturating_sub(geometry.y),
        w: look.width.max(1),
        h: TITLE_HEIGHT,
    })
}

/// evdev key codes the dropdown answers.
const KEY_ESC: u32 = 1;
const KEY_ENTER: u32 = 28;
const KEY_SPACE: u32 = 57;
const KEY_KPENTER: u32 = 96;
const KEY_UP: u32 = 103;
const KEY_DOWN: u32 = 108;

/// What a key does in a dropdown of `rows` with `lit` lit: another row lit,
/// the lit one's action, or the dropdown closed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MenuKey {
    Light(usize),
    Act(usize),
    Close,
    Nothing,
}

pub(crate) fn menu_key(key: u32, rows: usize, lit: Option<usize>) -> MenuKey {
    if rows == 0 {
        return MenuKey::Close;
    }
    match key {
        KEY_ESC => MenuKey::Close,
        KEY_DOWN => MenuKey::Light(lit.map_or(0, |r| (r + 1) % rows)),
        KEY_UP => MenuKey::Light(lit.map_or(rows - 1, |r| (r + rows - 1) % rows)),
        KEY_ENTER | KEY_KPENTER | KEY_SPACE => lit.map_or(MenuKey::Nothing, MenuKey::Act),
        _ => MenuKey::Nothing,
    }
}

impl Window {
    /// The ≡'s dropdown opened under it, taking the grab with `serial` on
    /// `seat` (the click's). False when it cannot be: the caller asks for
    /// the window menu instead. One at a time on the connection: another
    /// window's goes.
    fn open_menu(&mut self, f: &Frames, seat: Option<&Rc<WlSeat>>, serial: u32) -> bool {
        if self.menu.is_some() {
            self.close_menu();
            return true;
        }
        let (Some(seat), Some(text), Some(parent)) = (seat, f.text.clone(), self.xdg.upgrade())
        else {
            return false;
        };
        let (Some((_, _, Some(strip))), Some(geometry)) = (self.laid, self.sent_geometry) else {
            return false;
        };
        let Some((at, scale)) = self
            .title
            .as_ref()
            .and_then(|t| t.buttons.as_ref())
            .and_then(|b| b.at.map(|at| (at, b.scale)))
        else {
            return false;
        };
        let Some(anchor) = menu_anchor(strip, at, geometry, &self.look.buttons) else {
            return false;
        };
        let (compositor, viewporter, wm_base, pool) = {
            let own = f.own.borrow();
            (
                own.compositor.clone(),
                own.viewporter.clone(),
                own.wm_base.clone(),
                own.text_pool.clone(),
            )
        };
        let (Some(compositor), Some(viewporter), Some(wm_base), Some(pool)) =
            (compositor, viewporter, wm_base, pool)
        else {
            return false;
        };
        if let Some(other) = f.menu_on.take().and_then(|w| w.upgrade()) {
            if let Ok(mut other) = other.try_borrow_mut() {
                other.close_menu();
            }
        }
        let ((w, h), rows) = text.menu_size();
        let surface = compositor.new_send_create_surface();
        quiet(&*surface);
        surface.set_handler(Mine {
            window: self.me.clone(),
            part: Part::Menu,
        });
        let view = viewporter.new_send_get_viewport(&surface);
        quiet(&*view);
        let xdg = wm_base.new_send_get_xdg_surface(&surface);
        quiet(&*xdg);
        xdg.set_handler(MenuXdg {
            window: self.me.clone(),
        });
        let positioner = wm_base.new_send_create_positioner();
        quiet(&*positioner);
        positioner.send_set_size(w, h);
        positioner.send_set_anchor_rect(anchor.x, anchor.y, anchor.w, anchor.h);
        // Under the ≡, toward the middle of the window: its end is the
        // look's.
        let (anchor_at, gravity) = match self.look.buttons.end {
            End::Right => (
                XdgPositionerAnchor::BOTTOM_RIGHT,
                XdgPositionerGravity::BOTTOM_LEFT,
            ),
            End::Left => (
                XdgPositionerAnchor::BOTTOM_LEFT,
                XdgPositionerGravity::BOTTOM_RIGHT,
            ),
        };
        positioner.send_set_anchor(anchor_at);
        positioner.send_set_gravity(gravity);
        positioner.send_set_constraint_adjustment(XdgPositionerConstraintAdjustment(
            XdgPositionerConstraintAdjustment::SLIDE_X.0
                | XdgPositionerConstraintAdjustment::SLIDE_Y.0
                | XdgPositionerConstraintAdjustment::FLIP_Y.0,
        ));
        let popup = xdg.new_send_get_popup(Some(&parent), &positioner);
        quiet(&*popup);
        popup.set_handler(MenuPopup {
            window: self.me.clone(),
        });
        positioner.send_destroy();
        popup.send_grab(seat, serial);
        surface.send_commit();
        self.menu = Some(Dropdown {
            surface,
            view,
            xdg,
            popup,
            text,
            pool,
            scale,
            size: (w, h),
            rows,
            lit: None,
            configured: false,
            current: None,
            retired: Vec::new(),
        });
        *f.menu_on.borrow_mut() = Some(self.me.clone());
        true
    }

    /// The dropdown gone, if it is open.
    fn close_menu(&mut self) {
        if let Some(menu) = self.menu.take() {
            menu.destroy();
        }
    }

    /// The pointer over the dropdown at `y` (none: off it): the row there lit.
    fn menu_hover(&mut self, y: Option<f64>) {
        if let Some(menu) = &mut self.menu {
            let row = y.and_then(|y| crate::wl_title::menu_row(menu.rows, y));
            menu.light(row);
        }
    }

    /// The left button let go over the dropdown at `y`: the row there acts.
    fn menu_click(&mut self, f: &Frames, y: f64) {
        let row = self
            .menu
            .as_ref()
            .and_then(|m| crate::wl_title::menu_row(m.rows, y));
        if let Some(row) = row {
            self.menu_act(f, row);
        }
    }

    /// A key while the dropdown has the keyboard.
    fn menu_key(&mut self, f: &Frames, key: u32) {
        let Some(menu) = &mut self.menu else {
            return;
        };
        match menu_key(key, menu.rows, menu.lit) {
            MenuKey::Light(row) => menu.light(Some(row)),
            MenuKey::Act(row) => self.menu_act(f, row),
            MenuKey::Close => self.close_menu(),
            MenuKey::Nothing => {}
        }
    }

    /// Row `row` of `wl_title::MENU_LABELS` chosen: the dropdown goes, and
    /// what the row says is asked of the supervisor — or, the last, the
    /// program's own close event, as the × does.
    fn menu_act(&mut self, f: &Frames, row: usize) {
        let Some(menu) = self.menu.take() else {
            return;
        };
        let asks = &f.asks;
        menu.destroy();
        match row {
            0 => asks.push(Ask::Network),
            1 => asks.push(Ask::Restart),
            2 => asks.push(Ask::Menu),
            3 => {
                if let Some(toplevel) = self.toplevel.as_ref().and_then(Weak::upgrade) {
                    toplevel.send_close();
                }
            }
            _ => {}
        }
    }
}

/// The proxy's own `xdg_wm_base`: it answers the compositor's pings itself.
struct OwnWmBase;

impl XdgWmBaseHandler for OwnWmBase {
    fn handle_ping(&mut self, slf: &Rc<XdgWmBase>, serial: u32) {
        slf.send_pong(serial);
    }
}

/// The dropdown's `xdg_surface`: a configure is acked and the dropdown
/// drawn.
struct MenuXdg {
    window: Weak<RefCell<Window>>,
}

impl XdgSurfaceHandler for MenuXdg {
    fn handle_configure(&mut self, slf: &Rc<XdgSurface>, serial: u32) {
        slf.send_ack_configure(serial);
        let Some(window) = self.window.upgrade() else {
            return;
        };
        if let Ok(mut window) = window.try_borrow_mut() {
            if let Some(menu) = &mut window.menu {
                menu.configured = true;
                menu.draw();
            }
        };
    }
}

/// The dropdown's `xdg_popup`: dismissed by the compositor (a click
/// elsewhere, the window gone), it goes.
struct MenuPopup {
    window: Weak<RefCell<Window>>,
}

impl XdgPopupHandler for MenuPopup {
    fn handle_configure(&mut self, _slf: &Rc<XdgPopup>, _x: i32, _y: i32, _w: i32, _h: i32) {}

    fn handle_popup_done(&mut self, _slf: &Rc<XdgPopup>) {
        if let Some(window) = self.window.upgrade() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.close_menu();
            };
        }
    }
}

/// The program's keyboard. While a surface of the proxy's has its focus —
/// the dropdown, whose grab took it —, nothing of it is the program's: the
/// enter, the keys, the modifiers and the leave are the dropdown's. Every
/// `wl_keyboard` of the program hears a key; the dropdown acts on it once
/// ([`Frames::first`]).
struct Keyboard {
    f: Rc<Frames>,
    menu: bool,
    /// The keys down on the program's surface, and its locked modifiers and
    /// group: what a held-back leave lets go of (3d).
    down: Vec<u32>,
    locked: (u32, u32),
    /// The program's surface a leave of it was held back from (3d,
    /// `Frames::always_focused`): passed on before the next enter.
    held: Option<Weak<WlSurface>>,
}

impl WlKeyboardHandler for Keyboard {
    fn handle_enter(
        &mut self,
        slf: &Rc<WlKeyboard>,
        serial: u32,
        surface: &Rc<WlSurface>,
        keys: &[u8],
    ) {
        self.menu = !programs(surface);
        if !self.menu {
            if let Some(gone) = self.held.take().and_then(|w| w.upgrade()).filter(programs) {
                slf.send_leave(serial, &gone);
            }
            self.down = keys
                .as_chunks::<4>()
                .0
                .iter()
                .map(|k| u32::from_ne_bytes(*k))
                .take(32)
                .collect();
            slf.send_enter(serial, surface, keys);
        }
    }

    fn handle_leave(&mut self, slf: &Rc<WlKeyboard>, serial: u32, surface: &Rc<WlSurface>) {
        if programs(surface) {
            if self.f.always_focused {
                // It keeps the focus (3d): what is down is let go of, the
                // modifiers but the locked ones with it.
                for key in std::mem::take(&mut self.down) {
                    slf.send_key(serial, 0, key, WlKeyboardKeyState::RELEASED);
                }
                slf.send_modifiers(serial, 0, 0, self.locked.0, self.locked.1);
                self.held = Some(Rc::downgrade(surface));
            } else {
                slf.send_leave(serial, surface);
            }
        }
        self.menu = false;
    }

    fn handle_key(
        &mut self,
        slf: &Rc<WlKeyboard>,
        serial: u32,
        time: u32,
        key: u32,
        state: WlKeyboardKeyState,
    ) {
        if !self.menu {
            if state == WlKeyboardKeyState::PRESSED {
                if !self.down.contains(&key) && self.down.len() < 32 {
                    self.down.push(key);
                }
            } else {
                self.down.retain(|k| *k != key);
            }
            slf.send_key(serial, time, key, state);
            return;
        }
        if state != WlKeyboardKeyState::PRESSED || !self.f.first(serial) {
            return;
        }
        let window = self.f.menu_on.borrow().as_ref().and_then(Weak::upgrade);
        if let Some(window) = window {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.menu_key(&self.f, key);
            };
        }
    }

    fn handle_modifiers(
        &mut self,
        slf: &Rc<WlKeyboard>,
        serial: u32,
        mods_depressed: u32,
        mods_latched: u32,
        mods_locked: u32,
        group: u32,
    ) {
        if !self.menu {
            self.locked = (mods_locked, group);
            slf.send_modifiers(serial, mods_depressed, mods_latched, mods_locked, group);
        }
    }
}

/// A layer of a surface's stack of subsurfaces: the surface itself, or a
/// child (by its wl-proxy id, which is unique for the connection's life).
enum Layer {
    Itself,
    Child(u64, Weak<WlSurface>),
}

/// wl_surface state the size of a root surface comes from, pending and
/// committed.
#[derive(Default)]
struct Pending {
    buffer: Option<Option<(i32, i32)>>,
    scale: Option<i32>,
    transform: Option<u32>,
    destination: Option<Option<(i32, i32)>>,
    source: Option<Option<(i32, i32)>>,
}

struct Committed {
    buffer: Option<(i32, i32)>,
    scale: i32,
    transform: u32,
    destination: Option<(i32, i32)>,
    source: Option<(i32, i32)>,
}

impl Default for Committed {
    fn default() -> Self {
        Self {
            buffer: None,
            scale: 1,
            transform: 0,
            destination: None,
            source: None,
        }
    }
}

/// Every surface of the program.
struct Surface {
    f: Rc<Frames>,
    /// Its xdg_surface, when it has one.
    window: Option<Rc<RefCell<Window>>>,
    /// The surface it is a subsurface of.
    parent: Option<Weak<WlSurface>>,
    /// Itself and its subsurfaces, bottom to top — as the compositor has
    /// them pending, so that the strips can be put above the top.
    stack: Vec<Layer>,
    pending: Pending,
    committed: Committed,
}

impl Surface {
    fn new(f: Rc<Frames>) -> Self {
        Self {
            f,
            window: None,
            parent: None,
            stack: vec![Layer::Itself],
            pending: Pending::default(),
            committed: Committed::default(),
        }
    }

    /// The topmost layer of this surface's stack.
    fn top(&self, me: &Rc<WlSurface>) -> Rc<WlSurface> {
        for layer in self.stack.iter().rev() {
            match layer {
                Layer::Itself => return me.clone(),
                Layer::Child(_, child) => {
                    if let Some(child) = child.upgrade() {
                        return child;
                    }
                }
            }
        }
        me.clone()
    }

    fn position(&self, id: Option<u64>) -> Option<usize> {
        self.stack.iter().position(|layer| match (layer, id) {
            (Layer::Itself, None) => true,
            (Layer::Child(c, _), Some(id)) => *c == id,
            _ => false,
        })
    }

    /// `child` moved just above or below `sibling` (this surface itself when
    /// it is the parent).
    fn reorder(
        &mut self,
        me: &Rc<WlSurface>,
        child: &Rc<WlSurface>,
        sibling: &Rc<WlSurface>,
        above: bool,
    ) {
        let Some(from) = self.position(Some(child.unique_id())) else {
            return;
        };
        let layer = self.stack.remove(from);
        let sibling = (!Rc::ptr_eq(sibling, me)).then(|| sibling.unique_id());
        // A sibling that is none (the compositor refuses it) leaves the
        // child where it would be: on top.
        let at = self
            .position(sibling)
            .map_or(self.stack.len(), |i| if above { i + 1 } else { i });
        self.stack.insert(at, layer);
        self.restack(me);
    }

    fn remove(&mut self, child: u64) {
        if let Some(at) = self.position(Some(child)) {
            self.stack.remove(at);
        }
    }

    /// The strips of this surface's window, if it has them, back on top.
    fn restack(&self, me: &Rc<WlSurface>) {
        if let Some(window) = &self.window {
            if let Ok(window) = window.try_borrow() {
                window.raise(&self.top(me));
            }
        }
    }
}

impl WlSurfaceHandler for Surface {
    fn handle_attach(
        &mut self,
        slf: &Rc<WlSurface>,
        buffer: Option<&Rc<WlBuffer>>,
        x: i32,
        y: i32,
    ) {
        slf.send_attach(buffer, x, y);
        self.pending.buffer = Some(buffer.and_then(|b| {
            b.try_get_handler_ref::<BufferSize>()
                .ok()
                .map(|s| (s.width, s.height))
        }));
    }

    fn handle_set_buffer_scale(&mut self, slf: &Rc<WlSurface>, scale: i32) {
        slf.send_set_buffer_scale(scale);
        self.pending.scale = Some(scale);
    }

    fn handle_set_buffer_transform(&mut self, slf: &Rc<WlSurface>, transform: WlOutputTransform) {
        slf.send_set_buffer_transform(transform);
        self.pending.transform = Some(transform.0);
    }

    fn handle_commit(&mut self, slf: &Rc<WlSurface>) {
        let p = std::mem::take(&mut self.pending);
        let c = &mut self.committed;
        if let Some(buffer) = p.buffer {
            c.buffer = buffer;
        }
        if let Some(scale) = p.scale {
            c.scale = scale;
        }
        if let Some(transform) = p.transform {
            c.transform = transform;
        }
        if let Some(destination) = p.destination {
            c.destination = destination;
        }
        if let Some(source) = p.source {
            c.source = source;
        }
        if let Some(window) = &self.window {
            if let Ok(mut window) = window.try_borrow_mut() {
                let top = self.top(slf);
                window.before_commit(&self.f, slf, &top, surface_size(&self.committed));
            }
        }
        slf.send_commit();
    }

    fn handle_destroy(&mut self, slf: &Rc<WlSurface>) {
        slf.send_destroy();
        if let Some(window) = self.window.take() {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.drop_strips();
            }
        }
        // It leaves its parent's stack (its subsurface is inert now).
        if let Some(parent) = self.parent.take().and_then(|p| p.upgrade()) {
            if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
                h.remove(slf.unique_id());
            }
        }
        slf.unset_handler();
    }
}

struct Compositor {
    f: Rc<Frames>,
}

impl WlCompositorHandler for Compositor {
    fn handle_create_surface(&mut self, slf: &Rc<WlCompositor>, id: &Rc<WlSurface>) {
        slf.send_create_surface(id);
        id.set_handler(Surface::new(self.f.clone()));
    }
}

struct Subcompositor;

impl WlSubcompositorHandler for Subcompositor {
    fn handle_get_subsurface(
        &mut self,
        slf: &Rc<WlSubcompositor>,
        id: &Rc<WlSubsurface>,
        surface: &Rc<WlSurface>,
        parent: &Rc<WlSurface>,
    ) {
        slf.send_get_subsurface(id, surface, parent);
        if Rc::ptr_eq(surface, parent) {
            // The compositor's error to raise.
            return;
        }
        if let Ok(mut h) = surface.try_get_handler_mut::<Surface>() {
            h.parent = Some(Rc::downgrade(parent));
        }
        if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
            // A new subsurface goes on top of its parent's stack — above the
            // strips, until they are raised again right here.
            h.stack
                .push(Layer::Child(surface.unique_id(), Rc::downgrade(surface)));
            h.restack(parent);
        }
        id.set_handler(Subsurface {
            child: Rc::downgrade(surface),
            parent: Rc::downgrade(parent),
        });
    }
}

struct Subsurface {
    child: Weak<WlSurface>,
    parent: Weak<WlSurface>,
}

impl Subsurface {
    fn reorder(&self, sibling: &Rc<WlSurface>, above: bool) {
        let (Some(child), Some(parent)) = (self.child.upgrade(), self.parent.upgrade()) else {
            return;
        };
        if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
            h.reorder(&parent, &child, sibling, above);
        };
    }
}

impl WlSubsurfaceHandler for Subsurface {
    fn handle_place_above(&mut self, slf: &Rc<WlSubsurface>, sibling: &Rc<WlSurface>) {
        slf.send_place_above(sibling);
        self.reorder(sibling, true);
    }

    fn handle_place_below(&mut self, slf: &Rc<WlSubsurface>, sibling: &Rc<WlSurface>) {
        slf.send_place_below(sibling);
        self.reorder(sibling, false);
    }

    fn handle_destroy(&mut self, slf: &Rc<WlSubsurface>) {
        slf.send_destroy();
        let child = self.child.upgrade();
        if let (Some(child), Some(parent)) = (&child, self.parent.upgrade()) {
            if let Ok(mut h) = parent.try_get_handler_mut::<Surface>() {
                h.remove(child.unique_id());
            }
        }
        if let Some(child) = child {
            if let Ok(mut h) = child.try_get_handler_mut::<Surface>() {
                h.parent = None;
            }
        }
        slf.unset_handler();
    }
}

struct WmBase {
    f: Rc<Frames>,
}

impl XdgWmBaseHandler for WmBase {
    fn handle_get_xdg_surface(
        &mut self,
        slf: &Rc<XdgWmBase>,
        id: &Rc<XdgSurface>,
        surface: &Rc<WlSurface>,
    ) {
        slf.send_get_xdg_surface(id, surface);
        // Only a surface whose commits pass here can have its geometry kept
        // for its commit; any other (none should be) is passed on as it is.
        let (mode, look) = (self.f.mode, self.f.look);
        let window =
            Rc::new_cyclic(|me| RefCell::new(Window::new(id, surface, me.clone(), mode, look)));
        let attached = match surface.try_get_handler_mut::<Surface>() {
            Ok(mut h) => {
                h.window = Some(window.clone());
                true
            }
            Err(_) => false,
        };
        if attached {
            id.set_handler(XdgSurfaceH {
                f: self.f.clone(),
                window,
            });
        }
    }

    fn handle_create_positioner(&mut self, slf: &Rc<XdgWmBase>, id: &Rc<XdgPositioner>) {
        slf.send_create_positioner(id);
        id.set_handler(Positioner::default());
    }
}

struct XdgSurfaceH {
    f: Rc<Frames>,
    window: Rc<RefCell<Window>>,
}

impl XdgSurfaceHandler for XdgSurfaceH {
    fn handle_set_window_geometry(
        &mut self,
        slf: &Rc<XdgSurface>,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        // An empty one is an error: the compositor's to raise, now.
        if width <= 0 || height <= 0 {
            slf.send_set_window_geometry(x, y, width, height);
            return;
        }
        match self.window.try_borrow_mut() {
            Ok(mut window) => {
                window.geometry = Some(Rect {
                    x,
                    y,
                    w: width,
                    h: height,
                })
            }
            Err(_) => slf.send_set_window_geometry(x, y, width, height),
        }
    }

    fn handle_get_toplevel(&mut self, slf: &Rc<XdgSurface>, id: &Rc<XdgToplevel>) {
        slf.send_get_toplevel(id);
        crate::wl_proxy::window_opened();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.toplevel = Some(Rc::downgrade(id));
        }
        id.set_handler(Toplevel {
            f: self.f.clone(),
            window: self.window.clone(),
        });
    }

    fn handle_get_popup(
        &mut self,
        slf: &Rc<XdgSurface>,
        id: &Rc<XdgPopup>,
        parent: Option<&Rc<XdgSurface>>,
        positioner: &Rc<XdgPositioner>,
    ) {
        let i = parent.map_or(Insets::default(), |p| insets_of_xdg(&self.f, p));
        with_positioner_up(positioner, i, || slf.send_get_popup(id, parent, positioner));
        id.set_handler(Popup { i });
    }

    /// The compositor's configure of this surface: whether it says
    /// fullscreen (its toplevel's configure came just before) is kept by
    /// serial, until the program acks it.
    fn handle_configure(&mut self, slf: &Rc<XdgSurface>, serial: u32) {
        if let Ok(mut window) = self.window.try_borrow_mut() {
            let fullscreen = window.next_fullscreen;
            window.configures.push_back((serial, fullscreen));
            if window.configures.len() > MAX_CONFIGURES {
                window.configures.pop_front();
            }
        }
        slf.send_configure(serial);
    }

    /// The program acks a configure: its next commit is of that state, and
    /// of every one before it (xdg-shell).
    fn handle_ack_configure(&mut self, slf: &Rc<XdgSurface>, serial: u32) {
        slf.send_ack_configure(serial);
        if let Ok(mut window) = self.window.try_borrow_mut() {
            if let Some(at) = window.configures.iter().position(|(s, _)| *s == serial) {
                window.fullscreen = window.configures[at].1;
                window.configures.drain(..=at);
            }
        }
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgSurface>) {
        // Its popup of the proxy's first: a parent outlives its popups.
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.close_menu();
        }
        slf.send_destroy();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.drop_strips();
            if let Some(root) = window.root.upgrade() {
                if let Ok(mut h) = root.try_get_handler_mut::<Surface>() {
                    h.window = None;
                }
            }
        }
        slf.unset_handler();
    }
}

/// The frame of the window whose xdg_surface is `xdg` now (none when not
/// ours or not framed).
fn insets_of_xdg(f: &Frames, xdg: &Rc<XdgSurface>) -> Insets {
    xdg.try_get_handler_ref::<XdgSurfaceH>()
        .ok()
        .and_then(|h| h.window.try_borrow_mut().ok().map(|mut w| w.current(f)))
        .unwrap_or_default()
}

/// The frame of the window of `toplevel` now.
fn insets_of_toplevel(f: &Frames, toplevel: &Rc<XdgToplevel>) -> Insets {
    toplevel
        .try_get_handler_ref::<Toplevel>()
        .ok()
        .and_then(|h| h.window.try_borrow_mut().ok().map(|mut w| w.current(f)))
        .unwrap_or_default()
}

/// Send `call` (a popup made or moved on `positioner`) with the positioner's
/// anchor rect and parent size translated into the compositor's geometry of
/// a parent with the frame `i`, and put them back after: the positioner's
/// state is copied when it is used, and the program may use it again
/// elsewhere.
fn with_positioner_up(positioner: &Rc<XdgPositioner>, i: Insets, call: impl FnOnce()) {
    let state = if i != Insets::default() {
        positioner
            .try_get_handler_ref::<Positioner>()
            .ok()
            .map(|p| (p.anchor, p.parent_size))
    } else {
        None
    };
    let Some((anchor, parent_size)) = state else {
        call();
        return;
    };
    if let Some(a) = anchor {
        positioner.send_set_anchor_rect(point_up(a.x, i.border), point_up(a.y, i.top()), a.w, a.h);
    }
    if let Some((w, h)) = parent_size {
        positioner.send_set_parent_size(size_up(w, i.across()), size_up(h, i.down()));
    }
    call();
    if let Some(a) = anchor {
        positioner.send_set_anchor_rect(a.x, a.y, a.w, a.h);
    }
    if let Some((w, h)) = parent_size {
        positioner.send_set_parent_size(w, h);
    }
}

struct Toplevel {
    f: Rc<Frames>,
    window: Rc<RefCell<Window>>,
}

impl Toplevel {
    /// The frame of the window in a state `fullscreen` or not.
    fn insets(&self, fullscreen: bool) -> Insets {
        self.window
            .try_borrow_mut()
            .map_or(Insets::default(), |mut w| w.insets(&self.f, fullscreen))
    }

    /// The frame of the window now.
    fn current(&self) -> Insets {
        self.window
            .try_borrow_mut()
            .map_or(Insets::default(), |mut w| w.current(&self.f))
    }
}

/// Whether a configure's states (an array of u32) hold `state`.
/// `xdg_toplevel.state.activated` and `suspended`.
const ACTIVATED: u32 = 4;
const SUSPENDED: u32 = 9;

/// A configure's states as a window that always thinks it has the focus is
/// told them (3d): `activated` there, `suspended` not; the rest as they are.
pub(crate) fn always_activated(states: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = states
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|word| u32::from_ne_bytes(**word) != SUSPENDED)
        .flatten()
        .copied()
        .collect();
    if !has_state(&out, ACTIVATED) {
        out.extend_from_slice(&ACTIVATED.to_ne_bytes());
    }
    out
}

fn has_state(states: &[u8], state: u32) -> bool {
    states
        .as_chunks::<4>()
        .0
        .iter()
        .any(|word| u32::from_ne_bytes(*word) == state)
}

impl XdgToplevelHandler for Toplevel {
    /// The size less the frame of the state this configure asks for: in
    /// fullscreen the title strip takes no room (§5.7), so the program is
    /// told the output less the border only.
    fn handle_configure(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32, states: &[u8]) {
        let fullscreen = has_state(states, FULLSCREEN);
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.configured(fullscreen);
        }
        let i = self.insets(fullscreen);
        let focused;
        let states = if self.f.always_focused {
            focused = always_activated(states);
            &focused[..]
        } else {
            states
        };
        slf.send_configure(
            size_down(width, i.across()),
            size_down(height, i.down()),
            states,
        );
    }

    /// The bounds of a window that is not fullscreen.
    fn handle_configure_bounds(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        let i = self.insets(false);
        slf.send_configure_bounds(size_down(width, i.across()), size_down(height, i.down()));
    }

    fn handle_set_min_size(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        match self.window.try_borrow_mut() {
            Ok(mut window) if width >= 0 && height >= 0 => window.min = Some((width, height)),
            // A negative one is an error: the compositor's to raise, now.
            _ => slf.send_set_min_size(width, height),
        }
    }

    fn handle_set_max_size(&mut self, slf: &Rc<XdgToplevel>, width: i32, height: i32) {
        match self.window.try_borrow_mut() {
            Ok(mut window) if width >= 0 && height >= 0 => window.max = Some((width, height)),
            _ => slf.send_set_max_size(width, height),
        }
    }

    fn handle_show_window_menu(
        &mut self,
        slf: &Rc<XdgToplevel>,
        seat: &Rc<WlSeat>,
        serial: u32,
        x: i32,
        y: i32,
    ) {
        let i = self.current();
        slf.send_show_window_menu(seat, serial, point_up(x, i.border), point_up(y, i.top()));
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgToplevel>) {
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.close_menu();
        }
        slf.send_destroy();
        if let Ok(mut window) = self.window.try_borrow_mut() {
            window.drop_strips();
            window.toplevel = None;
        }
        slf.unset_handler();
    }
}

/// A positioner's state that is relative to the parent's geometry.
#[derive(Default)]
struct Positioner {
    anchor: Option<Rect>,
    parent_size: Option<(i32, i32)>,
}

impl XdgPositionerHandler for Positioner {
    fn handle_set_anchor_rect(
        &mut self,
        slf: &Rc<XdgPositioner>,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        slf.send_set_anchor_rect(x, y, width, height);
        self.anchor = Some(Rect {
            x,
            y,
            w: width,
            h: height,
        });
    }

    fn handle_set_parent_size(
        &mut self,
        slf: &Rc<XdgPositioner>,
        parent_width: i32,
        parent_height: i32,
    ) {
        slf.send_set_parent_size(parent_width, parent_height);
        self.parent_size = Some((parent_width, parent_height));
    }
}

/// A popup, with the frame of its parent when it was made (none when the
/// parent has none).
struct Popup {
    i: Insets,
}

impl XdgPopupHandler for Popup {
    fn handle_configure(&mut self, slf: &Rc<XdgPopup>, x: i32, y: i32, width: i32, height: i32) {
        slf.send_configure(
            point_down(x, self.i.border),
            point_down(y, self.i.top()),
            width,
            height,
        );
    }

    fn handle_reposition(
        &mut self,
        slf: &Rc<XdgPopup>,
        positioner: &Rc<XdgPositioner>,
        token: u32,
    ) {
        with_positioner_up(positioner, self.i, || {
            slf.send_reposition(positioner, token)
        });
    }

    fn handle_destroy(&mut self, slf: &Rc<XdgPopup>) {
        slf.send_destroy();
        slf.unset_handler();
    }
}

struct DragManager {
    f: Rc<Frames>,
}

impl XdgToplevelDragManagerV1Handler for DragManager {
    fn handle_get_xdg_toplevel_drag(
        &mut self,
        slf: &Rc<XdgToplevelDragManagerV1>,
        id: &Rc<XdgToplevelDragV1>,
        data_source: &Rc<WlDataSource>,
    ) {
        slf.send_get_xdg_toplevel_drag(id, data_source);
        id.set_handler(Drag { f: self.f.clone() });
    }
}

struct Drag {
    f: Rc<Frames>,
}

impl XdgToplevelDragV1Handler for Drag {
    fn handle_attach(
        &mut self,
        slf: &Rc<XdgToplevelDragV1>,
        toplevel: &Rc<XdgToplevel>,
        x_offset: i32,
        y_offset: i32,
    ) {
        let i = insets_of_toplevel(&self.f, toplevel);
        slf.send_attach(
            toplevel,
            point_up(x_offset, i.border),
            point_up(y_offset, i.top()),
        );
    }
}

// --- THE SIZE OF A BUFFER -----------------------------------------------------
// Only for a window without a geometry of its own: its root surface's size is
// its buffer's. Kept on the buffer as its handler, so it goes with it.

struct BufferSize {
    width: i32,
    height: i32,
}

impl WlBufferHandler for BufferSize {}

fn sized(buffer: &Rc<WlBuffer>, width: i32, height: i32) {
    buffer.set_handler(BufferSize { width, height });
}

struct Shm;

impl WlShmHandler for Shm {
    fn handle_create_pool(
        &mut self,
        slf: &Rc<WlShm>,
        id: &Rc<WlShmPool>,
        fd: &Rc<OwnedFd>,
        size: i32,
    ) {
        slf.send_create_pool(id, fd, size);
        id.set_handler(Pool);
    }
}

struct Pool;

impl WlShmPoolHandler for Pool {
    fn handle_create_buffer(
        &mut self,
        slf: &Rc<WlShmPool>,
        id: &Rc<WlBuffer>,
        offset: i32,
        width: i32,
        height: i32,
        stride: i32,
        format: WlShmFormat,
    ) {
        slf.send_create_buffer(id, offset, width, height, stride, format);
        sized(id, width, height);
    }
}

struct Dmabuf;

impl ZwpLinuxDmabufV1Handler for Dmabuf {
    fn handle_create_params(
        &mut self,
        slf: &Rc<ZwpLinuxDmabufV1>,
        params_id: &Rc<ZwpLinuxBufferParamsV1>,
    ) {
        slf.send_create_params(params_id);
        params_id.set_handler(Params::default());
    }
}

#[derive(Default)]
struct Params {
    size: Option<(i32, i32)>,
}

impl ZwpLinuxBufferParamsV1Handler for Params {
    fn handle_create(
        &mut self,
        slf: &Rc<ZwpLinuxBufferParamsV1>,
        width: i32,
        height: i32,
        format: u32,
        flags: ZwpLinuxBufferParamsV1Flags,
    ) {
        slf.send_create(width, height, format, flags);
        self.size = Some((width, height));
    }

    fn handle_created(&mut self, slf: &Rc<ZwpLinuxBufferParamsV1>, buffer: &Rc<WlBuffer>) {
        slf.send_created(buffer);
        if let Some((w, h)) = self.size {
            sized(buffer, w, h);
        }
    }

    fn handle_create_immed(
        &mut self,
        slf: &Rc<ZwpLinuxBufferParamsV1>,
        buffer_id: &Rc<WlBuffer>,
        width: i32,
        height: i32,
        format: u32,
        flags: ZwpLinuxBufferParamsV1Flags,
    ) {
        slf.send_create_immed(buffer_id, width, height, format, flags);
        sized(buffer_id, width, height);
    }
}

struct Drm;

impl WlDrmHandler for Drm {
    fn handle_create_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: u32,
        width: i32,
        height: i32,
        stride: u32,
        format: u32,
    ) {
        slf.send_create_buffer(id, name, width, height, stride, format);
        sized(id, width, height);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_create_planar_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: u32,
        width: i32,
        height: i32,
        format: u32,
        offset0: i32,
        stride0: i32,
        offset1: i32,
        stride1: i32,
        offset2: i32,
        stride2: i32,
    ) {
        slf.send_create_planar_buffer(
            id, name, width, height, format, offset0, stride0, offset1, stride1, offset2, stride2,
        );
        sized(id, width, height);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_create_prime_buffer(
        &mut self,
        slf: &Rc<WlDrm>,
        id: &Rc<WlBuffer>,
        name: &Rc<OwnedFd>,
        width: i32,
        height: i32,
        format: u32,
        offset0: i32,
        stride0: i32,
        offset1: i32,
        stride1: i32,
        offset2: i32,
        stride2: i32,
    ) {
        slf.send_create_prime_buffer(
            id, name, width, height, format, offset0, stride0, offset1, stride1, offset2, stride2,
        );
        sized(id, width, height);
    }
}

struct SinglePixel;

impl WpSinglePixelBufferManagerV1Handler for SinglePixel {
    fn handle_create_u32_rgba_buffer(
        &mut self,
        slf: &Rc<WpSinglePixelBufferManagerV1>,
        id: &Rc<WlBuffer>,
        r: u32,
        g: u32,
        b: u32,
        a: u32,
    ) {
        slf.send_create_u32_rgba_buffer(id, r, g, b, a);
        sized(id, 1, 1);
    }
}

struct Viewporter;

impl WpViewporterHandler for Viewporter {
    fn handle_get_viewport(
        &mut self,
        slf: &Rc<WpViewporter>,
        id: &Rc<WpViewport>,
        surface: &Rc<WlSurface>,
    ) {
        slf.send_get_viewport(id, surface);
        id.set_handler(Viewport {
            surface: Rc::downgrade(surface),
        });
    }
}

/// The program's viewport on one of its surfaces: part of the surface's size.
struct Viewport {
    surface: Weak<WlSurface>,
}

impl Viewport {
    fn pending(&self, f: impl FnOnce(&mut Pending)) {
        if let Some(surface) = self.surface.upgrade() {
            if let Ok(mut h) = surface.try_get_handler_mut::<Surface>() {
                f(&mut h.pending);
            }
        }
    }
}

impl WpViewportHandler for Viewport {
    fn handle_set_destination(&mut self, slf: &Rc<WpViewport>, width: i32, height: i32) {
        slf.send_set_destination(width, height);
        let destination = (width > 0 && height > 0).then_some((width, height));
        self.pending(|p| p.destination = Some(destination));
    }

    fn handle_set_source(
        &mut self,
        slf: &Rc<WpViewport>,
        x: Fixed,
        y: Fixed,
        width: Fixed,
        height: Fixed,
    ) {
        slf.send_set_source(x, y, width, height);
        let (w, h) = (width.to_f64(), height.to_f64());
        let source = (w > 0.0 && h > 0.0).then(|| (w.ceil() as i32, h.ceil() as i32));
        self.pending(|p| p.source = Some(source));
    }

    fn handle_destroy(&mut self, slf: &Rc<WpViewport>) {
        slf.send_destroy();
        self.pending(|p| {
            p.destination = Some(None);
            p.source = Some(None);
        });
        slf.unset_handler();
    }
}

// --- INPUT ON THE BORDER --------------------------------------------------------

/// The left pointer button (`linux/input-event-codes.h`): the one the frame
/// acts on.
const BTN_LEFT: u32 = 0x110;

struct Seat {
    f: Rc<Frames>,
}

impl WlSeatHandler for Seat {
    fn handle_get_pointer(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlPointer>) {
        slf.send_get_pointer(id);
        id.set_handler(Pointer::new(self.f.clone(), slf));
    }

    fn handle_get_touch(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlTouch>) {
        slf.send_get_touch(id);
        id.set_handler(Touch::default());
    }

    fn handle_get_keyboard(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlKeyboard>) {
        slf.send_get_keyboard(id);
        id.set_handler(Keyboard {
            f: self.f.clone(),
            menu: false,
            down: Vec::new(),
            locked: (0, 0),
            held: None,
        });
    }
}

/// The program's pointer. While the pointer is over a strip (`away`), every
/// event of it is dropped; a `frame` is passed only when something of its
/// group was — leaving the program's surface for a strip is a `leave` and a
/// `frame` to the program, and nothing after.
///
/// It is also the frame's own pointer: the compositor sends a client's
/// pointer events to every `wl_pointer` of it, so the proxy sees the
/// pointer over the program's windows and over its own strips on the
/// program's pointer. Over the program's surface near the top it brings a
/// hover title out (§0а, [`hover_at`]); over the frame it sets the cursor
/// (§5.5), lights the button under it, and a click of its left button moves
/// or resizes the window or presses a button (§5.11) — only events the
/// compositor sent, on surfaces the program cannot name. (A program that
/// binds no pointer has none of this: the proxy's own `wl_seat` and
/// `wl_pointer`, which would have it, are not made.)
struct Pointer {
    f: Rc<Frames>,
    /// The seat the program made it of: what a move or a resize names.
    seat: Weak<WlSeat>,
    away: bool,
    sent: bool,
    /// The window whose root surface the pointer is on.
    on: Option<Weak<RefCell<Window>>>,
    /// The window the pointer left in this frame: its hover strip goes in
    /// unless the pointer is back on it by the frame's end.
    leaving: Option<Weak<RefCell<Window>>>,
    /// The part of a frame the pointer is over, and where.
    over: Option<Over>,
    /// The serial of the pointer's last enter: the cursor is set with it.
    entered: u32,
    /// The proxy's cursor-shape device for this pointer, made when first
    /// needed, and the shape it set since the last enter.
    shape: Option<Rc<WpCursorShapeDeviceV1>>,
    cursor: Option<WpCursorShapeDeviceV1Shape>,
    /// The program's surface a leave of it was held back from, and that
    /// leave's serial (3d, `Frames::always_focused`): the program's pointer
    /// stays where it was. Passed on before the next enter.
    held: Option<(u32, Weak<WlSurface>)>,
    /// The buttons down on the program's surfaces: let go of before a leave
    /// is held back, or they would stay down.
    down: Vec<u32>,
}

/// Where on a frame the pointer is: the window, its part, and the point on
/// the part's surface.
struct Over {
    window: Weak<RefCell<Window>>,
    part: Part,
    x: f64,
    y: f64,
}

/// Where on a window the pointer is.
#[derive(PartialEq, Eq)]
enum Spot {
    /// The program's root surface.
    Root,
    /// The top strip of the border, or the title strip and what is on it.
    Top,
    /// Another strip of the border.
    Side,
}

/// The window `surface` belongs to, and where on it: the program's root
/// surface of a window, or a surface of the proxy's.
fn spot(surface: &Rc<WlSurface>) -> Option<(Rc<RefCell<Window>>, Spot)> {
    if let Ok(own) = surface.try_get_handler_ref::<Mine>() {
        let spot = match own.part {
            Part::Border(Side::Top, _) => Spot::Top,
            Part::Border(..) => Spot::Side,
            // The dropdown hangs from the title: a hover strip stays out
            // while the pointer is on it.
            Part::Title | Part::Text | Part::Buttons | Part::Menu => Spot::Top,
            // Never entered (no input region): as a side, it changes
            // nothing of a hover strip.
            Part::Corner => Spot::Side,
        };
        return own.window.upgrade().map(|w| (w, spot));
    }
    let h = surface.try_get_handler_ref::<Surface>().ok()?;
    h.window.clone().map(|w| (w, Spot::Root))
}

fn set_hover(window: &Rc<RefCell<Window>>, on: bool) {
    if let Ok(mut window) = window.try_borrow_mut() {
        window.set_hover(on);
    }
}

impl Pointer {
    fn new(f: Rc<Frames>, seat: &Rc<WlSeat>) -> Self {
        Self {
            f,
            seat: Rc::downgrade(seat),
            away: false,
            sent: false,
            on: None,
            leaving: None,
            over: None,
            entered: 0,
            shape: None,
            cursor: None,
            held: None,
            down: Vec::new(),
        }
    }

    fn pass(&mut self, send: impl FnOnce()) {
        if !self.away {
            send();
            self.sent = true;
        }
    }

    /// The pointer came onto `surface` at `y`.
    fn hover_enter(&mut self, surface: &Rc<WlSurface>, y: Fixed) {
        let target = spot(surface);
        let want = match &target {
            Some((_, Spot::Top)) => Some(true),
            Some((_, Spot::Side)) => Some(false),
            Some((window, Spot::Root)) => window
                .try_borrow()
                .ok()
                .and_then(|w| w.area())
                .and_then(|g| hover_at(g, y.to_f64())),
            None => None,
        };
        if let Some(left) = self.leaving.take().and_then(|w| w.upgrade()) {
            let back = target.as_ref().is_some_and(|(w, _)| Rc::ptr_eq(w, &left));
            if !back || want == Some(false) {
                set_hover(&left, false);
            }
        }
        if let (Some((window, _)), Some(on)) = (&target, want) {
            set_hover(window, on);
        }
        self.on = match target {
            Some((window, Spot::Root)) => Some(Rc::downgrade(&window)),
            _ => None,
        };
    }

    /// The pointer left `surface`: its window's hover strip goes in at the
    /// end of the frame, unless the pointer is back on the window by then —
    /// at once for a pointer without frames (before `wl_pointer` v5).
    fn hover_leave(&mut self, slf: &Rc<WlPointer>, surface: &Rc<WlSurface>) {
        self.on = None;
        if let Some((window, spot)) = spot(surface) {
            if spot == Spot::Side {
                return;
            }
            if slf.version() >= 5 {
                self.leaving = Some(Rc::downgrade(&window));
            } else {
                set_hover(&window, false);
            }
        }
    }

    /// The end of a frame: a window left and not come back to.
    fn hover_frame(&mut self) {
        if let Some(left) = self.leaving.take().and_then(|w| w.upgrade()) {
            set_hover(&left, false);
        }
    }

    /// The pointer moved on the program's root surface to `y`.
    fn hover_motion(&mut self, y: Fixed) {
        let Some(window) = self.on.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        let want = window
            .try_borrow()
            .ok()
            .and_then(|w| w.area())
            .and_then(|g| hover_at(g, y.to_f64()));
        if let Some(on) = want {
            set_hover(&window, on);
        }
    }

    /// The pointer came onto a part of a frame, or moved on it: the cursor
    /// for what is under it, and the button under it lit (the others not).
    fn over_frame(&mut self, slf: &Rc<WlPointer>) {
        let Some(over) = &self.over else {
            return;
        };
        let Some(window) = over.window.upgrade() else {
            return;
        };
        if over.part == Part::Menu {
            let y = over.y;
            self.set_cursor(slf, WpCursorShapeDeviceV1Shape::DEFAULT);
            if let Ok(mut window) = window.try_borrow_mut() {
                window.menu_hover(Some(y));
            };
            return;
        }
        let hit = window
            .try_borrow()
            .map_or(Hit::Nothing, |w| w.hit(over.part, over.x, over.y));
        self.set_cursor(slf, cursor_for(hit));
        let under = match hit {
            Hit::Button(button) => Some(button),
            _ => None,
        };
        light_under(&window, under, false);
    }

    /// The pointer left the frame it was over: nothing of it is lit, and a
    /// button pressed and not let go of is let go (the release will not
    /// come here).
    fn off_frame(&mut self) {
        let Some(over) = self.over.take() else {
            return;
        };
        let Some(window) = over.window.upgrade() else {
            return;
        };
        if over.part == Part::Menu {
            if let Ok(mut window) = window.try_borrow_mut() {
                window.menu_hover(None);
            };
        } else {
            light_under(&window, None, true);
        }
    }

    /// The cursor over the frame, with the serial of the enter onto it:
    /// the compositor takes a shape only with the latest enter's serial, and
    /// the program, which was not told of this enter, has none to set
    /// another. Without `wp_cursor_shape_v1` the cursor stays what it was.
    fn set_cursor(&mut self, slf: &Rc<WlPointer>, shape: WpCursorShapeDeviceV1Shape) {
        if self.cursor == Some(shape) {
            return;
        }
        if self.shape.is_none() {
            let manager = self.f.own.borrow().cursor_shape.clone();
            let Some(manager) = manager else {
                return;
            };
            let device = manager.new_send_get_pointer(slf);
            quiet(&*device);
            self.shape = Some(device);
        }
        if let Some(device) = &self.shape {
            device.send_set_shape(self.entered, shape);
            self.cursor = Some(shape);
        }
    }

    /// A button of the pointer over the frame (§5.11): the left one acts,
    /// once for all the program's pointers ([`Frames::first`]).
    fn frame_button(&mut self, serial: u32, button: u32, state: WlPointerButtonState) {
        if button != BTN_LEFT {
            return;
        }
        let Some(over) = &self.over else {
            return;
        };
        let Some(window) = over.window.upgrade() else {
            return;
        };
        if !self.f.first(serial) {
            return;
        }
        let (part, x, y) = (over.part, over.x, over.y);
        // A row of the dropdown acts on the release over it.
        if part == Part::Menu {
            if state == WlPointerButtonState::RELEASED {
                if let Ok(mut window) = window.try_borrow_mut() {
                    window.menu_click(&self.f, y);
                }
            }
            return;
        }
        let seat = self.seat.upgrade();
        let down = state == WlPointerButtonState::PRESSED;
        click(&window, &self.f, (part, x, y), down, seat.as_ref(), serial);
    }
}

/// The button under the pointer lit on `window` (none: nothing lit), and
/// the one pressed let go of when `let_go`.
fn light_under(window: &Rc<RefCell<Window>>, under: Option<Button>, let_go: bool) {
    if let Ok(mut window) = window.try_borrow_mut() {
        if let_go {
            window.pressed = None;
        }
        window.hover_button(under);
    }
}

/// The left pointer button down or up at `at` (a part of `window`'s frame
/// and a point on it): [`Window::click`] with what is there.
fn click(
    window: &Rc<RefCell<Window>>,
    f: &Frames,
    at: (Part, f64, f64),
    down: bool,
    seat: Option<&Rc<WlSeat>>,
    serial: u32,
) {
    if let Ok(mut window) = window.try_borrow_mut() {
        let hit = window.hit(at.0, at.1, at.2);
        window.click(f, hit, down, seat, serial);
    }
}

impl WlPointerHandler for Pointer {
    fn handle_enter(
        &mut self,
        slf: &Rc<WlPointer>,
        serial: u32,
        surface: &Rc<WlSurface>,
        surface_x: Fixed,
        surface_y: Fixed,
    ) {
        self.hover_enter(surface, surface_y);
        // Back on the program: the leave held back goes first (3d).
        if programs(surface) {
            if let Some((held, gone)) = self.held.take() {
                if let Some(gone) = gone.upgrade().filter(programs) {
                    slf.send_leave(held, &gone);
                    self.sent = true;
                }
            }
        }
        self.away = !programs(surface);
        self.entered = serial;
        self.cursor = None;
        self.off_frame();
        self.over = surface.try_get_handler_ref::<Mine>().ok().map(|own| Over {
            window: own.window.clone(),
            part: own.part,
            x: surface_x.to_f64(),
            y: surface_y.to_f64(),
        });
        self.over_frame(slf);
        self.pass(|| slf.send_enter(serial, surface, surface_x, surface_y));
    }

    fn handle_leave(&mut self, slf: &Rc<WlPointer>, serial: u32, surface: &Rc<WlSurface>) {
        self.hover_leave(slf, surface);
        self.off_frame();
        if programs(surface) {
            self.away = false;
            if self.f.always_focused {
                // The program's pointer stays where it was (3d): what is
                // down is let go of, and the leave waits for the next enter.
                for button in std::mem::take(&mut self.down) {
                    self.pass(|| {
                        slf.send_button(serial, 0, button, WlPointerButtonState::RELEASED)
                    });
                }
                self.held = Some((serial, Rc::downgrade(surface)));
            } else {
                self.pass(|| slf.send_leave(serial, surface));
            }
        } else {
            self.away = false;
        }
    }

    fn handle_motion(
        &mut self,
        slf: &Rc<WlPointer>,
        time: u32,
        surface_x: Fixed,
        surface_y: Fixed,
    ) {
        self.hover_motion(surface_y);
        if let Some(over) = &mut self.over {
            over.x = surface_x.to_f64();
            over.y = surface_y.to_f64();
            self.over_frame(slf);
        }
        self.pass(|| slf.send_motion(time, surface_x, surface_y));
    }

    fn handle_button(
        &mut self,
        slf: &Rc<WlPointer>,
        serial: u32,
        time: u32,
        button: u32,
        state: WlPointerButtonState,
    ) {
        self.frame_button(serial, button, state);
        if !self.away {
            if state == WlPointerButtonState::PRESSED {
                if !self.down.contains(&button) && self.down.len() < 32 {
                    self.down.push(button);
                }
            } else {
                self.down.retain(|b| *b != button);
            }
        }
        self.pass(|| slf.send_button(serial, time, button, state));
    }

    fn handle_axis(&mut self, slf: &Rc<WlPointer>, time: u32, axis: WlPointerAxis, value: Fixed) {
        self.pass(|| slf.send_axis(time, axis, value));
    }

    fn handle_frame(&mut self, slf: &Rc<WlPointer>) {
        self.hover_frame();
        if std::mem::take(&mut self.sent) {
            slf.send_frame();
        }
    }

    fn handle_axis_source(&mut self, slf: &Rc<WlPointer>, axis_source: WlPointerAxisSource) {
        self.pass(|| slf.send_axis_source(axis_source));
    }

    fn handle_axis_stop(&mut self, slf: &Rc<WlPointer>, time: u32, axis: WlPointerAxis) {
        self.pass(|| slf.send_axis_stop(time, axis));
    }

    fn handle_axis_discrete(&mut self, slf: &Rc<WlPointer>, axis: WlPointerAxis, discrete: i32) {
        self.pass(|| slf.send_axis_discrete(axis, discrete));
    }

    fn handle_axis_value120(&mut self, slf: &Rc<WlPointer>, axis: WlPointerAxis, value120: i32) {
        self.pass(|| slf.send_axis_value120(axis, value120));
    }

    fn handle_axis_relative_direction(
        &mut self,
        slf: &Rc<WlPointer>,
        axis: WlPointerAxis,
        direction: WlPointerAxisRelativeDirection,
    ) {
        self.pass(|| slf.send_axis_relative_direction(axis, direction));
    }

    fn handle_warp(&mut self, slf: &Rc<WlPointer>, surface_x: Fixed, surface_y: Fixed) {
        self.pass(|| slf.send_warp(surface_x, surface_y));
    }

    /// The program lets its pointer go: the proxy's cursor-shape device of
    /// it goes first.
    fn handle_release(&mut self, slf: &Rc<WlPointer>) {
        if let Some(device) = self.shape.take() {
            device.send_destroy();
        }
        slf.send_release();
    }
}

/// The program's touch: a touch point that went down on a strip is dropped
/// until it goes up; a `frame` passes when something of its group did.
#[derive(Default)]
struct Touch {
    away: HashSet<i32>,
    sent: bool,
}

impl Touch {
    fn pass(&mut self, id: i32, send: impl FnOnce()) {
        if !self.away.contains(&id) {
            send();
            self.sent = true;
        }
    }
}

impl WlTouchHandler for Touch {
    fn handle_down(
        &mut self,
        slf: &Rc<WlTouch>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        id: i32,
        x: Fixed,
        y: Fixed,
    ) {
        if programs(surface) {
            self.away.remove(&id);
            self.pass(id, || slf.send_down(serial, time, surface, id, x, y));
        } else {
            self.away.insert(id);
        }
    }

    fn handle_up(&mut self, slf: &Rc<WlTouch>, serial: u32, time: u32, id: i32) {
        self.pass(id, || slf.send_up(serial, time, id));
        self.away.remove(&id);
    }

    fn handle_motion(&mut self, slf: &Rc<WlTouch>, time: u32, id: i32, x: Fixed, y: Fixed) {
        self.pass(id, || slf.send_motion(time, id, x, y));
    }

    fn handle_shape(&mut self, slf: &Rc<WlTouch>, id: i32, major: Fixed, minor: Fixed) {
        self.pass(id, || slf.send_shape(id, major, minor));
    }

    fn handle_orientation(&mut self, slf: &Rc<WlTouch>, id: i32, orientation: Fixed) {
        self.pass(id, || slf.send_orientation(id, orientation));
    }

    fn handle_frame(&mut self, slf: &Rc<WlTouch>) {
        if std::mem::take(&mut self.sent) {
            slf.send_frame();
        }
    }

    fn handle_cancel(&mut self, slf: &Rc<WlTouch>) {
        // Every touch point is over; the program's are its news.
        self.away.clear();
        self.sent = false;
        slf.send_cancel();
    }
}

struct Gestures;

impl ZwpPointerGesturesV1Handler for Gestures {
    fn handle_get_swipe_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGestureSwipeV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_swipe_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }

    fn handle_get_pinch_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGesturePinchV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_pinch_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }

    fn handle_get_hold_gesture(
        &mut self,
        slf: &Rc<ZwpPointerGesturesV1>,
        id: &Rc<ZwpPointerGestureHoldV1>,
        pointer: &Rc<WlPointer>,
    ) {
        slf.send_get_hold_gesture(id, pointer);
        id.set_handler(Gesture::default());
    }
}

/// A gesture begun on a strip is dropped to its end.
#[derive(Default)]
struct Gesture {
    away: bool,
}

impl ZwpPointerGestureSwipeV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_update(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        time: u32,
        dx: Fixed,
        dy: Fixed,
    ) {
        if !self.away {
            slf.send_update(time, dx, dy);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGestureSwipeV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

impl ZwpPointerGesturePinchV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_update(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        time: u32,
        dx: Fixed,
        dy: Fixed,
        scale: Fixed,
        rotation: Fixed,
    ) {
        if !self.away {
            slf.send_update(time, dx, dy, scale, rotation);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGesturePinchV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

impl ZwpPointerGestureHoldV1Handler for Gesture {
    fn handle_begin(
        &mut self,
        slf: &Rc<ZwpPointerGestureHoldV1>,
        serial: u32,
        time: u32,
        surface: &Rc<WlSurface>,
        fingers: u32,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_begin(serial, time, surface, fingers);
        }
    }

    fn handle_end(
        &mut self,
        slf: &Rc<ZwpPointerGestureHoldV1>,
        serial: u32,
        time: u32,
        cancelled: i32,
    ) {
        if !std::mem::take(&mut self.away) {
            slf.send_end(serial, time, cancelled);
        }
    }
}

struct TabletManager;

impl ZwpTabletManagerV2Handler for TabletManager {
    fn handle_get_tablet_seat(
        &mut self,
        slf: &Rc<ZwpTabletManagerV2>,
        tablet_seat: &Rc<ZwpTabletSeatV2>,
        seat: &Rc<WlSeat>,
    ) {
        slf.send_get_tablet_seat(tablet_seat, seat);
        tablet_seat.set_handler(TabletSeat);
    }
}

struct TabletSeat;

impl ZwpTabletSeatV2Handler for TabletSeat {
    fn handle_tool_added(&mut self, slf: &Rc<ZwpTabletSeatV2>, id: &Rc<ZwpTabletToolV2>) {
        slf.send_tool_added(id);
        id.set_handler(Tool::default());
    }
}

/// A tablet tool near a strip: everything of it is dropped until it leaves,
/// a `frame` passes when something of its group did.
#[derive(Default)]
struct Tool {
    away: bool,
    sent: bool,
}

impl Tool {
    fn pass(&mut self, send: impl FnOnce()) {
        if !self.away {
            send();
            self.sent = true;
        }
    }
}

impl ZwpTabletToolV2Handler for Tool {
    fn handle_proximity_in(
        &mut self,
        slf: &Rc<ZwpTabletToolV2>,
        serial: u32,
        tablet: &Rc<ZwpTabletV2>,
        surface: &Rc<WlSurface>,
    ) {
        self.away = !programs(surface);
        self.pass(|| slf.send_proximity_in(serial, tablet, surface));
    }

    fn handle_proximity_out(&mut self, slf: &Rc<ZwpTabletToolV2>) {
        self.pass(|| slf.send_proximity_out());
        self.away = false;
    }

    fn handle_down(&mut self, slf: &Rc<ZwpTabletToolV2>, serial: u32) {
        self.pass(|| slf.send_down(serial));
    }

    fn handle_up(&mut self, slf: &Rc<ZwpTabletToolV2>) {
        self.pass(|| slf.send_up());
    }

    fn handle_motion(&mut self, slf: &Rc<ZwpTabletToolV2>, x: Fixed, y: Fixed) {
        self.pass(|| slf.send_motion(x, y));
    }

    fn handle_pressure(&mut self, slf: &Rc<ZwpTabletToolV2>, pressure: u32) {
        self.pass(|| slf.send_pressure(pressure));
    }

    fn handle_distance(&mut self, slf: &Rc<ZwpTabletToolV2>, distance: u32) {
        self.pass(|| slf.send_distance(distance));
    }

    fn handle_tilt(&mut self, slf: &Rc<ZwpTabletToolV2>, tilt_x: Fixed, tilt_y: Fixed) {
        self.pass(|| slf.send_tilt(tilt_x, tilt_y));
    }

    fn handle_rotation(&mut self, slf: &Rc<ZwpTabletToolV2>, degrees: Fixed) {
        self.pass(|| slf.send_rotation(degrees));
    }

    fn handle_slider(&mut self, slf: &Rc<ZwpTabletToolV2>, position: i32) {
        self.pass(|| slf.send_slider(position));
    }

    fn handle_wheel(&mut self, slf: &Rc<ZwpTabletToolV2>, degrees: Fixed, clicks: i32) {
        self.pass(|| slf.send_wheel(degrees, clicks));
    }

    fn handle_button(
        &mut self,
        slf: &Rc<ZwpTabletToolV2>,
        serial: u32,
        button: u32,
        state: ZwpTabletToolV2ButtonState,
    ) {
        self.pass(|| slf.send_button(serial, button, state));
    }

    fn handle_frame(&mut self, slf: &Rc<ZwpTabletToolV2>, time: u32) {
        if std::mem::take(&mut self.sent) {
            slf.send_frame(time);
        }
    }
}

struct DataDeviceManager;

impl WlDataDeviceManagerHandler for DataDeviceManager {
    fn handle_get_data_device(
        &mut self,
        slf: &Rc<WlDataDeviceManager>,
        id: &Rc<WlDataDevice>,
        seat: &Rc<WlSeat>,
    ) {
        slf.send_get_data_device(id, seat);
        id.set_handler(DataDevice::default());
    }
}

/// A drag over a strip is not over the program: its enter, motion, leave and
/// drop are dropped. (The offer announced before the enter has already gone
/// to the program; unused, it is harmless.)
#[derive(Default)]
struct DataDevice {
    away: bool,
}

impl WlDataDeviceHandler for DataDevice {
    fn handle_enter(
        &mut self,
        slf: &Rc<WlDataDevice>,
        serial: u32,
        surface: &Rc<WlSurface>,
        x: Fixed,
        y: Fixed,
        id: Option<&Rc<WlDataOffer>>,
    ) {
        self.away = !programs(surface);
        if !self.away {
            slf.send_enter(serial, surface, x, y, id);
        }
    }

    fn handle_leave(&mut self, slf: &Rc<WlDataDevice>) {
        if !std::mem::take(&mut self.away) {
            slf.send_leave();
        }
    }

    fn handle_motion(&mut self, slf: &Rc<WlDataDevice>, time: u32, x: Fixed, y: Fixed) {
        if !self.away {
            slf.send_motion(time, x, y);
        }
    }

    fn handle_drop(&mut self, slf: &Rc<WlDataDevice>) {
        if !std::mem::take(&mut self.away) {
            slf.send_drop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wl_title::LOOK;

    const R: Rect = Rect {
        x: 26,
        y: 23,
        w: 640,
        h: 480,
    };

    /// The border alone, 4 wide.
    const B: Insets = Insets {
        border: 4,
        title: 0,
    };
    /// The border and the title strip under it.
    const BT: Insets = Insets {
        border: 4,
        title: TITLE_HEIGHT,
    };

    #[test]
    fn the_geometry_grows_by_the_frame() {
        assert_eq!(
            geometry_up(R, B),
            Rect {
                x: 22,
                y: 19,
                w: 648,
                h: 488
            }
        );
        // The title strip is taken at the top only.
        assert_eq!(
            geometry_up(R, BT),
            Rect {
                x: 22,
                y: 23 - 4 - TITLE_HEIGHT,
                w: 648,
                h: 488 + TITLE_HEIGHT
            }
        );
        assert_eq!(geometry_up(R, Insets::default()), R, "no frame, no change");
        // Nonsense stays nonsense instead of wrapping.
        let edge = Rect {
            x: i32::MIN,
            y: 0,
            w: i32::MAX,
            h: 1,
        };
        let up = geometry_up(edge, BT);
        assert_eq!((up.x, up.w), (i32::MIN, i32::MAX));
        assert_eq!((B.top(), B.across(), B.down()), (4, 8, 8));
        assert_eq!(
            (BT.top(), BT.across(), BT.down()),
            (4 + TITLE_HEIGHT, 8, 8 + TITLE_HEIGHT)
        );
    }

    #[test]
    fn configure_takes_the_frame_off_and_leaves_zero_alone() {
        assert_eq!(size_down(800, 8), 792);
        assert_eq!(size_down(0, 8), 0, "0 is \"you decide\"");
        assert_eq!(size_down(8, 8), 1, "never 0 by subtraction");
        assert_eq!(size_down(5, 8), 1);
        assert_eq!(size_down(800, 0), 800);
        assert_eq!(
            size_down(-1, 8),
            -1,
            "the compositor's nonsense is passed on"
        );
        // Limits go the other way; 0 is "no limit".
        assert_eq!(size_up(300, 8), 308);
        assert_eq!(size_up(0, 8), 0);
        assert_eq!(size_up(i32::MAX, 8), i32::MAX);
        assert_eq!((point_up(10, 4), point_down(10, 4)), (14, 6));
        assert_eq!((point_up(10, 0), point_down(10, 0)), (10, 10));
    }

    /// What a compositor sizes is what it gets: the program, told the size
    /// left inside the frame, sets a geometry of that size; grown by the
    /// frame it is the compositor's size again, and the border's strips and
    /// the title strip fill exactly the band between.
    #[test]
    fn a_configured_window_is_exactly_the_size_the_compositor_asked_for() {
        for b in [1, 4, 7, 32] {
            for title in [0, TITLE_HEIGHT] {
                let i = Insets { border: b, title };
                for (w, h) in [(800, 600), (1920, 1080), (2 * b + 1, 2 * b + title + 1)] {
                    let program = Rect {
                        x: 10,
                        y: 20,
                        w: size_down(w, i.across()),
                        h: size_down(h, i.down()),
                    };
                    let up = geometry_up(program, i);
                    assert_eq!((up.w, up.h), (w, h), "{i:?}");
                    let mut parts = strips(program, i).to_vec();
                    parts.extend(title_strip(program, i, false));
                    assert_eq!(parts.len(), if title > 0 { 5 } else { 4 });
                    // They tile the band: their area is the difference.
                    let area: i64 = parts.iter().map(|r| r.w as i64 * r.h as i64).sum();
                    assert_eq!(
                        area,
                        w as i64 * h as i64 - program.w as i64 * program.h as i64,
                        "{i:?}"
                    );
                    // And every part is inside the compositor's geometry,
                    // none inside the program's, none over another.
                    let overlap = |a: &Rect, r: &Rect| {
                        a.x < r.x + r.w && a.x + a.w > r.x && a.y < r.y + r.h && a.y + a.h > r.y
                    };
                    for (n, r) in parts.iter().enumerate() {
                        assert!(r.x >= up.x && r.y >= up.y, "{r:?}");
                        assert!(
                            r.x + r.w <= up.x + up.w && r.y + r.h <= up.y + up.h,
                            "{r:?}"
                        );
                        assert!(!overlap(r, &program), "{r:?} overlaps the program");
                        for other in &parts[n + 1..] {
                            assert!(!overlap(r, other), "{r:?} overlaps {other:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_strips_are_where_the_border_is() {
        let [top, bottom, left, right] = strips(R, B);
        assert_eq!(
            top,
            Rect {
                x: 22,
                y: 19,
                w: 648,
                h: 4
            }
        );
        assert_eq!(
            bottom,
            Rect {
                x: 22,
                y: 503,
                w: 648,
                h: 4
            }
        );
        assert_eq!(
            left,
            Rect {
                x: 22,
                y: 23,
                w: 4,
                h: 480
            }
        );
        assert_eq!(
            right,
            Rect {
                x: 666,
                y: 23,
                w: 4,
                h: 480
            }
        );
        assert_eq!(title_strip(R, B, false), None, "no strip, no room");
    }

    /// The title strip: under the top border, between the side strips, the
    /// program's width; or, hovering, over the top of the program's content.
    #[test]
    fn the_title_strip_is_under_the_top_border_or_over_the_content() {
        let [top, _, left, right] = strips(R, BT);
        let strip = title_strip(R, BT, false).unwrap();
        assert_eq!(
            strip,
            Rect {
                x: 26,
                y: 23 - TITLE_HEIGHT,
                w: 640,
                h: TITLE_HEIGHT
            }
        );
        assert_eq!(top.y + top.h, strip.y, "right under the top border");
        assert_eq!(strip.y + strip.h, R.y, "right above the program");
        assert_eq!((left.x + left.w, right.x), (strip.x, strip.x + strip.w));
        assert_eq!((left.y, left.h), (strip.y, R.h + TITLE_HEIGHT));
        // Hovering, it takes no room: over the program, never taller.
        assert_eq!(
            title_strip(R, B, true),
            Some(Rect {
                x: 26,
                y: 23,
                w: 640,
                h: TITLE_HEIGHT
            })
        );
        let low = Rect { h: 5, ..R };
        assert_eq!(title_strip(low, B, true).unwrap().h, 5);
        assert_eq!(
            title_strip(R, Insets::default(), true),
            None,
            "no frame, no strip"
        );
    }

    /// The text: the whole line after the pad when it fits, else what fits
    /// with the pad at both ends; the viewport cuts the same share of its
    /// buffer, at any scale.
    #[test]
    fn the_text_is_cut_to_the_strip() {
        assert_eq!(text_shown(640, 120), 120);
        assert_eq!(text_shown(100, 120), 100 - 2 * TITLE_PAD);
        assert_eq!(text_shown(2 * TITLE_PAD, 120), 0);
        assert_eq!(text_shown(3, 120), 0);
        assert_eq!(text_shown(640, 0), 0);
        // The whole line: the whole buffer.
        assert_eq!(source_width(120, 120, 180), 180);
        // Half of it at 1.5: half of the buffer, rounded.
        assert_eq!(source_width(60, 120, 180), 90);
        assert_eq!(source_width(61, 120, 180), 92);
        assert_eq!(source_width(0, 120, 180), 0);
        assert_eq!(source_width(500, 120, 180), 180, "never past the buffer");
        assert_eq!(source_width(10, 0, 0), 0);
    }

    /// A hover strip comes out at the very top of the window, and goes in
    /// when the pointer is below where it would be.
    #[test]
    fn the_pointer_at_the_top_brings_the_hover_strip_out() {
        let g = R;
        let top = f64::from(g.y);
        assert_eq!(hover_at(g, top), Some(true));
        assert_eq!(hover_at(g, top + f64::from(HOVER_EDGE) - 0.5), Some(true));
        assert_eq!(hover_at(g, top - 3.0), Some(true), "a CSD shadow above");
        assert_eq!(hover_at(g, top + f64::from(HOVER_EDGE)), None);
        assert_eq!(hover_at(g, top + f64::from(TITLE_HEIGHT) - 1.0), None);
        assert_eq!(hover_at(g, top + f64::from(TITLE_HEIGHT)), Some(false));
        assert_eq!(hover_at(g, top + 300.0), Some(false));
    }

    #[test]
    fn a_configure_says_fullscreen_by_its_states() {
        let states: Vec<u8> = [1u32, 4, FULLSCREEN]
            .iter()
            .flat_map(|s| s.to_ne_bytes())
            .collect();
        assert!(has_state(&states, FULLSCREEN));
        assert!(!has_state(&states[..8], FULLSCREEN));
        assert!(!has_state(&[], FULLSCREEN));
        // A torn word is not a state.
        assert!(!has_state(&states[..11], FULLSCREEN));
    }

    #[test]
    fn a_surface_without_geometry_is_its_buffer_scaled_turned_or_viewported() {
        let mut c = Committed::default();
        assert_eq!(surface_size(&c), None, "no buffer, no size");
        c.buffer = Some((1200, 800));
        assert_eq!(surface_size(&c), Some((1200, 800)));
        c.scale = 2;
        assert_eq!(surface_size(&c), Some((600, 400)));
        c.transform = 1; // 90°
        assert_eq!(surface_size(&c), Some((400, 600)));
        c.transform = 6; // flipped 180°
        assert_eq!(surface_size(&c), Some((600, 400)));
        c.source = Some((300, 200));
        assert_eq!(surface_size(&c), Some((300, 200)));
        c.destination = Some((1000, 700));
        assert_eq!(surface_size(&c), Some((1000, 700)));
        c.buffer = None;
        assert_eq!(
            surface_size(&c),
            Some((1000, 700)),
            "a destination is the size even before the buffer's is known"
        );
    }

    /// The dropdown hangs from the ≡'s cell, in the geometry the compositor
    /// was told: the strip and the row where they are, less the geometry's
    /// origin; the ≡ the first cell of stage 3's look.
    #[test]
    fn the_dropdown_hangs_from_the_menu_button() {
        let look = &LOOK.buttons;
        let strip = Rect {
            x: 4,
            y: 4,
            w: 632,
            h: TITLE_HEIGHT,
        };
        let geometry = Rect {
            x: 0,
            y: 0,
            w: 640,
            h: 500,
        };
        let at = strip.w - look.width_all() - look.margin;
        let anchor = menu_anchor(strip, at, geometry, look).unwrap();
        assert_eq!(anchor.x, 4 + at);
        assert_eq!(
            (anchor.y, anchor.w, anchor.h),
            (4, look.width, TITLE_HEIGHT)
        );
        // The geometry's origin moved: the anchor with it.
        let moved = Rect {
            x: -3,
            y: -7,
            ..geometry
        };
        let far = menu_anchor(strip, at, moved, look).unwrap();
        assert_eq!((far.x, far.y), (anchor.x + 3, anchor.y + 7));
    }

    /// «Always focused» (3d): `activated` added where it is not, once;
    /// `suspended` taken out; every other state kept, in its order.
    #[test]
    fn a_window_that_is_always_focused_is_told_it_is_activated() {
        let words = |ws: &[u32]| -> Vec<u8> { ws.iter().flat_map(|w| w.to_ne_bytes()).collect() };
        assert_eq!(always_activated(&words(&[])), words(&[ACTIVATED]));
        assert_eq!(
            always_activated(&words(&[FULLSCREEN, SUSPENDED])),
            words(&[FULLSCREEN, ACTIVATED])
        );
        assert_eq!(
            always_activated(&words(&[ACTIVATED, 1])),
            words(&[ACTIVATED, 1])
        );
    }

    /// The dropdown's keys: ↓ ↑ go round, Enter and Space act on the lit
    /// row (nothing lit: nothing), Esc closes, anything else is nothing.
    #[test]
    fn the_dropdown_answers_its_keys() {
        assert_eq!(menu_key(KEY_DOWN, 4, None), MenuKey::Light(0));
        assert_eq!(menu_key(KEY_DOWN, 4, Some(3)), MenuKey::Light(0));
        assert_eq!(menu_key(KEY_UP, 4, None), MenuKey::Light(3));
        assert_eq!(menu_key(KEY_UP, 4, Some(0)), MenuKey::Light(3));
        assert_eq!(menu_key(KEY_ENTER, 4, Some(2)), MenuKey::Act(2));
        assert_eq!(menu_key(KEY_KPENTER, 4, Some(1)), MenuKey::Act(1));
        assert_eq!(menu_key(KEY_SPACE, 4, None), MenuKey::Nothing);
        assert_eq!(menu_key(KEY_ESC, 4, Some(1)), MenuKey::Close);
        assert_eq!(menu_key(30, 4, Some(1)), MenuKey::Nothing);
        assert_eq!(menu_key(KEY_DOWN, 0, None), MenuKey::Close);
        assert_eq!(
            crate::wl_title::MENU_LABELS.len(),
            4,
            "the rows menu_act knows"
        );
    }

    /// The buttons at the look's end of the strip, the text in the rest with
    /// its pads; a strip too narrow for them and a little to drag by has
    /// none.
    #[test]
    fn the_buttons_take_the_end_of_the_strip_and_the_text_the_rest() {
        let look = &LOOK.buttons;
        let row = look.width_all();
        assert_eq!(row, 72);
        // The look there is: at the right end.
        let wide = title_layout(640, look);
        assert_eq!(
            wide,
            TitleLayout {
                text_x: TITLE_PAD,
                room: 640 - row,
                buttons: Some(640 - row)
            }
        );
        // The text stops a pad before the buttons.
        let shown = text_shown(wide.room, 1000);
        assert_eq!(wide.text_x + shown + TITLE_PAD, 640 - row);
        // Just room for them and the drag, and not.
        let least = row + 2 * TITLE_PAD;
        assert_eq!(title_layout(least, look).buttons, Some(least - row));
        let narrow = title_layout(least - 1, look);
        assert_eq!(narrow.buttons, None);
        assert_eq!((narrow.text_x, narrow.room), (TITLE_PAD, least - 1));
        // A look with its buttons at the left end (macOS's, later): the row
        // first, the text after it.
        let left = ButtonsLook {
            end: End::Left,
            ..*look
        };
        let l = title_layout(640, &left);
        assert_eq!(l.buttons, Some(0));
        assert_eq!(l.text_x, row + TITLE_PAD);
        assert_eq!(l.text_x + text_shown(l.room, 1000) + TITLE_PAD, 640);
    }

    /// Which button a point on the row is: the look's cell under it, and
    /// none outside the row — so, which one is lit and which one a click
    /// is for. Wherever the row is on the strip, its surface's own
    /// coordinates say.
    #[test]
    fn the_button_under_the_pointer_is_the_one_lit() {
        let look = &LOOK.buttons;
        let row = title_layout(300, look).buttons.unwrap();
        // A point of the strip, on the row's surface.
        let on_row = |strip_x: f64, y: f64| look.at(strip_x - f64::from(row), y);
        assert_eq!(
            on_row(f64::from(row) - 1.0, 10.0),
            None,
            "left of it: the title"
        );
        assert_eq!(on_row(f64::from(row) + 1.0, 10.0), Some(Button::Menu));
        assert_eq!(on_row(f64::from(row) + 30.0, 10.0), Some(Button::Network));
        assert_eq!(on_row(299.0, 10.0), Some(Button::Close));
        assert_eq!(on_row(299.0, 25.0), None, "below the strip");
        let lit = |b: Option<Button>, pressed| b.map(|button| Lit { button, pressed });
        assert_eq!(look.variant(lit(on_row(299.0, 5.0), false)), 3);
        assert_eq!(
            look.variant(lit(on_row(f64::from(row) - 1.0, 5.0), false)),
            0
        );
    }

    /// A press on the border resizes by its side's edge — and by both edges
    /// of a corner within [`CORNER`] of it, measured from the window's
    /// corner (the side strips begin a border's width below it).
    #[test]
    fn the_border_resizes_by_its_edge_and_its_corners_by_both() {
        let [top, bottom, left, right] = strips(R, BT);
        let b = BT.border;
        let e = |side, r: Rect, x: f64, y: f64| edges(side, r, b, x, y);
        assert_eq!(e(Side::Top, top, 300.0, 2.0), EDGE_TOP);
        assert_eq!(e(Side::Top, top, 3.0, 2.0), EDGE_TOP | EDGE_LEFT);
        assert_eq!(
            e(Side::Top, top, f64::from(CORNER) - 0.5, 0.0),
            EDGE_TOP | EDGE_LEFT
        );
        assert_eq!(e(Side::Top, top, f64::from(CORNER), 0.0), EDGE_TOP);
        assert_eq!(
            e(Side::Top, top, f64::from(top.w) - 1.0, 1.0),
            EDGE_TOP | EDGE_RIGHT
        );
        assert_eq!(e(Side::Bottom, bottom, 300.0, 1.0), EDGE_BOTTOM);
        assert_eq!(e(Side::Bottom, bottom, 0.0, 1.0), EDGE_BOTTOM | EDGE_LEFT);
        assert_eq!(e(Side::Left, left, 1.0, 200.0), EDGE_LEFT);
        // The left strip starts `b` below the corner: its first CORNER - b
        // are the corner's.
        assert_eq!(e(Side::Left, left, 1.0, 0.0), EDGE_LEFT | EDGE_TOP);
        assert_eq!(
            e(Side::Left, left, 1.0, f64::from(CORNER - b) - 0.5),
            EDGE_LEFT | EDGE_TOP
        );
        assert_eq!(e(Side::Left, left, 1.0, f64::from(CORNER - b)), EDGE_LEFT);
        assert_eq!(
            e(Side::Right, right, 1.0, f64::from(right.h) - 1.0),
            EDGE_RIGHT | EDGE_BOTTOM
        );
        assert_eq!(e(Side::Right, right, 1.0, 100.0), EDGE_RIGHT);
        // The resize edges of xdg-shell.
        assert_eq!(EDGE_TOP | EDGE_LEFT, XdgToplevelResizeEdge::TOP_LEFT.0);
        assert_eq!(
            EDGE_BOTTOM | EDGE_RIGHT,
            XdgToplevelResizeEdge::BOTTOM_RIGHT.0
        );
        assert_eq!(Side::ALL.map(Side::index), [0, 1, 2, 3], "strips' order");
    }

    /// Arrows over the border, the default cursor over the title and the
    /// buttons (no hand: they light up instead).
    #[test]
    fn the_cursor_says_what_a_press_would_do() {
        use WpCursorShapeDeviceV1Shape as S;
        let c = |hit| cursor_for(hit).0;
        assert_eq!(c(Hit::Edge(EDGE_TOP)), S::N_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_BOTTOM)), S::S_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_LEFT)), S::W_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_RIGHT)), S::E_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_TOP | EDGE_LEFT)), S::NW_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_TOP | EDGE_RIGHT)), S::NE_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_BOTTOM | EDGE_LEFT)), S::SW_RESIZE.0);
        assert_eq!(c(Hit::Edge(EDGE_BOTTOM | EDGE_RIGHT)), S::SE_RESIZE.0);
        for hit in [
            Hit::Title,
            Hit::Button(Button::Close),
            Hit::Button(Button::Menu),
            Hit::Nothing,
        ] {
            assert_eq!(c(hit), S::DEFAULT.0, "{hit:?}");
        }
    }

    /// Asks wait for the proxy's loop in their order, a few at most.
    #[test]
    fn asks_are_kept_in_order_and_bounded() {
        let asks = Asks::default();
        asks.push(Ask::Menu);
        asks.push(Ask::Network);
        assert_eq!(asks.take(), [Ask::Menu, Ask::Network]);
        assert!(asks.take().is_empty());
        for _ in 0..10 {
            asks.push(Ask::Menu);
        }
        assert_eq!(asks.take().len(), MAX_ASKS);
    }

    /// Each look's buttons at its end of the strip, its margin between them
    /// and the end, the text in the rest with its pads; macOS's at the left,
    /// the text after them. Where the pointer finds a button is the look's
    /// cell there.
    #[test]
    fn each_look_lays_its_buttons_out_at_its_end() {
        use crate::frame::ButtonStyle;
        use crate::wl_title::buttons_look;
        let w = 640;
        for style in ButtonStyle::ALL {
            let look = buttons_look(style);
            let row = look.width_all();
            let layout = title_layout(w, &look);
            if row == 0 {
                assert_eq!(layout.buttons, None, "{style:?}");
                assert_eq!((layout.text_x, layout.room), (TITLE_PAD, w));
                continue;
            }
            let at = layout.buttons.unwrap();
            match look.end {
                End::Right => {
                    assert_eq!(at + row + look.margin, w, "{style:?}: at the right end");
                    assert_eq!(layout.text_x, TITLE_PAD);
                    // The text stops a pad before the buttons.
                    let shown = text_shown(layout.room, 1000);
                    assert_eq!(layout.text_x + shown + TITLE_PAD, at, "{style:?}");
                }
                End::Left => {
                    assert_eq!(style, ButtonStyle::Macos);
                    assert_eq!(at, look.margin, "at the left end");
                    assert_eq!(layout.text_x, look.margin + row + TITLE_PAD);
                    assert_eq!(layout.text_x + text_shown(layout.room, 1000) + TITLE_PAD, w);
                }
            }
            // A point of the strip on the row's surface: the look's cell,
            // close where the look has it.
            let on_row = |strip_x: f64| look.at(strip_x - f64::from(at), 10.0);
            let close = look
                .order
                .iter()
                .position(|b| b.button == Button::Close)
                .unwrap();
            let middle = f64::from(at) + f64::from(look.width) * (close as f64 + 0.5);
            assert_eq!(on_row(middle), Some(Button::Close), "{style:?}");
            assert_eq!(on_row(f64::from(at) - 0.5), None, "{style:?}: the strip's");
            assert_eq!(on_row(f64::from(at + row)), None, "{style:?}: the strip's");
            if style == ButtonStyle::Macos {
                assert_eq!(close, 0, "close first, at the left");
            } else {
                assert_eq!(close, 2, "close last, at the right");
            }
            // Too narrow for the row, its margin and a little to drag by:
            // none.
            let least = row + look.margin + 2 * TITLE_PAD;
            assert!(title_layout(least, &look).buttons.is_some());
            assert_eq!(title_layout(least - 1, &look).buttons, None);
        }
    }

    /// The soft border's rings: the outer one around the inner one around
    /// the program and the title; together they tile the band exactly, each
    /// ring's corners on the diagonal; one ring is the border of before.
    #[test]
    fn the_rings_of_a_border_tile_its_band() {
        for i in [
            B,
            BT,
            Insets {
                border: 6,
                title: 0,
            },
            Insets {
                border: 5,
                title: TITLE_HEIGHT,
            },
        ] {
            // One ring: `strips` exactly — `full` keeps its pixels.
            assert_eq!(ring_strips(R, i, &[i.border]), strips(R, i).to_vec());
            let widths = [i.border / 2, i.border - i.border / 2];
            let parts = ring_strips(R, i, &widths);
            assert_eq!(parts.len(), 8);
            let up = geometry_up(R, i);
            let mut all = parts.clone();
            all.extend(title_strip(R, i, false));
            let area: i64 = all.iter().map(|r| r.w as i64 * r.h as i64).sum();
            assert_eq!(
                area,
                up.w as i64 * up.h as i64 - R.w as i64 * R.h as i64,
                "{i:?}"
            );
            let overlap = |a: &Rect, r: &Rect| {
                a.x < r.x + r.w && a.x + a.w > r.x && a.y < r.y + r.h && a.y + a.h > r.y
            };
            for (n, r) in all.iter().enumerate() {
                assert!(
                    r.x >= up.x && r.y >= up.y && r.x + r.w <= up.x + up.w,
                    "{r:?}"
                );
                assert!(!overlap(r, &R), "{r:?} over the program");
                for other in &all[n + 1..] {
                    assert!(!overlap(r, other), "{r:?} over {other:?}");
                }
            }
            // The outer ring along the outside, the inner one hugging the
            // program (and the title).
            assert_eq!((parts[0].x, parts[0].y), (up.x, up.y));
            assert_eq!(parts[0].h, widths[0]);
            assert_eq!(parts[4].y + parts[4].h, R.y - i.title, "{i:?}");
            assert_eq!(parts[6].x + parts[6].w, R.x);
            // The top left corner: the outer ring's where either distance
            // from the outside is within it — on the diagonal.
            let inner_top = parts[4];
            assert_eq!(inner_top.x, up.x + widths[0]);
            assert_eq!(inner_top.y, up.y + widths[0]);
        }
    }

    /// Any ring of a side resizes by that side's edge, and near a corner of
    /// the window by both — measured on the whole border, whichever ring the
    /// pointer is on.
    #[test]
    fn every_ring_of_the_border_resizes_as_the_border() {
        let i = Insets {
            border: 6,
            title: TITLE_HEIGHT,
        };
        let parts = ring_strips(R, i, &[3, 3]);
        let whole = strips(R, i);
        for side in Side::ALL {
            let outer = whole[side.index()];
            for ring in 0..2 {
                let strip = parts[ring * 4 + side.index()];
                // The same point of the screen on either ring's strip.
                let e = |x: f64, y: f64| ring_edges(side, strip, outer, i.border, x, y);
                let middle = (f64::from(strip.w) / 2.0, f64::from(strip.h) / 2.0);
                let own = edges(
                    side,
                    outer,
                    i.border,
                    f64::from(outer.w) / 2.0,
                    f64::from(outer.h) / 2.0,
                );
                assert_eq!(e(middle.0, middle.1), own, "{side:?} ring {ring}");
                // Its first pixel: a corner.
                let first = e(0.5, 0.5);
                assert_ne!(first, own, "{side:?} ring {ring}: no corner at its start");
                assert_eq!(first & own, own);
            }
        }
        // One ring: exactly `edges`.
        let [top, _, left, _] = strips(R, BT);
        assert_eq!(
            ring_edges(Side::Top, top, top, 4, 3.0, 2.0),
            EDGE_TOP | EDGE_LEFT
        );
        assert_eq!(ring_edges(Side::Left, left, left, 4, 1.0, 200.0), EDGE_LEFT);
    }

    /// The round corners: squares of the radius in the program's corners,
    /// smaller on a small window, none on one too small.
    #[test]
    fn the_round_corners_lie_in_the_windows_corners() {
        let [tl, tr, bl, br] = corner_rects(R, 12).unwrap();
        assert_eq!(
            tl,
            Rect {
                x: 26,
                y: 23,
                w: 12,
                h: 12
            }
        );
        assert_eq!(
            tr,
            Rect {
                x: 26 + 640 - 12,
                y: 23,
                w: 12,
                h: 12
            }
        );
        assert_eq!(
            bl,
            Rect {
                x: 26,
                y: 23 + 480 - 12,
                w: 12,
                h: 12
            }
        );
        assert_eq!(
            br,
            Rect {
                x: 26 + 640 - 12,
                y: 23 + 480 - 12,
                w: 12,
                h: 12
            }
        );
        // Each inside the program's geometry, in its corner.
        for r in [tl, tr, bl, br] {
            assert!(r.x >= R.x && r.y >= R.y && r.x + r.w <= R.x + R.w && r.y + r.h <= R.y + R.h);
        }
        let small = Rect { w: 10, h: 30, ..R };
        assert_eq!(
            corner_rects(small, 12).unwrap()[3].w,
            5,
            "half the window at most"
        );
        assert_eq!(corner_rects(Rect { w: 1, ..R }, 12), None);
        assert_eq!(corner_rects(R, 0), None);
    }

    /// The tag's row: the title's, but a frame without a border still lays
    /// it over the content (hover); the title strip there needs a border.
    #[test]
    fn the_tags_row_is_there_without_a_border() {
        let none = Insets::default();
        assert_eq!(title_strip(R, none, true), None, "no frame, no strip");
        assert_eq!(
            tag_row(R, none, true),
            Some(Rect {
                x: 26,
                y: 23,
                w: 640,
                h: TITLE_HEIGHT
            })
        );
        assert_eq!(tag_row(R, none, false), None);
        let room = Insets {
            border: 0,
            title: TITLE_HEIGHT,
        };
        assert_eq!(tag_row(R, room, false), title_strip(R, room, false));
        assert_eq!(tag_row(R, room, true).unwrap().y, 23 - TITLE_HEIGHT);
        // The tag look takes the row's height of the window and no border.
        assert_eq!(
            geometry_up(R, room),
            Rect {
                x: 26,
                y: 3,
                w: 640,
                h: 500
            }
        );
    }
}
