//! Phase 0 of the proxy plan: verify assumptions A1 and A2 against the
//! pinned wayland-client / wayland-protocols crates.
//!
//! A1: `Proxy::interface()` / the generated `__interfaces` statics give a
//!     `&'static Interface` (wayland-client's re-export of
//!     `wayland_backend::protocol::Interface`) whose `requests` / `events`
//!     `MessageDesc`s carry the wire `signature` and `child_interface`,
//!     usable as a runtime signature table.
//! A2: the untyped `new_id` of `wl_registry.bind` is expanded on the wire
//!     to the interface string + version, like the table describes.
//!
//! A3-A5 (tagged-socket connect, `receive`/`send` fd forwarding,
//! xwayland-satellite eagerness) require a live wlroots compositor and are
//! verified on a real system, not here.

use wayland_client::backend::protocol::{AllowNull, ArgumentType, Interface};
use wayland_client::protocol::__interfaces::{
    WL_DATA_DEVICE_INTERFACE, WL_DATA_OFFER_INTERFACE, WL_DATA_SOURCE_INTERFACE,
    WL_KEYBOARD_INTERFACE, WL_POINTER_INTERFACE, WL_REGISTRY_INTERFACE, WL_TOUCH_INTERFACE,
    WL_DISPLAY_INTERFACE,
};

fn check(name: &str, expected: &Interface) {
    let table: &'static Interface = match name {
        "wl_data_offer" => &WL_DATA_OFFER_INTERFACE,
        "wl_data_device" => &WL_DATA_DEVICE_INTERFACE,
        "wl_data_source" => &WL_DATA_SOURCE_INTERFACE,
        "wl_keyboard" => &WL_KEYBOARD_INTERFACE,
        "wl_pointer" => &WL_POINTER_INTERFACE,
        "wl_touch" => &WL_TOUCH_INTERFACE,
        "wl_registry" => &WL_REGISTRY_INTERFACE,
        "wl_display" => &WL_DISPLAY_INTERFACE,
        _ => panic!("unknown {name}"),
    };
    assert_eq!(table.name, expected.name, "name mismatch for {name}");
    assert_eq!(table.version, expected.version, "version mismatch for {name}");
    assert_eq!(
        table.requests.len(),
        expected.requests.len(),
        "request count mismatch for {name}"
    );
    assert_eq!(
        table.events.len(),
        expected.events.len(),
        "event count mismatch for {name}"
    );
    for (i, (a, b)) in table.requests.iter().zip(expected.requests.iter()).enumerate() {
        assert_eq!(a.name, b.name, "request {i} of {name}");
        assert_eq!(a.signature, b.signature, "request {i} ({}) signature of {name}", a.name);
    }
    for (i, (a, b)) in table.events.iter().zip(expected.events.iter()).enumerate() {
        assert_eq!(a.name, b.name, "event {i} of {name}");
        assert_eq!(a.signature, b.signature, "event {i} ({}) signature of {name}", a.name);
    }
    println!("{name}: v{} | requests: {:?} | events: {:?}",
        table.version,
        table.requests.iter().map(|m| m.name).collect::<Vec<_>>(),
        table.events.iter().map(|m| m.name).collect::<Vec<_>>(),
    );
}

#[test]
fn a1_signature_table_is_usable() {
    // The statics must match each other (generated table vs. the backend's
    // hand-written core tables for wl_display / wl_registry / wl_callback):
    // if they disagreed, the client and a wayland-rs server would speak
    // different wire formats for the same message.
    check("wl_registry", &WL_REGISTRY_INTERFACE);
    check("wl_data_offer", &WL_DATA_OFFER_INTERFACE);
    check("wl_data_device", &WL_DATA_DEVICE_INTERFACE);
    check("wl_data_source", &WL_DATA_SOURCE_INTERFACE);
    check("wl_keyboard", &WL_KEYBOARD_INTERFACE);
    check("wl_pointer", &WL_POINTER_INTERFACE);
    check("wl_touch", &WL_TOUCH_INTERFACE);
    check("wl_display", &WL_DISPLAY_INTERFACE);
}

#[test]
fn a2_registry_bind_expansion() {
    // The untyped `new_id` of wl_registry.bind expands on the wire to
    // (name: uint, interface: str, version: uint, id: new_id).
    let bind = &WL_REGISTRY_INTERFACE.requests[0];
    assert_eq!(bind.name, "bind");
    assert_eq!(
        bind.signature,
        &[
            ArgumentType::Uint,
            ArgumentType::Str(AllowNull::No),
            ArgumentType::Uint,
            ArgumentType::NewId,
        ]
    );
    assert!(bind.child_interface.is_none(), "bind's new_id is untyped");

    // The generated client code expands a bind-like (untyped) new_id into
    // the (interface, version) tuple plus the id word, so the on-wire
    // message is exactly this 4-arg signature (name, interface, version,
    // id); see wayland-scanner client_gen `gen_methods`.
    // global event: (name: uint, interface: str, version: uint)
    let global = &WL_REGISTRY_INTERFACE.events[0];
    assert_eq!(global.name, "global");
    assert_eq!(
        global.signature,
        &[ArgumentType::Uint, ArgumentType::Str(AllowNull::No), ArgumentType::Uint]
    );

    // opcode == index in the table (tables are built in XML order)
    assert_eq!(WL_REGISTRY_INTERFACE.requests[0].name, "bind");
    assert_eq!(WL_REGISTRY_INTERFACE.events[0].name, "global");
    assert_eq!(WL_REGISTRY_INTERFACE.events[1].name, "global_remove");
    // NOTE (protocol facts in this timeline): wl_display has no `flush`
    // request (flushing is a local-only socket flush) and carries a
    // `delete_id` *event* (server acknowledgement of a deletion).
    assert_eq!(WL_DISPLAY_INTERFACE.requests.len(), 2);
    assert_eq!(WL_DISPLAY_INTERFACE.requests[0].name, "sync");
    assert_eq!(WL_DISPLAY_INTERFACE.requests[1].name, "get_registry");
    assert_eq!(WL_DISPLAY_INTERFACE.events[0].name, "error");
    assert_eq!(WL_DISPLAY_INTERFACE.events[1].name, "delete_id");
}

#[test]
fn a2b_clipboard_message_signatures() {
    // wl_data_offer.receive: (mime: string, fd) — the interception point
    // of the clipboard gate. (The mime argument is non-nullable in this
    // timeline's protocol.)
    let receive = &WL_DATA_OFFER_INTERFACE
        .requests
        .iter()
        .find(|m| m.name == "receive")
        .expect("wl_data_offer has receive");
    assert_eq!(
        receive.signature,
        &[ArgumentType::Str(AllowNull::No), ArgumentType::Fd]
    );

    // wl_data_source.send: (mime: string, fd) — the origin-proof signal.
    let send = &WL_DATA_SOURCE_INTERFACE
        .events
        .iter()
        .find(|m| m.name == "send")
        .expect("wl_data_source has send");
    assert_eq!(send.signature, &[ArgumentType::Str(AllowNull::No), ArgumentType::Fd]);

    // wl_data_device.data_offer: (new_id wl_data_offer)
    let data_offer = &WL_DATA_DEVICE_INTERFACE
        .events
        .iter()
        .find(|m| m.name == "data_offer")
        .expect("wl_data_device has data_offer");
    assert_eq!(data_offer.signature, &[ArgumentType::NewId]);
    assert!(data_offer.child_interface.is_some());
    assert_eq!(
        data_offer.child_interface.unwrap().name,
        "wl_data_offer"
    );
}
