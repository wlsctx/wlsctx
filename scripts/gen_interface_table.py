#!/usr/bin/env python3
"""Generate src/proxy/interfaces.rs: the proxy's name -> &'static Interface table.

Walks the protocol crate sources (wayland-client, wayland-protocols) to find
every `wayland_protocol!` invocation, resolves the Rust path of its generated
`__interfaces` module, and reads the interface names from the protocol XML.
Also covers the wlroots family vendored under protocols/.

Run from the repository root. The dependency sources are located in the
cargo registry: after `cargo fetch --locked` plus any build that extracts
them (e.g. `cargo check`), the extracted sources live in
`$CARGO_HOME/registry/src/<index-hash>/`. The crate versions are read from
Cargo.toml, so a version bump in the manifest is all it takes to
regenerate against the new sources. The registry layout is overridable
for unusual setups:

    WLSCTX_CARGO_REGISTRY   root of the registry `src/` tree
                            (default: $CARGO_HOME or ~/.cargo, + /registry/src)
    WLSCTX_WAYLAND_CLIENT_SRC    directory of the extracted wayland-client source
    WLSCTX_WAYLAND_PROTOCOLS_SRC directory of the extracted wayland-protocols source

    python3 scripts/gen_interface_table.py
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "src" / "proxy" / "interfaces.rs"

# Features enabled for wayland-protocols in Cargo.toml
ENABLED = {"client", "staging", "unstable"}


def ident(name: str) -> str:
    return name.replace("-", "_").upper() + "_INTERFACE"


def xml_interfaces(xml_path: Path):
    root = ET.parse(xml_path).getroot()
    return [iface.get("name") for iface in root.findall("interface")]


def parse_modules(src_text: str, crate_root: Path, file_mod: str):
    """Yield (module_path, xml_abs_path, required_features) for every
    wayland_protocol! invocation, honouring nested `pub mod` and their
    #[cfg(feature = "...")] gates. `file_mod` is the module this file is
    (the files live inside the crate's lib.rs mod tree)."""
    lines = src_text.splitlines()
    stack: list[tuple[str, set[str]]] = [(file_mod, set())]  # (name, features)
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"\s*pub mod (\w+) \{", line)
        if m:
            feats = set()
            j = i - 1
            while j >= 0:
                cm = re.match(r'\s*#\[cfg\((.*?)\)\]\s*$', lines[j])
                if cm:
                    for f in re.findall(r'feature = "(\w+)"', cm.group(1)):
                        feats.add(f)
                    j -= 1
                else:
                    break
            stack.append((m.group(1), feats))
            i += 1
            continue
        if "wayland_protocol!(" in line:
            # The call is usually multi-line: the path is the first
            # string literal on this line or one of the next few.
            path = None
            for k in range(i, min(i + 4, len(lines))):
                m2 = re.search('"([^"]+)"', lines[k])
                if m2 and m2.group(1).endswith(".xml"):
                    path = m2.group(1)
                    break
            if path is None:
                sys.exit(f"no xml path for wayland_protocol! at line {i + 1}")
            if not path.startswith("./"):
                sys.exit(f"unexpected xml path {path!r}")
            xml_abs = (crate_root / path).resolve()
            if not xml_abs.exists():
                sys.exit(f"missing xml {xml_abs}")
            feats = set()
            for _, f in stack:
                feats |= f
            modpath = "::".join(name for name, _ in stack)
            yield modpath, xml_abs, feats
            i += 1
            continue
        if line.strip() == "}" and stack:
            stack.pop()
        i += 1


def manifest_version(crate: str) -> str:
    """The version the manifest pins for `crate` (e.g. `0.31.11`)."""
    toml = (REPO / "Cargo.toml").read_text()
    for line in toml.splitlines():
        m = re.match(rf"^{crate}\s*=\s*\{{[^}}]*version\s*=\s*\"([^\"]+)\"|^{crate}\s*=\s*\"([^\"]+)\"", line)
        if m:
            return m.group(1) or m.group(2)
    sys.exit(f"{crate} not found in Cargo.toml")


def find_extracted_source(crate: str) -> Path:
    """Locate the extracted sources of `crate` in the cargo registry.

    Prefers an explicit override env var; otherwise scans
    `$CARGO_HOME/registry/src/*/` for the exact `crate-version` directory
    named by Cargo.toml. (cargo fetch only downloads the .crate file into
    `registry/cache/`; the `src/` tree appears once something builds —
    CI runs `cargo check` first.)
    """
    override = os.environ.get(f"WLSCTX_{crate.upper().replace('-', '_')}_SRC")
    if override:
        p = Path(override)
        if not p.is_dir():
            sys.exit(f"{override} (from WLSCTX_{crate.upper()}_SRC) is not a directory")
        return p

    cargo_home = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    src_root = Path(os.environ.get(
        "WLSCTX_CARGO_REGISTRY",
        str(Path(cargo_home) / "registry" / "src"),
    ))
    version = manifest_version(crate)
    # Glob per index-hash directory, keeping exact-version directories only.
    candidates = [
        d for idx in sorted(src_root.glob("*")) if idx.is_dir()
        for d in [idx / f"{crate}-{version}"] if d.is_dir()
    ]
    if len(candidates) > 1:
        sys.exit(f"multiple {crate}-{version} sources under {src_root}: "
                 f"{[str(c) for c in candidates]}")
    if not candidates:
        sys.exit(
            f"could not find the extracted {crate}-{version} sources under "
            f"{src_root} (looked for <index-hash>/{crate}-{version}); "
            f"run `cargo fetch --locked && cargo check` first, or point "
            f"WLSCTX_{crate.upper()}_SRC at the source directory"
        )
    print(f"using {crate} sources: {candidates[0]}", file=sys.stderr)
    return candidates[0]


def main():
    arms = []
    seen = {}

    def add(name: str, rust_path: str, origin: str):
        if name in seen:
            print(f"warn: duplicate interface {name}: {origin} vs {seen[name]} (keeping first)", file=sys.stderr)
            return
        seen[name] = origin
        arms.append((name, rust_path, origin))

    wc_root = find_extracted_source("wayland-client")
    wp_root = find_extracted_source("wayland-protocols")

    # 1. Core protocol (wayland-client's wayland.xml)
    core_xml = wc_root / "wayland.xml"
    if not core_xml.exists():
        sys.exit(f"missing {core_xml}")
    for name in xml_interfaces(core_xml):
        add(name, f"wayland_client::protocol::__interfaces::{ident(name)}", "core")

    # 2. wayland-protocols (client-side generated tables)
    for src_file in ("xdg.rs", "wp.rs", "ext.rs"):
        file_mod = src_file[: -len(".rs")]
        for modpath, xml_abs, feats in parse_modules(
            (wp_root / "src" / src_file).read_text(), wp_root, file_mod
        ):
            if not feats <= ENABLED:
                print(f"skip {modpath}: needs {feats - ENABLED}", file=sys.stderr)
                continue
            for name in xml_interfaces(xml_abs):
                add(
                    name,
                    f"wayland_protocols::{modpath}::client::__interfaces::{ident(name)}",
                    f"wayland-protocols {modpath}",
                )

    # 3. Vendored wlroots family
    for xml_abs in sorted((REPO / "protocols").glob("*.xml")):
        for name in xml_interfaces(xml_abs):
            add(
                name,
                f"crate::proxy::wlr_tables::__interfaces::{ident(name)}",
                f"wlr:{xml_abs.name}",
            )

    arms.sort(key=lambda a: a[0])

    out = []
    out.append("//! Proxy interface table: protocol interface name -> `&'static Interface`.")
    out.append("")
    out.append("// GENERATED FILE — do not edit by hand.")
    out.append(f"// Regenerate: python3 scripts/gen_interface_table.py  ({len(arms)} interfaces)")
    out.append("")
    out.append("use wayland_backend::protocol::Interface;")
    out.append("")
    out.append(
        "/// The complete set of interfaces the proxy can parse. The proxy is"
    )
    out.append(
        "/// fail-closed: a `wl_registry.bind` naming an interface that is not"
    )
    out.append(
        "/// listed here aborts the connection (see [`crate::proxy::wire`])."
    )
    out.append("pub static TABLE: &[(&str, &Interface)] = &[")
    for name, rust_path, _origin in arms:
        out.append(f'    (\"{name}\", &{rust_path}),')
    out.append("];")
    out.append("")
    out.append(
        "/// Look up an interface by its wire name (the `str` argument of"
    )
    out.append("/// `wl_registry.bind`).")
    out.append("pub fn lookup(name: &str) -> Option<&'static Interface> {")
    out.append("    TABLE.iter().find(|(n, _)| *n == name).map(|(_, i)| *i)")
    out.append("}")
    out.append("")

    OUT.write_text("\n".join(out))
    print(f"wrote {OUT} with {len(arms)} interfaces")


if __name__ == "__main__":
    main()
