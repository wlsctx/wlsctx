#!/bin/sh
# Build the wlsctx SELinux module.
#
#   ./build.sh            → build/wlsctx.p + build/wlsctx.pp
#
# checkmodule (from the checkpolicy package) compiles the .te into a
# loadable module; -m = non-base (loadable) module, -M = MLS/MCS
# (this system runs targeted + MCS, so the module types carry the
# user's range). No network, no root, no SRPM needed.
set -eu
cd "$(dirname "$0")"
mkdir -p build
checkmodule -m -M -o build/wlsctx.p wlsctx.te
#
# CIL rendering (see README.md "Build"): checkpolicy 3.11 can *write*
# CIL; the CIL *reader* it relies on lives in libsepol (the library
# semodule links), so `semodule -i build/wlsctx.cil` is a valid install
# path on this toolchain (LESSONS #25). The `.cil` carries the rules
# only (no `-f` below) — it has no file contexts; the label lands
# separately (README "Install", route B).
checkmodule -m -M -C -o build/wlsctx.cil wlsctx.te
#
# .pp packages. `semanage_package`'s filecon context survives the
# 3.11 `.pp`→CIL store conversion only in *colon form*; the standard
# `gen_context(...)` form (wlsctx.fc) is serialized verbatim and the
# reader then rejects it (LESSONS #25). So:
#   wlsctx.pp           - gen_context fc (classic; works on older
#                         policycoreutils, breaks on 3.11)
#   wlsctx.nofc.pp      - policy only
#   wlsctx.fcresolved.pp- the 3.11-safe one-command install (colon-form
#                         fc), README "Install" route A
if [ -f wlsctx.fc ]; then
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p -f wlsctx.fc
else
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p
fi
if [ -f wlsctx.fc.resolved ]; then
    semodule_package -o build/wlsctx.fcresolved.pp -m build/wlsctx.p -f wlsctx.fc.resolved
    semodule_package -o build/wlsctx.nofc.pp -m build/wlsctx.p
fi
echo "built: $(pwd)/build/wlsctx.{pp,fcresolved.pp,nofc.pp,cil}"
