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
# CIL rendering — the *install path* on policycoreutils 3.11+:
# libsepol's CIL reader (in the same library semodule uses) accepts
# plain CIL files, so `semodule -i build/wlsctx.cil` installs this
# module with no checkmodule/semodule_package round-trip (see
# README.md and LESSONS.md). Note the .cil carries no file contexts
# (this build passes no -f); the filecon lands via
# `semanage fcontext -a -f wlsctx.fc` at install time.
checkmodule -m -M -C -o build/wlsctx.cil wlsctx.te
if [ -f wlsctx.fc ]; then
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p -f wlsctx.fc
else
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p
fi
echo "built: $(pwd)/build/wlsctx.pp"
