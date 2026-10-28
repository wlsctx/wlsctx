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
# Reference CIL rendering (checkpolicy 3.11 can *write* CIL but not
# *read* it — see README.md; not an install path).
checkmodule -m -M -C -o build/wlsctx.cil wlsctx.te
if [ -f wlsctx.fc ]; then
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p -f wlsctx.fc
else
    semodule_package -o build/wlsctx.pp -m build/wlsctx.p
fi
echo "built: $(pwd)/build/wlsctx.pp"
