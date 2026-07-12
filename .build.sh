#!/bin/bash
cd "${0%/*}"
APPNAME=logic_monitor_websites
OUTPUT="${1:-$APPNAME.spl}"
chmod -R u=rwX,go= *
chmod -R u-x+X *
chmod -R u=rwx,go= bin/*
python3.9 -m pip install --upgrade -t lib -r lib/requirements.txt --no-dependencies
find lib -type d -name __pycache__ -prune -exec rm -rf {} +
# Package id (logic_monitor_websites) differs from this repo's checkout dir name,
# so rename the top-level directory in the archive rather than tar the checkout as-is.
SRC="$(basename "$PWD")"
cd ..
tar -cpzf "$OUTPUT" --exclude=.* --overwrite --transform "s,^$SRC,$APPNAME," "$SRC"
