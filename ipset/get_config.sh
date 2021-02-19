#!/bin/sh
# run script specified in config

if which greadlink >/dev/null 2>/dev/null; then
 SCRIPT=$(greadlink -f "$0")
else
 SCRIPT=$(readlink -f "$0")
fi
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/../config"

[ -z "$GETLIST" ] && GETLIST=get_exclude.sh
[ -x "$EXEDIR/$GETLIST" ] && exec "$EXEDIR/$GETLIST"
