#!/bin/sh

if which greadlink >/dev/null 2>/dev/null; then
 SCRIPT=$(greadlink -f "$0")
else
 SCRIPT=$(readlink -f "$0")
fi
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

getuser

. "$EXEDIR/antifilter.helper"

get_antifilter https://antifilter.network/download/ipsum.lst "$ZIPLIST"

"$EXEDIR/create_ipset.sh"
