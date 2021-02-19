#!/bin/sh
# resolve user host list

if which greadlink >/dev/null 2>/dev/null; then
 SCRIPT=$(greadlink -f "$0")
else
 SCRIPT=$(readlink -f "$0")
fi
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

getexclude

"$EXEDIR/create_ipset.sh"
