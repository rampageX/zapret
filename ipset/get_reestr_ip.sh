#!/bin/sh

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

ZREESTR="$TMPDIR/reestr.txt"
#ZURL_REESTR=https://reestr.rublacklist.net/api/current
ZURL_REESTR=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv

getuser

dig_reestr()
{
 # $1 - grep ipmask
 # $2 - iplist

 echo processing reestr list $2

 tail -n +2 "$ZREESTR" | grep -oE "$1" | cut_local | sort -u | zz "$2"
}


# assume all https banned by ip
curl -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL_REESTR" -o "$ZREESTR" ||
{
 echo reestr list download failed
 exit 2
}
dlsize=$(wc -c "$ZREESTR" | xargs | cut -f 1 -d ' ')
if test $dlsize -lt 1048576; then
 echo reestr ip list is too small. can be bad.
 exit 2
fi
#sed -i 's/\\n/\r\n/g' $ZREESTR

[ "$DISABLE_IPV4" != "1" ] && {
 dig_reestr '[1-9][0-9]{0,2}\.([0-9]{1,3}\.){2}[0-9]{1,3}(/[0-9]+)?' "$ZIPLIST"
}

[ "$DISABLE_IPV6" != "1" ] && {
 dig_reestr '[0-9,a-f,A-F]{1,4}:[0-9,a-f,A-F,:]+[0-9,a-f,A-F]{1,4}(/[0-9]+)?' "$ZIPLIST6"
}

rm -f "$ZREESTR"

"$EXEDIR/create_ipset.sh"
