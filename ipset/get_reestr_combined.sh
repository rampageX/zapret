#!/bin/sh

if which greadlink >/dev/null 2>/dev/null; then
 SCRIPT=$(greadlink -f "$0")
else
 SCRIPT=$(readlink -f "$0")
fi
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
 # $3 - ipban list
 # $4 - ip version : 4,6

 local DOMMASK='^.*;[^ ;:/]+\.[^ ;:/]+;'
 local TMP="$TMPDIR/tmp.txt"

 echo processing reestr lists $2 $3

 # find entries with https or without domain name - they should be banned by IP
 # 2971-18 is TELEGRAM. lots of proxy IPs banned, list grows very large
 ($GREP -avE "$DOMMASK" "$ZREESTR" ; $GREP -a "https://" "$ZREESTR") |
  $GREP -oE "$1" | cut_local | sort -u >$TMP

 ip2net$4 <"$TMP" | zz "$3" 

 # other IPs go to regular zapret list
 tail -n +2 "$ZREESTR"  | $GREP -oE "$1" | cut_local | $GREP -xvFf "$TMP" | ip2net$4 | zz "$2"

 rm -f "$TMP"
}


curl -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL_REESTR" -o "$ZREESTR" ||
{
 echo reestr list download failed
 exit 2
}
dlsize=$(LANG=C wc -c "$ZREESTR" | xargs | cut -f 1 -d ' ')
if test $dlsize -lt 1048576; then
 echo reestr ip list is too small. can be bad.
 exit 2
fi
#sed -i 's/\\n/\r\n/g' $ZREESTR

[ "$DISABLE_IPV4" != "1" ] && {
 dig_reestr '[1-9][0-9]{0,2}\.([0-9]{1,3}\.){2}[0-9]{1,3}(/[0-9]+)?' "$ZIPLIST" "$ZIPLIST_IPBAN" 4
}

[ "$DISABLE_IPV6" != "1" ] && {
 dig_reestr '[0-9,a-f,A-F]{1,4}:[0-9,a-f,A-F,:]+[0-9,a-f,A-F]{1,4}(/[0-9]+)?' "$ZIPLIST6" "$ZIPLIST_IPBAN6" 6
}

rm -f "$ZREESTR"

"$EXEDIR/create_ipset.sh"
