#!/bin/sh

# automated script for easy installing zapret

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")
ZAPRET_CONFIG="$EXEDIR/config"

. "$ZAPRET_CONFIG"

ZAPRET_BASE=/opt/zapret

GET_LIST="$EXEDIR/ipset/get_config.sh"
GET_LIST_PREFIX=/ipset/get_
INIT_SCRIPT=/etc/init.d/zapret

DNSCHECK_DNS="8.8.8.8 1.1.1.1 77.88.8.8"
DNSCHECK_DOM="pornhub.com putinhuylo.com rutracker.org nnmclub.to kinozal.tv"
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt

SYSTEMD_SYSTEM_DIR=/lib/systemd/system
[ -d "$SYSTEMD_SYSTEM_DIR" ] || SYSTEMD_SYSTEM_DIR=/usr/lib/systemd/system

exists()
{
	which $1 >/dev/null 2>/dev/null
}
whichq()
{
	which $1 2>/dev/null
}

exitp()
{
	local A

	echo
	echo press enter to continue
	read A
	exit $1
}

[ $(id -u) -ne "0" ] && {
	echo root is required
	exists sudo && exec sudo "$0"
	exists su && exec su -c "$0"
	echo su or sudo not found
	exitp 2
}

read_yes_no()
{
	# $1 - default (Y/N)
	local A
	read A
	[ -z "$A" ] || ([ "$A" != "Y" ] && [ "$A" != "y" ] && [ "$A" != "N" ] && [ "$A" != "n" ]) && A=$1
	[ "$A" = "Y" ] || [ "$A" = "y" ] || [ "$A" = "1" ]
}
ask_yes_no()
{
	# $1 - default (Y/N or 0/1)
	# $2 - text
	local DEFAULT=$1
	[ "$1" = "1" ] && DEFAULT=Y
	[ "$1" = "0" ] && DEFAULT=N
	[ -z "$DEFAULT" ] && DEFAULT=N
	echo -n "$2 (default : $DEFAULT) (Y/N) ? "
	read_yes_no $DEFAULT
}
ask_yes_no_var()
{
	# $1 - variable name for answer : 0/1
	# $2 - text
	local DEFAULT
	eval DEFAULT="\$$1"
	if ask_yes_no "$DEFAULT" "$2"; then
		eval $1=1
	else
		eval $1=0
	fi
}

on_off_function()
{
	# $1 : function name on
	# $2 : function name off
	# $3 : 0 - off, 1 - on
	local F="$1"
	[ "$3" = "1" ] || F="$2"
	shift
	shift
	shift
	"$F" "$@"
}

get_dir_inode()
{
	local dir="$1"
	[ -L "$dir" ] && dir=$(readlink -f "$dir")
	ls -id "$dir" | awk '{print $1}'
}

md5file()
{
	md5sum "$1" | cut -f1 -d ' '
}

random()
{
	# $1 - min, $2 - max
	local r rs
	if [ -c /dev/urandom ]; then
		read rs </dev/urandom
	else
		rs="$RANDOM$RANDOM$(date)"
	fi
	# shells use signed int64
	r=1$(echo $rs | md5sum | sed 's/[^0-9]//g' | head -c 17)
	echo $(( ($r % ($2-$1+1)) + $1 ))
}

check_system()
{
	local UNAME=$(uname)

	echo \* checking system

	SYSTEM=""
	SYSTEMCTL=$(whichq systemctl)

	if [ "$UNAME" = "Linux" ]; then
		if [ -x "$SYSTEMCTL" ] ; then
			SYSTEM=systemd
		elif [ -f "/etc/openwrt_release" ] && exists opkg && exists uci ; then
			SYSTEM=openwrt
		else
			echo system is not either systemd based or openwrt. check readme.txt for manual setup info.
			exitp 5
		fi
	else
		echo easy installer only supports Linux. check readme.txt for supported systems and manual setup info.
		exitp 5
	fi
	echo system is based on $SYSTEM
}

check_bins()
{
	echo \* checking executables

	local arch=$(get_bin_arch)
	[ "$FORCE_BUILD" = "1" ] && {
		echo forced build mode
		if [ "$arch" = "my" ]; then
			echo already compiled
		else
			arch=""
		fi
	}
	if [ -n "$arch" ] ; then
		echo found architecture "\"$arch\""
	elif [ -f "$EXEDIR/Makefile" ] && exists make; then
		echo trying to compile
		make -C "$EXEDIR" || {
			echo could not compile
			exitp 8
		}
		echo compiled
	else
		echo build tools not found
		exitp 8
	fi
}

call_install_bin()
{
	"$EXEDIR/install_bin.sh" $1
}
get_bin_arch()
{
	call_install_bin getarch
}

install_binaries()
{
	echo \* installing binaries

	call_install_bin || {
		echo compatible binaries not found
		exitp 8
	}
}

find_str_in_list()
{
	[ -n "$1" ] && {
		for v in $2; do
			[ "$v" = "$1" ] && return
		done
	}
	false
}

ask_list()
{
	# $1 - mode var
	# $2 - space separated value list
	# $3 - (optional) default value
	local M_DEFAULT
	eval M_DEFAULT="\$$1"
	local M_ALL=$M_DEFAULT
	local M=""
	local m
	
	[ -n "$3" ] && { find_str_in_list "$M_DEFAULT" "$2" || M_DEFAULT="$3" ;}
	
	n=1
	for m in $2; do
		echo $n : $m
		n=$(($n+1))
	done
	echo -n "your choice (default : $M_DEFAULT) : "
	read m
	[ -n "$m" ] && M=$(echo $2 | cut -d ' ' -f$m 2>/dev/null)
	[ -z "$M" ] && M="$M_DEFAULT"
	echo selected : $M
	eval $1="$M"
	
	[ "$M" != "$M_OLD" ]
}
write_config_var()
{
	# $1 - mode var
	local M
	eval M="\$$1"

	if grep -q "^$1=\|^#$1=" "$ZAPRET_CONFIG"; then
		# replace / => \/
		#M=${M//\//\\\/}
		M=$(echo $M | sed 's/\//\\\//g')
		if [ -n "$M" ]; then
			sed -ri "s/^#?$1=.*$/$1=$M/" "$ZAPRET_CONFIG"
		else
			# write with comment at the beginning
			sed -ri "s/^#?$1=.*$/#$1=/" "$ZAPRET_CONFIG"
		fi
	else
		# var does not exist in config. add it
		if [ -n "$M" ]; then
			echo "$1=$M" >>"$ZAPRET_CONFIG"
		else
			echo "#$1=$M" >>"$ZAPRET_CONFIG"
		fi
	fi
}

select_mode_mode()
{
	echo
	echo select MODE :
	ask_list MODE "tpws nfqws filter custom" tpws && write_config_var MODE
	case $MODE in
		tpws)
			echo
			echo tpws options : $TPWS_OPT
			echo to change : edit TPWS_OPT in $ZAPRET_CONFIG
			;;
		nfqws)
			echo
			echo nfqws options : $NFQWS_OPT_DESYNC
			echo to change : edit NFQWS_OPT_DESYNC in $ZAPRET_CONFIG
			;;
	esac
}
select_mode_http()
{
	[ "$MODE" != "filter" ] && {
		echo
		ask_yes_no_var MODE_HTTP "enable http support"
		write_config_var MODE_HTTP
	}
}
select_mode_keepalive()
{
	[ "$MODE" = "nfqws" ] && [ "$MODE_HTTP" = "1" ] && {
		echo
		echo enable keep alive support only if DPI checks every outgoing packet for http signature
		echo dont enable otherwise because it consumes more cpu resources
		ask_yes_no_var MODE_HTTP_KEEPALIVE "enable http keep alive support"
		write_config_var MODE_HTTP_KEEPALIVE
	}
}
select_mode_https()
{
	[ "$MODE" != "filter" ] && {
		echo
		ask_yes_no_var MODE_HTTPS "enable https support"
		write_config_var MODE_HTTPS
	}
}
select_mode_filter()
{
	echo
	echo select filtering :
	ask_list MODE_FILTER "none ipset hostlist" none && write_config_var MODE_FILTER
}
select_mode()
{
	select_mode_mode
	select_mode_http
	select_mode_keepalive
	select_mode_https
	select_mode_filter
}

select_getlist()
{
	if [ "$MODE_FILTER" = "ipset" -o "$MODE_FILTER" = "hostlist" ]; then
		local D=N
		[ -n "$GETLIST" ] && D=Y
		echo
		if ask_yes_no $D "do you want to auto download ip/host list"; then
			if [ "$MODE_FILTER" = "hostlist" ] ; then
				local GL_OLD=$GETLIST
				GETLIST="get_reestr_hostlist.sh"
				[ "$GL_OLD" != "$GET_LIST" ] && write_config_var GETLIST
			else
				GETLISTS="get_user.sh get_antifilter_ip.sh get_antifilter_ipsmart.sh get_antifilter_ipsum.sh get_reestr_ip.sh get_reestr_combined.sh get_reestr_resolve.sh"
				GETLIST_DEF="get_antifilter_ipsmart.sh"
				ask_list GETLIST "$GETLISTS" "$GETLIST_DEF" && write_config_var GETLIST
			fi
			return
		fi
	fi
	GETLIST=""
	write_config_var GETLIST
}
select_ipv6()
{
	local T=N

	[ "$DISABLE_IPV6" != '1' ] && T=Y
	local old6=$DISABLE_IPV6
	echo
	if ask_yes_no $T "enable ipv6 support"; then
		DISABLE_IPV6=0
	else
		DISABLE_IPV6=1
	fi
	[ "$old6" != "$DISABLE_IPV6" ] && write_config_var DISABLE_IPV6
}

ask_config()
{
	select_mode
	select_getlist
}

ask_iface()
{
	# $1 - var to ask
	ask_list $1 "$(ls /sys/class/net)" && write_config_var $1
}

ask_config_offload()
{
	is_flow_offload_avail && {
		echo
		echo flow offloading can greatly increase speed on slow devices and high speed links \(usually 150+ mbits\)
		echo unfortuantely its not compatible with most nfqws options. nfqws traffic must be exempted from flow offloading.
		echo donttouch = disable system flow offloading setting if nfqws mode was selected, dont touch it otherwise and dont configure selective flow offloading
		echo none = always disable system flow offloading setting and dont configure selective flow offloading
		echo software = always disable system flow offloading setting and configure selective software flow offloading
		echo hardware = always disable system flow offloading setting and configure selective hardware flow offloading
		echo select flow offloading :
		ask_list FLOWOFFLOAD "donttouch none software hardware" donttouch && write_config_var FLOWOFFLOAD
	}
}

get_free_space_mb()
{
    df -m $PWD | awk '/[0-9]%/{print $(NF-2)}'
}
get_ram_kb()
{
    grep MemTotal /proc/meminfo | awk '{print $2}'
}
get_ram_mb()
{
    local R=$(get_ram_kb)
    echo $(($R/1024))
}

ask_config_tmpdir()
{
	# ask tmpdir change for low ram systems with enough free disk space
	[ -n "$GETLIST" ] && [ $(get_free_space_mb "$ZAPRET_BASE/tmp") -ge 128 ] && [ $(get_ram_mb) -le 400 ] && {
		echo
		echo /tmp in openwrt is tmpfs. on low RAM systems there may be not enough RAM to store downloaded files
		echo default tmpfs has size of 50% RAM
		echo "RAM  : $(get_ram_mb) Mb"
		echo "DISK : $(get_free_space_mb) Mb"
		echo select temp file location 
		[ -z "$TMPDIR" ] && TMPDIR=/tmp
		ask_list TMPDIR "/tmp $ZAPRET_BASE/tmp" && {
		    [ "$TMPDIR" = "/tmp" ] && TMPDIR=
		    write_config_var TMPDIR
		}
	}
}

select_router_iface()
{
	local T=N
	[ -n "$IFACE_LAN" ] && [ -n "$IFACE_WAN" ] && T=Y
	local old_lan=$IFACE_LAN
	local old_wan=$IFACE_WAN

	echo
	if ask_yes_no $T "is this system a router"; then
		echo LAN interface :
		ask_iface IFACE_LAN
		echo WAN interface :
		ask_iface IFACE_WAN
	else
		[ -n "$old_lan" ] && {
			IFACE_LAN=""
			write_config_var IFACE_LAN
		}
		[ -n "$old_wan" ] && {
			IFACE_WAN=""
			write_config_var IFACE_WAN
		}
	fi
}
ask_config_desktop()
{
	select_router_iface
}

copy_all()
{
	cp -R "$1" "$2"
	[ -d "$2/tmp" ] || mkdir "$2/tmp"
}
copy_openwrt()
{
	local ARCH=$(get_bin_arch)
	local BINDIR="$1/binaries/$ARCH"
	
	[ -d "$2" ] || mkdir -p "$2"
	
	mkdir "$2/tpws" "$2/nfq" "$2/ip2net" "$2/mdig" "$2/binaries" "$2/binaries/$ARCH" "$2/init.d" "$2/tmp"
	cp -R "$1/ipset" "$2"
	cp -R "$1/init.d/openwrt" "$2/init.d"
	cp "$1/config" "$1/install_easy.sh" "$1/uninstall_easy.sh" "$1/install_bin.sh" "$2"
	cp "$BINDIR/tpws" "$BINDIR/nfqws" "$BINDIR/ip2net" "$BINDIR/mdig" "$2/binaries/$ARCH"
}

_backup_settings()
{
	local i=0
	for f in "$@"; do
		[ -f "$ZAPRET_BASE/$f" ] && cp -f "$ZAPRET_BASE/$f" "/tmp/zapret-bkp-$i"
		i=$(($i+1))
	done
}
_restore_settings()
{
	local i=0
	for f in "$@"; do
		[ -f "/tmp/zapret-bkp-$i" ] && mv -f "/tmp/zapret-bkp-$i" "$ZAPRET_BASE/$f"
		i=$(($i+1))
	done
}
backup_restore_settings()
{
	# $1 - 1 - backup, 0 - restore
	local mode=$1
	on_off_function _backup_settings _restore_settings $mode "config" "init.d/sysv/custom" "init.d/openwrt/custom" "ipset/zapret-hosts-user.txt" "ipset/zapret-hosts-user-exclude.txt" "ipset/zapret-hosts-user-ipban.txt"
}

check_location()
{
	# $1 - copy function

	echo \* checking location

	# use inodes in case something is linked
	[ -d "$ZAPRET_BASE" ] && [ $(get_dir_inode "$EXEDIR") = $(get_dir_inode "$ZAPRET_BASE") ] || {
		echo
		echo easy install is supported only from default location : $ZAPRET_BASE
		echo currently its run from $EXEDIR
		if ask_yes_no N "do you want the installer to copy it for you"; then
			local keep=N
			if [ -d "$ZAPRET_BASE" ]; then
				echo
				echo installer found existing $ZAPRET_BASE
				echo directory needs to be replaced. config and custom scripts can be kept or replaced with clean version
				if ask_yes_no N "do you want to delete all files there and copy this version"; then
					echo
					ask_yes_no Y "keep config, custom scripts and user lists" && keep=Y
					[ "$keep" = "Y" ] && backup_restore_settings 1
					rm -r "$ZAPRET_BASE"
				else
					echo refused to overwrite $ZAPRET_BASE. exiting
					exitp 3
				fi
			fi
			local B=$(dirname "$ZAPRET_BASE")
			[ -d "$B" ] || mkdir -p "$B"
			$1 "$EXEDIR" "$ZAPRET_BASE"
			[ "$keep" = "Y" ] && backup_restore_settings 0
			echo relaunching itself from $ZAPRET_BASE
			exec $ZAPRET_BASE/$(basename $0)
		else
			echo copying aborted. exiting
			exitp 3
		fi
	}
	echo running from $EXEDIR
}


check_prerequisites_linux()
{
	echo \* checking prerequisites

	if exists ipset && exists curl ; then
		echo everything is present
	else
		echo \* installing prerequisites

		APTGET=$(whichq apt-get)
		YUM=$(whichq yum)
		PACMAN=$(whichq pacman)
		ZYPPER=$(whichq zypper)
		EOPKG=$(whichq eopkg)
		if [ -x "$APTGET" ] ; then
			"$APTGET" update
			"$APTGET" install -y --no-install-recommends ipset curl dnsutils || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$YUM" ] ; then
			"$YUM" -y install curl ipset || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$PACMAN" ] ; then
			"$PACMAN" -Syy
			"$PACMAN" --noconfirm -S ipset curl || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$ZYPPER" ] ; then
			"$ZYPPER" --non-interactive install ipset curl || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$EOPKG" ] ; then
			"$EOPKG" -y install ipset curl || {
				echo could not install prerequisites
				exitp 6
			}
		else
			echo supported package manager not found
			echo you must manually install : ipset curl
			exitp 5
		fi
	fi
}


service_install_systemd()
{
	echo \* installing zapret service

	rm -f "$INIT_SCRIPT"
	ln -fs "$EXEDIR/init.d/systemd/zapret.service" "$SYSTEMD_SYSTEM_DIR"
	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" enable zapret || {
		echo could not enable systemd service
		exitp 20
	}
}

service_stop_systemd()
{
	echo \* stopping zapret service

	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" disable zapret
	"$SYSTEMCTL" stop zapret
}

service_start_systemd()
{
	echo \* starting zapret service

	"$SYSTEMCTL" start zapret || {
		echo could not start zapret service
		exitp 30
	}
}

timer_install_systemd()
{
	echo \* installing zapret-list-update timer

	"$SYSTEMCTL" disable zapret-list-update.timer
	"$SYSTEMCTL" stop zapret-list-update.timer
	ln -fs "$EXEDIR/init.d/systemd/zapret-list-update.service" "$SYSTEMD_SYSTEM_DIR"
	ln -fs "$EXEDIR/init.d/systemd/zapret-list-update.timer" "$SYSTEMD_SYSTEM_DIR"
	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" enable zapret-list-update.timer || {
		echo could not enable zapret-list-update.timer
		exitp 20
	}
	"$SYSTEMCTL" start zapret-list-update.timer || {
		echo could not start zapret-list-update.timer
		exitp 30
	}
}

download_list()
{
	[ -x "$GET_LIST" ] &&	{
		echo \* downloading blocked ip/host list

		# can be txt or txt.gz
		"$EXEDIR/ipset/clear_lists.sh"
		"$GET_LIST" || {
			echo could not download ip list
			exitp 25
		}
	}
}

crontab_del_quiet()
{
	exists crontab || return

	CRONTMP=/tmp/cron.tmp
	crontab -l >$CRONTMP
	if grep -q "$GET_IPLIST_PREFIX" $CRONTMP; then
		grep -v "$GET_IPLIST_PREFIX" $CRONTMP >$CRONTMP.2
		crontab $CRONTMP.2
		rm -f $CRONTMP.2
	fi
	rm -f $CRONTMP
}

crontab_add()
{
	# $1 - hour min
	# $2 - hour max
	[ -x "$GET_LIST" ] &&	{
		echo \* adding crontab entry

		CRONTMP=/tmp/cron.tmp
		crontab -l >$CRONTMP
		if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
			echo some entries already exist in crontab. check if this is corrent :
			grep "$GET_LIST_PREFIX" $CRONTMP
		else
			echo "$(random 0 59) $(random $1 $2) */2 * * $GET_LIST" >>$CRONTMP
			crontab $CRONTMP
		fi

		rm -f $CRONTMP
	}
}


pingtest()
{
	ping -c 1 -W 1 $1 >/dev/null
}
find_working_public_dns()
{
	for dns in $DNSCHECK_DNS; do
		pingtest $dns && nslookup w3.org $dns >/dev/null 2>/dev/null && {
			PUBDNS=$dns
			return
		}
	done
	false
}
check_dns_spoof()
{
	# $1 - domain
	# $2 - public DNS
	echo $1 | "$EXEDIR/mdig/mdig" --family=4 >"$DNSCHECK_DIG1"
	nslookup $1 $2 | sed -n '/Name:/,$p' | grep ^Address | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >"$DNSCHECK_DIG2"
	# check whether system resolver returns anything other than public DNS
	grep -qvFf "$DNSCHECK_DIG2" "$DNSCHECK_DIG1"
}
check_dns_cleanup()
{
	rm -f "$DNSCHECK_DIG1" "$DNSCHECK_DIG2" "$DNSCHECK_DIGS" 2>/dev/null
}
check_dns()
{
	local C1 C2

	echo \* checking DNS

	[ -f "$DNSCHECK_DIGS" ] && rm -f "$DNSCHECK_DIGS"
	if find_working_public_dns ; then
		echo comparing system resolver to public DNS : $PUBDNS
		for dom in $DNSCHECK_DOM; do
			if check_dns_spoof $dom $PUBDNS ; then
				echo $dom : MISMATCH
				echo -- system resolver :
				cat "$DNSCHECK_DIG1"
				echo -- $PUBDNS :
				cat "$DNSCHECK_DIG2"
				check_dns_cleanup
				echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
				echo -- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED
				false
				return
			else
				echo $dom : OK
				cat "$DNSCHECK_DIG1" >>"$DNSCHECK_DIGS"
			fi
		done
	else
		echo no working public DNS was found. looks like public DNS blocked.
		for dom in $DNSCHECK_DOM; do echo $dom; done | "$EXEDIR/mdig/mdig" --family=4 >"$DNSCHECK_DIGS"
	fi

	echo checking resolved IP uniqueness for : $DNSCHECK_DOM
	echo censor\'s DNS can return equal result for multiple blocked domains.
	C1=$(wc -l <"$DNSCHECK_DIGS")
	C2=$(sort -u "$DNSCHECK_DIGS" | wc -l)
	[ "$C1" = "$C2" ] ||
	{
		echo system dns resolver has returned equal IPs for some domains checked above \($C1 total, $C2 unique\)
		echo non-unique IPs :
		sort "$DNSCHECK_DIGS" | uniq -d
		echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
		echo -- DNSCRYPT MAY BE REQUIRED
		check_dns_cleanup
		false
		return
	}
	echo all resolved IPs are unique
	echo -- DNS looks good
	echo -- NOTE this check is Russia targeted. In your country other domains can be blocked.
	check_dns_cleanup
	true
}

install_systemd()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/sysv/zapret"

	check_bins
	check_location copy_all
	check_prerequisites_linux
	service_stop_systemd
	install_binaries
	check_dns
	select_ipv6
	ask_config_desktop
	ask_config
	service_install_systemd
	download_list
	# in case its left from old version of zapret
	crontab_del_quiet
	# now we use systemd timers
	timer_install_systemd
	service_start_systemd
}




check_kmod()
{
	[ -f "/lib/modules/$(uname -r)/$1.ko" ]
}
check_package_exists_openwrt()
{
	[ -n "$(opkg list $1)" ]
}
check_package_openwrt()
{
	[ -n "$(opkg list-installed $1)" ]
}
check_packages_openwrt()
{
	for pkg in $@; do
		check_package_openwrt $pkg || return
	done
}

is_linked_to_busybox()
{
	local F P
	F=/usr/bin/$1
	P="$(readlink $F)"
	if [ -z "$P" ] && [ -x $F ] && [ ! -L $F ]; then false; return; fi
	[ "${P%busybox*}" != "$P" ] && return
	F=/bin/$1
	P="$(readlink $F)"
	if [ -z "$P" ] && [ -x $F ] && [ ! -L $F ]; then false; return; fi
	[ "${P%busybox*}" != "$P" ]
}

check_prerequisites_openwrt()
{
	echo \* checking prerequisites

	local PKGS="iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt iptables-mod-conntrack-extra ipset curl"
	[ "$DISABLE_IPV6" != "1" ] && PKGS="$PKGS ip6tables-mod-nat"
	local UPD=0

	if check_packages_openwrt $PKGS ; then
		echo everything is present
	else
		echo \* installing prerequisites

		opkg update
		UPD=1
		opkg install $PKGS || {
			echo could not install prerequisites
			exitp 6
		}
	fi
	
	is_linked_to_busybox gzip && {
		echo
		echo your system uses default busybox gzip. its several times slower than GNU gzip.
		echo ip/host list scripts will run much faster with GNU gzip
		echo installer can install GNU gzip but it requires about 100 Kb space
		if ask_yes_no N "do you want to install GNU gzip"; then
			[ "$UPD" = "0" ] && {
				opkg update
				UPD=1
			}
			opkg install --force-overwrite gzip
		fi
	}
	is_linked_to_busybox sort && {
		echo
		echo your system uses default busybox sort. its much slower and consumes much more RAM than GNU sort
		echo ip/host list scripts will run much faster with GNU sort
		echo installer can install GNU sort but it requires about 100 Kb space
		if ask_yes_no N "do you want to install GNU sort"; then
			[ "$UPD" = "0" ] && {
				opkg update
				UPD=1
			}
			opkg install --force-overwrite coreutils-sort
		fi
	}
	is_linked_to_busybox grep && {
		echo
		echo your system uses default busybox grep. its damn infinite slow with -f option
		echo get_combined.sh will be severely impacted
		echo installer can install GNU grep but it requires about 0.5 Mb space
		if ask_yes_no N "do you want to install GNU grep"; then
			[ "$UPD" = "0" ] && {
				opkg update
				UPD=1
			}
			opkg install --force-overwrite grep

			# someone reported device partially fail if /bin/grep is absent
			# grep package deletes /bin/grep
			[ -f /bin/grep ] || ln -s busybox /bin/grep
		fi
	}
}

openwrt_fw_section_find()
{
	# $1 - fw include postfix
	# echoes section number
	
	i=0
	while true
	do
		path=$(uci -q get firewall.@include[$i].path)
		[ -n "$path" ] || break
		[ "$path" = "$OPENWRT_FW_INCLUDE$1" ] && {
	 		echo $i
	 		return
		}
		i=$(($i+1))
	done
	false
	return
}
openwrt_fw_section_del()
{
	# $1 - fw include postfix

	local id=$(openwrt_fw_section_find $1)
	[ -n "$id" ] && {
		uci delete firewall.@include[$id] && uci commit firewall
		rm -f "$OPENWRT_FW_INCLUDE$1"
	}
}
openwrt_fw_section_add()
{
	openwrt_fw_section_find ||
	{
		uci add firewall include >/dev/null || return
		echo -1
	}
}
openwrt_fw_section_configure()
{
	local id=$(openwrt_fw_section_add $1)
	[ -z "$id" ] ||
	 ! uci set firewall.@include[$id].path="$OPENWRT_FW_INCLUDE" ||
	 ! uci set firewall.@include[$id].reload="1" ||
	 ! uci commit firewall &&
	{
		echo could not add firewall include
		exitp 50
	}
}

install_openwrt_firewall()
{
	echo \* installing firewall script $1
	
	[ -n "MODE" ] || {
		echo should specify MODE in $ZAPRET_CONFIG
		exitp 7
	}
	
	echo "linking : $FW_SCRIPT_SRC => $OPENWRT_FW_INCLUDE"
	ln -fs "$FW_SCRIPT_SRC" "$OPENWRT_FW_INCLUDE"
	
	openwrt_fw_section_configure $1
}


restart_openwrt_firewall()
{
	echo \* restarting firewall

	fw3 -q restart || {
		echo could not restart firewall
		exitp 30
	}
}

remove_openwrt_firewall()
{
	echo \* removing firewall script
	
	openwrt_fw_section_del
	# from old zapret versions. now we use single include
	openwrt_fw_section_del 6

	# free some RAM
	"$EXEDIR/ipset/create_ipset.sh" clear
}

install_openwrt_iface_hook()
{
	echo \* installing ifup hook
	
	ln -fs "$OPENWRT_IFACE_HOOK" /etc/hotplug.d/iface
}

is_flow_offload_avail()
{
	# $1 = '' for ipv4, '6' for ipv6
	grep -q FLOWOFFLOAD /proc/net/ip$1_tables_targets
}

deoffload_openwrt_firewall()
{
	echo \* checking flow offloading

	is_flow_offload_avail || {
		echo unavailable
		return
	}

	local fo=$(uci -q get firewall.@defaults[0].flow_offloading)

	if [ "$fo" = "1" ] ; then
		local mod=0
		echo -n "system wide flow offloading detected. "
		case $FLOWOFFLOAD in
			donttouch)
				if [ "$MODE" = "nfqws" ]; then
					echo its incompatible with nfqws tcp data tampering. disabling
					uci set firewall.@defaults[0].flow_offloading=0
					mod=1
				else
					if [ "$MODE" = "custom" ] ; then
						echo custom mode selected !!! only you can decide whether flow offloading is compatible
					else
						echo its compatible with selected options. not disabling
					fi
				fi
			;;
		*)
			echo zapret will disable system wide offloading setting and add selective rules if required
			uci set firewall.@defaults[0].flow_offloading=0
			mod=1
		esac
		[ "$mod" = "1" ] && uci commit firewall
	else
		echo system wide software flow offloading disabled. ok
	fi
			
}

install_sysv_init()
{
	# $1 - "0"=disable
	echo \* installing init script

	[ -x "$INIT_SCRIPT" ] && {
		"$INIT_SCRIPT" stop
		"$INIT_SCRIPT" disable
	}
	ln -fs "$INIT_SCRIPT_SRC" "$INIT_SCRIPT"
	[ "$1" != "0" ] && "$INIT_SCRIPT" enable
}

service_start_sysv()
{
	echo \* starting zapret service

	"$INIT_SCRIPT" start || {
		echo could not start zapret service
		exitp 30
	}
}



install_openwrt()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/openwrt/zapret"
	FW_SCRIPT_SRC="$EXEDIR/init.d/openwrt/firewall.zapret"
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret
	OPENWRT_IFACE_HOOK="$EXEDIR/init.d/openwrt/90-zapret"
	
	check_bins
	check_location copy_openwrt
	install_binaries
	check_dns
	select_ipv6
	check_prerequisites_openwrt
	ask_config
	ask_config_tmpdir
	ask_config_offload
	install_sysv_init
	# can be previous firewall preventing access
	remove_openwrt_firewall
	restart_openwrt_firewall
	download_list
	# router system : works 24/7. night is the best time
	crontab_add 0 6
	service_start_sysv
	install_openwrt_iface_hook
	install_openwrt_firewall
	deoffload_openwrt_firewall
	restart_openwrt_firewall
}


# build binaries, do not use precompiled
[ "$1" = "make" ] && FORCE_BUILD=1

check_system

case $SYSTEM in
	systemd)
		install_systemd
		;;
	openwrt)
		install_openwrt
		;;
esac


exitp 0
