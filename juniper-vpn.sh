#!/bin/bash
#set -x

VPNSITE="vpn.site.com"
JUNIPER="$HOME/.juniper_networks/"
COOKIES="$HOME/.mozilla/firefox/yourprofile.default/cookies.sqlite"
NCUI="$JUNIPER/network_connect/ncui"
CERT="$JUNIPER/network_connect/ssl.crt"


function getCert()
{
    [ -r "$CERT" ] && return
    openssl s_client -connect $VPNSITE 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform der > ${CERT}
    if [ ! -r "$CERT" ]; then
	echo "Couldn't get cert from vpn site $VPNSITE"
	exit 1
    fi
}

function getDsid()
{
    if [ ! -r "$COOKIES" ]
    then
	echo "Couldn't read browser cookie cache $COOKIES"
	echo "Make sure you set the correct path in this script"
	exit 1
    fi
    
    DSID=$(sqlite3 "$COOKIES"  "select value from moz_cookies where name='DSID'")
    if [ -z "$DSID" ] 
    then
	echo "Couldn't get DSID, you must login to $VPNSITE from your browser"
	echo "and the sqlite3 package must be installed on your system"
	return 1
    fi
    return 0
}

function makeNcui()
{
    [ -x ${NCUI} ] && return
    gcc -m32 -Wl,-rpath,${JUNIPER}/network_connect/ -o ${NCUI} ${JUNIPER}/network_connect/libncui.so
    if [ ! -x ${NCUI} ]
    then
	echo "Couldn't make ncui executable"
	echo "Make sure you have gcc-multilib packages installed"
	exit 1
    fi
    echo "Setting NCUI executable set UID root"
    echo "Enter password for sudo"
    sudo chown root:root $NCUI || exit 1
    sudo chmod 4755 $NCUI || exit 1
}

function connect()
{
    getDsid || return 1
    # echo new line in order to pass enter to Password prompt
    (echo | $NCUI -h $VPNSITE -c DSID=$DSID -f ${CERT}  >/dev/null 2>&1 ) 2>/dev/null &
}

function disconnect()
{
    pgrep ncui >/dev/null || return
    for i in "1 2 3 4 5"
    do
	    pgrep ncui >/dev/null || break
	    killall ncui
	    sleep 1
    done
    pgrep ncui >/dev/null && killall -9 ncui
}

function restoreResolv()
{
    # killing/exiting ncui in disconnect should restore resolv.conf
    # if it does not, this will restore it
    # TODO: eventually call this before quitting or after a 'd' command
    if [ ! -L /etc/resolve.conf ] && [ -f /run/resolvconf/resolv.conf ]
    then
	sudo rm -f /etc/resolv.conf
	sudo ln -s /run/resolvconf/resolv.conf /etc/resolv.conf
	echo "Restored /etc/resolv.conf"
    fi
}

function testNetwork()
{
    # ping default gateway since some networks like airport wifi 
    # block pings outside the network, being able to ping the gateway
    # doesn't mean network is good however, may need to use wget
    # to retreive public url of some minimal web page
    GATEWAY=$(ip route | grep default | grep -v tun | awk '{print $3}')
    ping -c 1 -W 2 $GATEWAY >/dev/null 2>&1 
    if [ "$?" -ne 0 ]; then
	return 1
    fi
    return 0
}

function testVpn()
{
    # ping the vpn gateway to see if our vpn connection is still up
    VPNHOST=$(ip route | grep default | grep tun | awk '{print $3}')
    [ -n "$VPNHOST" ] || return 1
    ping -c 1 -W 3 $VPNHOST > /dev/null 2>&1 || return 1
    return 0
}

function checkCmd()
{   
    read -t 10 -N 1 CMD
    if [ "$CMD" = "q" ]
    then
	echo
	echo "Got 'q', disconnecting and exiting"
	disconnect
	exit 0
    elif [ "$CMD" = "d" ]
    then
	echo
	echo "Got 'd', disconnecting and waiting for 'q' or 'r'"
	disconnect
	WAIT="y"
    elif [ "$CMD" = "r" ]
    then
	echo
	echo "Got 'r', reconnecting"
	disconnect
	WAIT=""
    elif [ "$CMD" = "p" ]
    then
	echo
	echo "Got 'p', printing connection details"
	ip addr show tun0
	ip route | grep tun
    fi 
}

WAIT=""
function main()
{
    getCert
    makeNcui
    getDsid
    echo "Starting vpn connect script"
    echo "Hit q at anytime to quit, r to start/restart vpn, d to disconnect vpn, p to print connection details"
    while : 
    do
    	if  ! testNetwork
	then
	    echo "Waiting for network..."
	    disconnect
	elif ! testVpn
	then
	    echo "VPN connection failed or not connected, reconnecting"
	    disconnect
	    sleep 2
	    connect
	fi
	checkCmd
	while [ -n "$WAIT" ]
	do
	    checkCmd
	done
    done
}

main
