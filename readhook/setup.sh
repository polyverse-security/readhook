#!/bin/bash

. /etc/os-release

function setup() {
	case "$ID" in
		alpine)
			apk update
			apk add bash curl gcc make
			;;
	
		centos|fedora|rhel)
	
			yum -y update
			yum -y install bash curl gcc make
			;;
	
		debian|ubuntu)
			DEBIAN_FRONTEND=noninteractive apt-get -y update
			DEBIAN_FRONTEND=noninteractive apt-get -y install bash curl gcc make
			;;
	
		opensuse*)
			zypper -n update
			zypper -n install bash curl gcc make
			;;
	
		*)
			echo "ERROR: in setup.h"
			return 1
			;;
	esac

	return 0
}

setup $@

