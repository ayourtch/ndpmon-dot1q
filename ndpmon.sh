#!/bin/sh

### BEGIN INIT INFO
# Provides:          ndpmon
# Required-Start:    $syslog $network
# Required-Stop:     $syslog $network
# Should-Start:      $local_fs
# Should-Stop:       $local_fs
# Default-Start:     
# Default-Stop:      0 1 6
# Short-Description: Launch ndpmon daemon
### END INIT INFO

prefix=/usr/local
exec_prefix=${prefix}
datadir=${prefix}/share
confdir=${prefix}/etc
datadir=${prefix}/share
localstatedir=${prefix}/var

INSTALL_DIR=$prefix/ndpmon
MAN_DIR=/usr/local/share/man/man8
BINARY_DIR=${exec_prefix}/sbin
confprefix=/usr/local/etc
CONF_DIR=$confprefix/ndpmon
dataprefix=/var/local
DATA_DIR=$dataprefix/ndpmon


DAEMON="$BINARY_DIR/ndpmon"
INIT="$CONF_DIR/config_ndpmon.xml"
NAME="ndpmon"
DESC="Neighbor Discovery Protocol Monitor"
HOMEDIR="$INSTALL_DIR"
LOGDIR="/var/log/"
PIDFILE="/var/run/ndpmon.pid"


# Check the existence of required files
test -f $DAEMON || exit 0
test -f $INIT || exit 0

# Identify the distribution
if [ -f /etc/debian_version ]
then
	DISTRIB="DEBIAN"
elif [ -f /etc/fedora-release ]
then
	DISTRIB="FEDORA"
elif [ -f /etc/redhat-release ]
then
	DISTRIB="REDHAT"
fi

if [ $DISTRIB != "DEBIAN" ]
then
	# Source function library.
	. /etc/init.d/functions
fi

start() {
	echo -n $"Starting $DESC"
	if [ $DISTRIB = "DEBIAN" ]
	then
		start-stop-daemon --start --quiet --name $NAME --make-pidfile --pidfile $PIDFILE --exec $DAEMON 1>/dev/null 2>&1 &
	else
		daemon +5 $NAME  1>/dev/null 2>&1 &
	fi
	RETVAL=$?
	sleep 2
	echo
	if [ $RETVAL -ne 0 ]; then
	    return $RETVAL
	fi
}

stop() {	
	echo -n $"Stopping $DESC"
	if [ $DISTRIB = "DEBIAN" ]
	then
		kill `cat $PIDFILE`
	else
		killall -9 $NAME
	fi
	RETVAL=$?
	echo
	if [ $RETVAL -ne 0 ]; then
	    return $RETVAL
	fi
	
}

# See how we were called.
RETVAL=0

case "$1" in
  'start' )
  	start;
	echo
	break;;
  'stop' )
  	stop;
	echo
	break;;
  'restart'  )
  	$0 stop
	$0 start
	echo
	break;;
  'status' )
  	if [ $DISTRIB != "DEBIAN" ]
	then
		status $NAME
		RETVAL=$?
	else
		echo $"Usage: $0 {start|stop|restart}";
	fi
	;;
  *)
	echo $"Usage: $0 {start|stop|status|restart}";
	exit 1;;
esac 

exit $?
