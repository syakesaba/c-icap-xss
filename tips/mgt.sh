#!/usr/bin/env bash
# encoding: utf-8

if [ `id -u` != "0" ];then
    echo "RUN AS ROOT!!!!";
    exit;
fi

SQUID_USER=squid
C_ICAP_USER=c-icap
SQUID_GROUP=squid
C_ICAP_GROUP=c-icap
SQUID_DIR=/usr/local/squid
C_ICAP_DIR=/usr/local/c-icap
C_ICAP_IP="127.0.0.1"
SQUID_IP="127.0.0.1"
C_ICAP_PORT="1344"
SQUID_PORT="3128"
C_ICAP_SERVICE_REQMOD="xss"
C_ICAP_SERVICE_RESPMOD="xss"

TEMP_PROXY="http://${SQUID_IP}:$SQUID_PORT/"

LINES="20";

Usage(){
    echo "
    **Squid And C-iCAP Manager Shell Script
    Usage: $0 [start|stop|restart|stats|log N|check]
    
    start        - Start Squid and C-iCAP server 
    stop         - Kill All Squid and C-iCAP server
    restart      - stop & start & log flash
    stats        - Show status
    log <N|flash>- log 10 To show last 10line of logs,log flash To flash logs
    check        - Check services

    this script uses 'curl', 'w3m', 'killall', 'lsof', 'bash', 'pkill'.
    if you use a server have not installed them yet,install them.
"
}

start(){
    mkdir -p /var/run/c-icap/
    chown -R $C_ICAP_USER:$C_ICAPGROUP /var/run/c-icap;
    touch $SQUID_DIR/var/logs/access.log;
    touch $SQUID_DIR/var/logs/cache.log;
    touch $C_ICAP_DIR/var/log/server.log;
    touch $C_ICAP_DIR/var/log/access.log;
    chown -R $C_ICAP_USER:$C_ICAPGROUP $C_ICAP_DIR;
    chown -R $SQUID_USER:$SQUID_GROUP $SQUID_DIR;
    sudo -u $SQUID_USER $SQUID_DIR/sbin/squid;
    sudo -u $C_ICAP_USER $C_ICAP_DIR/bin/c-icap;
}
stop(){
    pkill squid
    pkill c-icap
    killall squid
    killall c-icap
}
restart(){
    stop;
    echo '[*]Wait 1 seconds to finish killing Squid and C-iCAP'
    sleep 1
    echo "[*]Done.";
    _log_flash;
    echo '[*]Wait 1 seconds to flash logs'
    sleep 1
    echo "[*]Done.";
    start;
    echo '[*]Wait 1 seconds to start Squid and C-iCAP.'
    sleep 1
    echo "[*]Done. Check Below. Squid and C-iCAP,are realy up?"
    sleep 1
    status;
}

_log_flash(){
    rm -f $SQUID_DIR/var/logs/*.log;
    rm -f $C_ICAP_DIR/var/log/*.log;
    touch $SQUID_DIR/var/logs/access.log;
    touch $SQUID_DIR/var/logs/cache.log;
    touch $C_ICAP_DIR/var/log/server.log;
    touch $C_ICAP_DIR/var/log/access.log;
    chown -R $C_ICAP_USER:$C_ICAPGROUP $C_ICAP_DIR;
    chown -R $SQUID_USER:$SQUID_GROUP $SQUID_DIR;
}
status(){
    ps -A | grep squid
    ps -A | grep c-icap
    lsof -i:$C_ICAP_PORT
    lsof -i:$SQUID_PORT
}
debug(){
    stop;
    echo "DEBUGGING_START!!"
    sleep 3;
    sudo -u $SQUID_USER $SQUID_DIR/sbin/squid -d 5;
    sudo -u $C_ICAP_USER $C_ICAP_DIR/bin/c-icap -D -d 1;
    status;
}
log(){
    _show_log;
    exit;
}
_show_log(){
    echo "***squid.access"
    cat $SQUID_DIR/var/logs/access.log | tail -n $LINES 
    echo "***squid.cache"
    cat $SQUID_DIR/var/logs/cache.log | tail -n $LINES
    echo "***icap.access"
    cat $C_ICAP_DIR/var/log/access.log | tail -n $LINES
    echo "***icap.server"
    cat $C_ICAP_DIR/var/log/server.log | tail -n $LINES
    exit;
}
check(){
    #echo "[*]Accessing Squid GET------------------------------"
    #export http_proxy="$TEMP_PROXY"
    #w3m -dump_head "http://www.google.com"
    #echo "[*]Accessing Squid POST-----------------------------"
    #curl -v -x $SQUID_IP:$SQUID_PORT -d '<script>alert(this)</script>\r\n' "http://www.yahoo.co.jp/" 1>/dev/null 
    echo "[*]c-icap REQMOD------------------------------------"
    $C_ICAP_DIR/bin/c-icap-client -p $C_ICAP_PORT -s $C_ICAP_SERVICE_REQMOD
    $C_ICAP_DIR/bin/c-icap-client -p $C_ICAP_PORT -s $C_ICAP_SERVICE_REQMOD -req http://www.google.co.jp/
    $C_ICAP_DIR/bin/c-icap-client -p $C_ICAP_PORT -s $C_ICAP_SERVICE_REQMOD -req http://www.google.co.jp -f $0
    echo "[*]c-icap RESOMOD-----------------------------------"
    $C_ICAP_DIR/bin/c-icap-client -p $C_ICAP_PORT -s $C_ICAP_SERVICE_RESPMOD
    $C_ICAP_DIR/bin/c-icap-client -p $C_ICAP_PORT -s $C_ICAP_SERVICE_RESPMOD -f $0
}

case $1 in
    "dbg" | "debug")
        debug;
    ;;
    "star" | "str" | "start")
        start;
    ;;
    "stop" | "sto")
        stop;
    ;;
    "restart" | "r" | "rtt" | "rst" | "rt")
        restart;
    ;;
    "ra")
        restart;
    ;;
    "stats" | "stt" | "stat")
        status;
    ;;
    "log" | "l" | "lo")
        case $2 in
            "flash")
                _log_flash;
            ;;
            "")
                _show_log;
            ;;
            *)
                LINES="$2"
                log;
            ;;
        esac
    ;;
    "check" | "c" | "ch" | "chk" )
        check;
    ;;
    *)
        Usage;
    ;;
esac
