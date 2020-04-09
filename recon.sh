#!/bin/bash

set -u
set -e
set -o pipefail

declare  DIR
declare  HOST
declare  FILE

RED='\e[91m'
GREEN='\e[32m'
BLUE='\e[34m'
NC='\e[0m'

echo "______  __             _____             
___  / / /___  __________  /_____________
__  /_/ /_  / / /_  __ \  __/  _ \_  ___/
_  __  / / /_/ /_  / / / /_ /  __/  /    
/_/ /_/  \__,_/ /_/ /_/\__/ \___//_/     
                                    "
echo ""

while getopts ':d:f:' OPTION; do
    case ${OPTION} in
        d)
            #Using sed to make sure the / at the end is removed, just in case user puts in !
            DIR="$(echo $OPTARG | sed -e 's/\/$//g')"
            ;;
        f)
            FILE="$OPTARG"
            ;;
        \?) 
            echo -e "${RED}[!] USAGE: $(basename $0) [-d DIRECTORY] [-f FILE containing IP's]${NC}"
            exit 1
            ;;
    esac
done
shift "$(($OPTIND -1))"

function nmap_scan {
    echo  -e "${BLUE}[*] Nmap TCP scan initiated${NC}"
    nmap_speedy_tcp $1 &
    echo  -e "${BLUE}[*] Nmap UDP scan initiated${NC}"
    nmap_speedy_udp $1 &
    wait
    echo  -e "${GREEN}[+] Nmap TCP scan completed${NC}"
    echo  -e "${GREEN}[+] Nmap UDP scan completed${NC}"
    
    if [ -f "$DIR/$1/out" ]; then
    #get the ports
        ports=($(egrep -v "^#|Status: Up" "$DIR/$1/out" | cut -d' ' -f4- | sed -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | sort -n | uniq | grep -iv "closed" | cut -d'/' -f1))
    #This can proceed in background to speed up the whole thing as we only need the grepable output to continue
        nmap -sV -sC --max-retries 10 --max-scan-delay 50 --min-rate 350 --script=vulners.nse --script-args mincvss=7.0 -vv -Pn -n -A -O -p$(echo ${ports[@]} | tr ' ' ',') $1 -oN "$DIR/$1/nmap_tcp_full" 2>&1>/dev/null &
    fi

    if [ -f "$DIR/$1/out" ] && [ -f "$DIR/$1/out_udp" ]; then
        ps=($(egrep -v "^#|Status: Up" "$DIR/$1/out" "$DIR/$1/out_udp" | cut -d' ' -f4- | sed -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | sort -n | uniq | grep -iv "closed"))
    
        for ps in "${ps[@]}"; do
            ports=($(echo $ps | awk -F '/' '{print $1}'))
            services=($(echo $ps | awk -F '/' '{print $5}'))
            for serv in "${!services[@]}"; do
                service=${services[$serv]}
                port=${ports[$serv]}
                if [[ "$service" == "http" ]]; then
                    http_enum $port $1 &
                    #gobuster_scan $service $1 &
                elif [[ "$service" =~ ^apani1 ]]; then
                    cassandra_enum $port $1 &
                elif [[ "$service" =~ ^ipp ]]; then
                    cups_enum $port $1 &
                elif [[ "$service" =~ ^distccd ]]; then
                    distcc_enum $port $1 &
                elif [[ "$service" =~ ^domain ]]; then
                    dns_enum $port $1 &
                elif [[ "$service" =~ ^imap ]]; then
                    imap_enum $port $1 &
                elif [[ "$service" =~ ^kerberos ]] || [[ "$service" =~ ^kpasswd ]]; then
                    kerberos_enum $port $1 &
                elif [[ "$service" =~ ^ldap ]]; then
                    LDAP_enum $port $1 &
                elif [[ "$service" =~ ^mongod ]]; then
                    mongodb_enum $port $1 &
                elif [[ "$service" =~ ^mssql ]] || [[ "$service" =~ ^ms-sql ]]; then
                    mssql_enum $port $1 &
                elif [[ "$service" =~ ^mysql ]]; then
                    mysql_enum $port $1 &
                elif [[ "$service" =~ ^nfs ]] || [[ "$service" =~ ^rpcbind ]]; then
                    nfs_enum $port $1 &
                elif [[ "$service" =~ ^nntp ]]; then
                    nntp_enum $port $1 &
                elif [[ "$service" =~ ^oracle ]]; then
                    oracle_enum $port $1 &
                elif [[ "$service" =~ ^pop3 ]]; then
                    pop3_enum $port $1 &
                elif [[ "$service" =~ ^rdp ]] || [[ "$service" =~ ^ms-wbt-server ]] || [[ "$service" =~ ^ms-term-serv ]]; then
                    rdp_enum $port $1 &
                elif [[ "$service" =~ ^java\-rmi ]] || [[ "$service" =~ ^rmiregistry ]]; then
                    rmi_enum $port $1 &
                elif [[ "$service" =~ ^msrpc ]] || [[ "$service" =~ ^rpcbind ]] || [[ "$service" =~ ^erpc ]]; then
                    rpc_enum $port $1
                elif [[ "$service" =~ ^asterisk ]]; then
                    sip_enum $port $1 &
                elif [[ "$service" =~ ^ssh ]]; then
                    ssh_enum $port $1 &
                elif [[ "$service" =~ ^telnet ]]; then
                    telnet_enum $port $1 &
                elif [[ "$service" =~ ^tftp ]]; then
                    tftp_enum $port $1 &
                elif [[ "$service" =~ ^vnc ]]; then
                    vnc_enum $port $1 &
                elif [[ "$service" == "ssl|http" ]] || [[ "$service" == "https" ]]; then
                    https_enum $port $1 &
                    #gobuster_scan $service $1 &
                elif [[ "$service" =~ ^smtp ]]; then
                    smtp_enum $port $1 &
                elif [[ "$service" =~ ^ftp ]] || [[ "$service" =~ ^ftp-data ]]; then
                    ftp_enum $port $1 &
                elif [[ "$service" =~ ^microsoft-ds ]] || [[ "$service" =~ ^smb ]] || [[ "$service" =~ ^netbios ]]; then
                    if [ $port -eq 445 ];then
                        echo $port
                        smb_enum $port $1 &
                    fi
                elif [[ "$service" =~ ^snmp ]]; then
                    snmp_enum $port $1 &
                fi
            done
        done
        wait
        cleanup $1
    fi
}

function nmap_speedy_tcp {
    #make sure you got a beefy machine to handle this.
    limit=4369
    for i in {1..15}; do
        lower=$((limit - 4368))
        nmap_range $lower $limit "$1" &
        limit=$((limit + 4369))
    done
    wait
}

function nmap_range {
    nmap "-p$1-$2" -T4 --open --min-rate=150 --max-scan-delay 30 --max-retries 5 -Pn -n -vv "$3" -oG "$DIR/$3/$1" 2>&1>/dev/null
    # write to file if output contains any open port
    grep -q "open/" "$DIR/$3/$1"
    if [[ "$?" -eq 0 ]]; then
        cat "$DIR/$3/$1" | grep -i "open/" >> "$DIR/$3/out"
    fi
}

function nmap_speedy_udp {
    nmap -Pn -n -T4 -sU -vv --min-rate=500 --max-retries=5 --top-ports 200 "$1" -oG "$DIR/$1/out_udp" 2>&1>/dev/null
    ps=($(egrep -v "^#|Status: Up" "$DIR/$1/out_udp" | cut -d' ' -f4- | sed -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | sort -n | uniq | grep -iv "closed" | cut -d'/' -f1))

    #This can proceed in background to speed up the whole thing as we only need grepable output to continue
    nmap -sV -sC -sU -T4 -Pn -n -vv --min-rate=350 --max-retries=8 --script=vulners.nse --script-args mincvss=7.0 -A -O -p$(echo ${ps[@]} | tr ' ' ',') $1 -oN "$DIR/$1/nmap_udp_top200" 2>&1>/dev/null &
}

function gobuster_scan {
    if [ "$1" == "ssl|http" ] || [ "$1" == "https" ]; then
        echo  -e "${BLUE}[*] Gobuster scan initiated${NC}"
        gobuster -u https://$2/ -w /usr/share/wordlists/dirb/common.txt -t 40 >> "$DIR/$2/gobuster"
    else
        echo  -e "${BLUE}[*] Gobuster scan initiated${NC}"
        gobuster -u http://$2/ -w /usr/share/wordlists/dirb/common.txt -t 40 >> "$DIR/$2/gobuster"
    fi
    echo  -e "${GREEN}[+] Gobuster scan completed${NC}"

}

function http_enum {
    echo -e "${BLUE}[*] HTTP enumeration initiated${NC}"
    nmap -sV -Pn -n -T4 -vv -p $1 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" --append-output -oN "$DIR/$2/http_enum" $2 >/dev/null
    echo -e "${BLUE}[*] Running Nikto${NC}"
    #nikto -ask=no -host http://$2:$1 > "$DIR/$2/nikto_http"
    echo -e "${GREEN}[+] Nikto scan completed"
    echo  -e "${GREEN}[+] HTTP enumeration completed${NC}"
}

function https_enum {
    echo  -e "${BLUE}[*] HTTPS Enumeration initiated${NC}"
    nmap -sV -Pn -n -T4  -p $1 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt --append-output -oN "$DIR/$2/https_enum" -vv $2 >/dev/null
    sslscan --show-certificate $2 2>&1 | tee "$DIR/$2/sslscan"
    echo -e "${BLUE}[*] Running Nikto${NC}"
    #nikto -ask=no -h https://$2:$1 -ssl > "$DIR/$2/nikto_http"
    echo -e "${GREEN}[+] Nikto scan completed${NC}"
    echo  -e "${GREEN}[+] HTTPS Enumeration completed${NC}"
}

function cassandra_enum {
    echo -e "${BLUE}[*] Cassandra Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/cassandra_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] Cassandra Scan completed${NC}"
}

function cups_enum {
    echo -e "${BLUE}[*] Cups Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(cups* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/cups_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] Cups scan completed${NC}"
}

function distcc_enum {
    echo -e "${BLUE}[*] distcc Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd=id" --append-output -oN "$DIR/$2/distcc_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] distcc scan completed"
}

function dns_enum {
    echo -e "${BLUE}[*] DNS Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/dns_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] DNS scan completed"
}

function ftp_enum {
    echo  -e "${BLUE}[*] FTP Scan initiated${NC}"
    nmap -sV -Pn -T4 -n  -p $1 --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/ftp_enum" -vv $2 >/dev/null
    echo  -e "${GREEN}[+] FTP Scan completed${NC}"
}

function imap_enum {
    echo -e "${BLUE}[*] IMAP Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/imap_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] IMAP Scan completed${NC}"
}

function LDAP_enum {
    echo -e "${BLUE}[*] LDAP Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/LDAP_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] LDAP Scan completed${NC}"
}

function kerberos_enum {
    echo -e "${BLUE}[*] Kerberos Scan inititated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,krb5-enum-users" --append-output -oN "$DIR/$2/kerberus_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] Kerberos Scan completed${NC}"
}

function mongodb_enum {
    echo -e "${BLUE}[*] Mongodb Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/mongodb_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] Mongodb Scan completed${NC}"
}

function mysql_enum {
    echo -e "${BLUE}[*] MySql Scan started${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/mysql_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] MySql Scan completed${NC}"
}

function nfs_enum {
    echo -e "${BLUE}[*] NFS enumeration started${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/nfs_enum_nmap" -vv $2 >/dev/null
    showmount -e $2 2>&1 | tee "$DIR/$2/nfs_showmount"
    echo -e "${GREEN}[+] NFS enumeration completed${NC}"
}

function nntp_enum {
    echo -e "${BLUE}[*] nntp scan started${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,nntp-ntlm-info" --append-output -oN "$DIR/$2/nntp_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] nttp scan completed${NC}"
}

function oracle_enum {
    echo -e "${BLUE}[*] Oracle enumeration initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(oracle* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/oracle_enum_nmap" -vv $2 >/dev/null
    nmap -sV -Pn -n -T4 -p $1 --script="banner,oracle-sid-brute" --append-output -oN "$DIR/$2/oracle_sidbrute_nmap" -vv $2 >/dev/null
    tnscmd10g ping -h $2 -p $1 2>&1 | tee "$DIR/$2/oracle-tnscmd-ping"
    tnscmd10g version -h $2 -p $1 2>&1 | tee "$DIR/$2/oracle-tnscmd-version"
    oscanner -v -s $2 -P $1 2>&1 | tee "$DIR/$2/oracle-scanner"
    echo -e "${GREEN}[+] Oracle enumeration completed${NC}"
}

function pop3_enum {
    echo -e "${BLUE}[*] pop3 Scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/pop3_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] pop3 Scan completed${NC}"
}

function rdp_enum {
    echo -e "${BLUE}[*] RDP Scan inititated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/rdp_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] RDP Scan completed${NC}"
}

function rmi_enum {
    echo -e "${BLUE}[*] RMI Scan inititated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,rmi-vuln-classloader,rmi-dumpregistry" --append-output -oN "$DIR/$2/rmi_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] RMI Scan completed${NC}"
}

function rpc_enum {
    echo -e "${BLUE}[*] RPC Scan inititated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,msrpc-enum,rpc-grind,rpcinfo" --append-output -oN "$DIR/$2/rpc_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] RPC Scan completed${NC}"
}

function sip_enum {
    echo -e "${BLUE}[*] SIP Scan inititated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,sip-enum-users,sip-methods" --append-output -oN "$DIR/$2/sip_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] SIP Scan completed${NC}"
}

function smb_enum {
    echo  -e "${BLUE}[*] SMB scan initiated${NC}"
    nmap -sV -Pn -T4 -n  -p $1 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 --append-output -oN "$DIR/$2/smb_enum_nmap" -vv $2 >/dev/null 
    echo  -e "${GREEN}[+] SMB scan completed${NC}"
    echo -e "${BLUE}[*] Running nbtscan${NC}"
    nbtscan -rvh $2 >> "$DIR/$2/nbtscan"
    echo -e "${GREEN}[+] nbtscan completed${NC}"
    echo  -e "${BLUE}[*] Trying to enumerate SMB shares${NC}"
    smbmap -H $2 >> "$DIR/$2/smbmap" 
    smbclient -L\\ -N -I $2 > "$DIR/$2/smbclient"
    echo  -e "${GREEN}[+] SMB shares enum completed${NC}"
    echo  -e "${BLUE}[*] Running enum4linux${NC}"
    enum4linux -a -M -l -d $2 >> "$DIR/$2/enum4linux"
    echo  -e "${GREEN}[+] Completed enum4linux scan${NC}"
}

function snmp_enum {
    echo  -e "${BLUE}[*] Running snmpwalk${NC}"
    snmpwalk -c public -v1 $2 >> "$DIR/$2/snmpwalk"
    echo  -e "${GREEN}[+] snmpwalk enum completed${NC}"
    echo  -e "${BLUE}[*] SNMP scan initiated${NC}"
    nmap -sV -sU -Pn -T4 -n  -p $1 --script="banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/snmp_enum_nmap" -vv $2 >/dev/null
    onesixtyone -c /opt/Seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -dd $2 2>&1 | tee "$DIR/$2/onesixtyone"
    echo  -e "${GREEN}[+] SNMP scan completed${NC}"
}

function smtp_enum {
    echo -e "${BLUE}[*] Running SMTP Scan${NC}"
    nmap -sV -sV -Pn -T4 -n -p $1 --script="banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --append-output -oN "$DIR/$2/smtp_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] SMTP scan completed"
    echo -e "${BLUE}[*] Enumerating SMTP usernames${NC}"
    smtp-user-enum -M VRFY -U /opt/Seclists/Usernames/top-usernames-shortlist.txt -t $2 -p $1 2>&1 | tee "$DIR/$2/smtp_user_enum"
    echo -e "${GREEN}[+] SMTP username enumeration completed${NC}"
}

function ssh_enum {
    echo -e "${BLUE}[*] Running SSH Scan${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" --append-output -oN "$DIR/$2/ssh_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] SSH Scan completed${NC}"
}

function telnet_enum {
    echo -e "${BLUE}[*] Running telnet Scan${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,telnet-encryption,telnet-ntlm-info" --append-output -oN "$DIR/$2/telnet_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] telnet Scan completed${NC}"
}

function tftp_enum {
    echo -e "${BLUE}[*] Running TFTP Scan${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,tftp-enum" --append-output -oN "$DIR/$2/tftp_enum_nmap" -vv $2 >/dev/null
    echo -e "${GREEN}[+] TFTP Scan completed${NC}"
}

function mssql_enum {
    echo  -e "${BLUE}[*] MSSQL scan initiated${NC}"
    nmap  -sV -Pn -n -T4 -p $1 --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port=$1,mssql.username=sa,mssql.password=sa" --append-output -oN "$DIR/$2/mssql_enum_nmap" $2 >/dev/null
    echo  -e "${GREEN}[+] MSSQL scan completed${NC}"
}

function vnc_enum {
    echo  -e "${BLUE}[*] VNC scan initiated${NC}"
    nmap -sV -Pn -n -T4 -p $1 --script="banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" --append-output -oN "$DIR/$2/vnc_enum_nmap" -vv $2 >/dev/null
    echo  -e "${GREEN}[+] VNC scan completed${NC}"
}

function cleanup {
    rm -f "$DIR/$1/out"
    rm -f "$DIR/$1/out_udp"
    rm -f $DIR/$1/1* $DIR/$1/2* $DIR/$1/3* $DIR/$1/4* $DIR/$1/5* $DIR/$1/6* $DIR/$1/7* $DIR/$1/8* $DIR/$1/9*
}

if [ ${OPTIND} -eq 5 ]; then
    if [ ! -d "$DIR" ]; then
        mkdir -p "$DIR"
    else
        while read p; do
            rm -rf $p
            mkdir -p "$DIR/$p"
            nmap_scan $p
        done <  $FILE
        wait 
        echo "============================DONE============================="
    fi
else
    echo -e "${RED}[!] USAGE: $(basename $0) [-d DIRECTORY] [-f FILE containing IP's]${NC}"
fi
