#!/bin/bash

set -u
set -e
set -o pipefail

declare  DIR
declare  HOST
declare  FILE

echo -===========================================================
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
            echo -e "\e[91mUSAGE: $(basename $0) [-d DIRECTORY] [-f FILE containing IP's]\e[0m"
            exit 1
            ;;
    esac
done
shift "$(($OPTIND -1))"

function nmap_scan {
    echo  -e "\e[33m[*] Nmap TCP scan initiated\e[0m"
    nmap -Pn -n -T4 -sC -p- -sV -vv -A -O -oN "$DIR/$1/nmap_tcp" -oG "$DIR/$1/nmap_tcp_grep" --open $1 >/dev/null &
    echo  -e "\e[33m[*] Nmap UDP scan initiated\e[0m"
    nmap -Pn -n -T4 -sU -sV -sC -vv -A -O --top-ports 200 --open -oN "$DIR/$1/nmap_udp" -oG "$DIR/$1/nmap_udp_grep" --open $1 >/dev/null &
    #nmap -Pn -n -T2 -sV -A -sC -sU --top-ports 200  $1> "$1/udp_nmap"
    wait
    echo  -e "\e[92m[+] Nmap TCP scan completed\e[0m"
    echo  -e "\e[92m[+] Nmap UDP scan completed\e[0m"
    ps=($(egrep -v "^#|Status: Up" $DIR/$1/nmap_tcp_grep $DIR/$1/nmap_udp_grep | cut -d' ' -f4- | sed -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | sort -n))

    for ps in "${ps[@]}"; do
        ports=($(echo $ps | awk -F '/' '{print $1}'))
        services=($(echo $ps | awk -F '/' '{print $5}'))
        for serv in "${!services[@]}"; do
           # echo "${ports[$serv]}: ${services[$serv]}"
            service=${services[$serv]}
            port=${ports[$serv]}
            if [ "$service" == "http" ]; then
                http_enum $port $1 &
                nikto_scan $port $1 &
                gobuster_scan $port $1 &
            elif [ "$service" == "ssl|http" ] || [ "$service" == "https" ]; then
                https_enum $port $1 &
            elif [ "$service" == "smtp" ]; then
                smtp_enum $port $1 &
            elif [ "$service" == "ftp"  ]; then
                ftp_enum $port $1 &
            elif [ "$service" == "microsoft-ds" ] || [ "$service" == "netbios-ssn" ]; then
                smb_enum $port $1 &
            elif [ "$service" == "snmp" ]; then
                snmp_enum $port $1 &
            elif [ "$service" == "ms-sql" ]; then
                mssql_enum $port $1 &
            fi
        done        
    done
    wait
}

function gobuster_scan {
    if [ $1 -eq 80 ]; then
        echo  -e "\e[33m[*] Gobuster scan initiated\e[0m"
        gobuster -u http://$2/ -w /usr/share/wordlists/dirb/common.txt -t 40 > "$DIR/$2/gobuster"
    elif [ $1 -eq 443 ]; then
        echo  -e "\e[33m[*] Gobuster scan initiated\e[0m"
        gobuster -u https://$2/ -w /usr/share/wordlists/dirb/common.txt -t 40 > "$DIR/$2/gobuster"
    fi
    echo  -e "\e[92m[+] Gobuster scan completed\e[0m"

}

function http_enum {
    echo -e "\e[33m[*] HTTP enumeration initiated\e[0m"
    nmap -sV -Pn -n -T4 -vv -p $1 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt --append-output -oN "$DIR/$2/http_enum" $2 >/dev/null
    echo  -e "\e[33m[+] HTTP enumeration completed\e[0m"
}

function https_enum {
        echo  -e "\e[33m[*] HTTPS Enumeration initiated\e[0m"
    nmap -sV -Pn -n -T4  -p $1 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt --append-output -oN "$DIR/$2/https_enum" -vv $2 >/dev/null
        echo  -e "\e[92m[+] HTTPS Enumeration completed\e[0m"
}

function smtp_enum {
        echo  -e "\e[33m[*] SMTP scan initiated\e[0m"
    nmap -sV -Pn -n -T4  -p $1 --script=smtp-brute.nse,smtp-commands.nse,smtp-enum-users.nse,smtp-open-relay.nse,smtp-strangeport.nse,smtp-vuln* --append-output -oN "$DIR/$2/smtp_enum_nmap" -vv $2 >/dev/null
        echo  -e "\e[92m[+] SMTP scan completed\e[0m"
}

function ftp_enum {
        echo  -e "\e[33m[*] FTP Enumeration initiated\e[0m"
    nmap -sV -Pn -T4 -n  -p $1 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 --append-output -oN "$DIR/$2/ftp_enum" -vv $2 >/dev/null
        echo  -e "\e[92m[+] FTP Enumeration completed\e[0m"
}

function smb_enum {
        echo  -e "\e[33m[*] SMB scan initiated\e[0m"
    nmap -sV -Pn -T4 -n  -p $1 --script=smb-check-vulns.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-os-discovery.nse,smb-system-info.nse,smbv2-enabled.nse --append-output -oN "$DIR/$2/smb_enum_nmap" -vv $2 >/dev/null
        echo  -e "\e[92m[+] SMB scan completed\e[0m"
        echo  -e "\e[33m[*] Trying to enumerate SMB shares\e[0m"
    smbmap -H $2 > "$DIR/$2/smbmap" 
        echo  -e "\e[92m[+] SMB shares enum completed\e[0m"
        echo  -e "\e[33m[*] Running enum4linux\e[0m"
    enum4linux -a $2 > "$DIR/$2/enum4linux"
        echo  -e "\e[92m[+] Completed enum4linux scan\e[0m"
}

function snmp_enum {
        echo  -e "\e[33m[*] Running snmpwalk\e[0m"
    snmpwalk -c public -v1 $2 > "$DIR/$2/snmpwalk"
        echo  -e "\e[92m[+] snmpwalk enum completed\e[0m"
        echo  -e "\e[33m[*] SNMP scan initiated\e[0m"
    nmap -sV -sU -Pn -T4 -n  -p $1 --script=snmp-brute.nse,snmp-interfaces.nse,snmp-netstat.nse,snmp-processes.nse,snmp-sysdescr.nse --append-output -oN "$DIR/$2/snmp_enum_nmap" -vv $2 >/dev/null
        echo  -e "\e[92m[+] SNMP scan completed\e[0m"
}

function mssql_enum {
        echo  -e "\e[33m[*] MSSQL scan initiated\e[0m"
    nmap  -sV -Pn -n -T4 -p $1 --script=ms-sql-info,ms-sql-ntlm-info.nse,ms-sql-query.nse,ms-sql-tables.nse,ms-sql-brute.nse,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa --append-output -oN "$DIR/$2/mssql_enum_nmap" $2 >/dev/null
        echo  -e "\e[92m[+] MSSQL scan completed\e[0m"
}

function nikto_scan {
        echo  -e "\e[33m[*] RUnning Nikto\e[0m"
    nikto -h $2 -p $1 >> "$DIR/$2/nikto"
        echo  -e "\e[92m[+] Nikto scan completed\e[0m"
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
    echo -e "\e[91mUSAGE: $(basename $0) [-d DIRECTORY] [-f FILE containing IP's]\e[0m"
fi
