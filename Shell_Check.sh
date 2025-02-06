#!/usr/bin/bash

#로딩바-----------------------------------------------------------------------------
progress_bar() {
    local current=$1
    local total=$2
    local width=50
    local percent=$((current * 100 / total))
    
    printf "\r["
    local progress=$((percent * width / 100))
    for ((i=0; i<progress; i++)); do
        printf "#"
    done
    for ((i=progress; i<width; i++)); do
        printf " "
    done
    printf "] %d%% (%d/%d)\n" "$percent" "$current" "$total"
}
#------------------------------------------------------------------------------------
#setting---
#전체 처리갯수
total_tasks=72
#딜레이
sp=0.01
#----------

#파이프라인 표준에러 제거 grep pattern 2>/dev/null
#에러 메시지 제거 2>/dev/null


echo `clear`
bline="================================================================"

good_count=0
vuln_count=0

# 시스템 정보 수집
U_00_sys="`uname -a`"

# 진단 결과 출력 함수
print_result() {
    local title=$1
    local status=$2
    local message=$3
    local fix=$4
    
    echo $bline
    echo "[ $title ]"
    if [ "$status" = "취약" ]; then
        echo -e "\e[31m[취약]\e[0m $message"
        [ ! -z "$fix" ] && echo "조치방법: $fix"
        ((vuln_count++))
    else
        echo -e "\e[32m[양호]\e[0m $message"
        ((good_count++))
    fi
}

echo "Scanning system..."

# 시스템 정보 헤더 출력
echo $bline
echo -e "          \e[31mLED TEAM 리눅스 서버 취약점 진단 스크립트\e[0m          "
echo $bline
echo "SYSTEM INFO: $U_00_sys"
echo $bline

# 1. 계정 관리
# U-01 root 계정 원격 접속 제한
U_01_sshstat="`cat /etc/ssh/sshd_config | grep PermitRootLogin |grep -v "#" | awk '{print $2}'`"
if [ "$U_01_sshstat" = "no" ]; then
    print_result "U-01 root 계정 원격 접속 제한" "양호" \
        "root 계정 원격 접속이 제한되어 있습니다."
else
    print_result "U-01 root 계정 원격 접속 제한" "취약" \
        "root 계정 원격 접속이 허용되어 있습니다." \
        "/etc/ssh/sshd_config 파일에서 PermitRootLogin을 no로 변경하세요."
fi
progress_bar 1 $total_tasks

# U-02 패스워드 복잡성 설정
pwquality_check=$(cat /etc/security/pwquality.conf | grep -E "minlen|dcredit|ucredit|lcredit|ocredit" | grep -v "#")
if [ -n "$pwquality_check" ]; then
    print_result "U-02 패스워드 복잡성 설정" "양호" \
        "패스워드 복잡성 정책이 적절히 설정되어 있습니다."
else
    print_result "U-02 패스워드 복잡성 설정" "취약" \
        "패스워드 복잡성 설정이 미흡합니다." \
        "/etc/security/pwquality.conf 파일에서 적절한 패스워드 정책을 설정하세요."
fi
progress_bar 2 $total_tasks

# U-03 계정 잠금 임계값 설정
pam_tally2_check=$(grep "pam_tally2.so" /etc/pam.d/system-auth | grep "deny=")
if [ -n "$pam_tally2_check" ] && [[ "$pam_tally2_check" =~ deny=[1-5] ]]; then
    print_result "U-03 계정 잠금 임계값 설정" "양호" \
        "계정 잠금 임계값이 적절히 설정되어 있습니다."
else
    print_result "U-03 계정 잠금 임계값 설정" "취약" \
        "계정 잠금 임계값이 설정되어 있지 않거나 기준에 미달합니다." \
        "/etc/pam.d/system-auth 파일에서 pam_tally2.so의 deny 값을 5 이하로 설정하세요."
fi
progress_bar 3 $total_tasks

# U-04 패스워드 파일 보호
shadow_check=$(cat /etc/shadow 2>/dev/null)
if [ -n "$shadow_check" ]; then
    print_result "U-04 패스워드 파일 보호" "양호" \
        "쉐도우 패스워드를 사용하여 패스워드를 암호화하여 저장하고 있습니다."
else
    print_result "U-04 패스워드 파일 보호" "취약" \
        "쉐도우 패스워드를 사용하지 않거나 패스워드가 암호화되어 있지 않습니다." \
        "쉐도우 패스워드를 설정하고 패스워드를 암호화하여 저장하세요."
fi
progress_bar 4 $total_tasks

# U-05 root 홈, 패스 디렉터리 권한 및 패스 설정
path_check=$(echo $PATH | grep "::")
if [ -n "$path_check" ]; then
    print_result "U-05 root 홈, 패스 디렉터리 권한 및 패스 설정" "취약" \
        "PATH 환경변수에 '::' 가 포함되어 있어 현재 디렉터리가 포함될 수 있습니다." \
        "PATH 환경변수에서 '::' 를 제거하세요."
else
    print_result "U-05 root 홈, 패스 디렉터리 권한 및 패스 설정" "양호" \
        "PATH 환경변수가 적절히 설정되어 있습니다."
fi
progress_bar 5 $total_tasks

# U-06 파일 및 디렉터리 소유자 설정
file_owner_check=$(find / -nouser -o -nogroup 2>/dev/null)
if [ -n "$file_owner_check" ]; then
    print_result "U-06 파일 및 디렉터리 소유자 설정" "취약" \
        "소유자나 그룹이 존재하지 않는 파일이 있습니다." \
        "find / -nouser -o -nogroup 명령어로 검색된 파일의 소유자/그룹을 설정하세요."
else
    print_result "U-06 파일 및 디렉터리 소유자 설정" "양호" \
        "모든 파일 및 디렉터리의 소유자가 적절히 설정되어 있습니다."
fi
progress_bar 6 $total_tasks

# U-07 /etc/passwd 파일 소유자 및 권한 설정
passwd_owner=$(stat -c %U /etc/passwd)
passwd_perm=$(stat -c %a /etc/passwd)
if [ "$passwd_owner" = "root" ] && [ "$passwd_perm" = "644" ]; then
    print_result "U-07 /etc/passwd 파일 소유자 및 권한 설정" "양호" \
        "/etc/passwd 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-07 /etc/passwd 파일 소유자 및 권한 설정" "취약" \
        "/etc/passwd 파일의 소유자가 root가 아니거나 권한이 644가 아닙니다." \
        "chown root /etc/passwd; chmod 644 /etc/passwd 명령어로 설정을 변경하세요."
fi
progress_bar 7 $total_tasks

# U-08 /etc/shadow 파일 소유자 및 권한 설정
shadow_owner=$(stat -c %U /etc/shadow)
shadow_perm=$(stat -c %a /etc/shadow)
if [ "$shadow_owner" = "root" ] && [ "$shadow_perm" = "400" ]; then
    print_result "U-08 /etc/shadow 파일 소유자 및 권한 설정" "양호" \
        "/etc/shadow 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-08 /etc/shadow 파일 소유자 및 권한 설정" "취약" \
        "/etc/shadow 파일의 소유자가 root가 아니거나 권한이 400이 아닙니다." \
        "chown root /etc/shadow; chmod 400 /etc/shadow 명령어로 설정을 변경하세요."
fi
progress_bar 8 $total_tasks

# U-09 /etc/hosts 파일 소유자 및 권한 설정
hosts_owner=$(stat -c %U /etc/hosts)
hosts_perm=$(stat -c %a /etc/hosts)
if [ "$hosts_owner" = "root" ] && [ "$hosts_perm" = "644" ]; then
    print_result "U-09 /etc/hosts 파일 소유자 및 권한 설정" "양호" \
        "/etc/hosts 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-09 /etc/hosts 파일 소유자 및 권한 설정" "취약" \
        "/etc/hosts 파일의 소유자가 root가 아니거나 권한이 644가 아닙니다." \
        "chown root /etc/hosts; chmod 644 /etc/hosts 명령어로 설정을 변경하세요."
fi
progress_bar 9 $total_tasks

# U-10 /etc/xinetd.conf 파일 소유자 및 권한 설정
if [ -f "/etc/xinetd.conf" ]; then
    xinetd_owner=$(stat -c %U /etc/xinetd.conf)
    xinetd_perm=$(stat -c %a /etc/xinetd.conf)
    if [ "$xinetd_owner" = "root" ] && [ "$xinetd_perm" = "600" ]; then
        print_result "U-10 /etc/xinetd.conf 파일 소유자 및 권한 설정" "양호" \
            "/etc/xinetd.conf 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        print_result "U-10 /etc/xinetd.conf 파일 소유자 및 권한 설정" "취약" \
            "/etc/xinetd.conf 파일의 소유자가 root가 아니거나 권한이 600이 아닙니다." \
            "chown root /etc/xinetd.conf; chmod 600 /etc/xinetd.conf 명령어로 설정을 변경하세요."
    fi
else
    print_result "U-10 /etc/xinetd.conf 파일 소유자 및 권한 설정" "양호" \
        "xinetd 서비스가 설치되어 있지 않습니다."
fi
progress_bar 10 $total_tasks

# U-11 /etc/syslog.conf 파일 소유자 및 권한 설정
if [ -f "/etc/syslog.conf" ]; then
    syslog_owner=$(stat -c %U /etc/syslog.conf)
    syslog_perm=$(stat -c %a /etc/syslog.conf)
    if [ "$syslog_owner" = "root" ] && [ "$syslog_perm" = "644" ]; then
        print_result "U-11 /etc/syslog.conf 파일 소유자 및 권한 설정" "양호" \
            "/etc/syslog.conf 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        print_result "U-11 /etc/syslog.conf 파일 소유자 및 권한 설정" "취약" \
            "/etc/syslog.conf 파일의 소유자가 root가 아니거나 권한이 644가 아닙니다." \
            "chown root /etc/syslog.conf; chmod 644 /etc/syslog.conf 명령어로 설정을 변경하세요."
    fi
else
    print_result "U-11 /etc/syslog.conf 파일 소유자 및 권한 설정" "양호" \
        "syslog.conf 파일이 존재하지 않습니다. (rsyslog를 사용중일 수 있음)"
fi
progress_bar 11 $total_tasks

# U-12 /etc/services 파일 소유자 및 권한 설정
services_owner=$(stat -c %U /etc/services)
services_perm=$(stat -c %a /etc/services)
if [ "$services_owner" = "root" ] && [ "$services_perm" = "644" ]; then
    print_result "U-12 /etc/services 파일 소유자 및 권한 설정" "양호" \
        "/etc/services 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-12 /etc/services 파일 소유자 및 권한 설정" "취약" \
        "/etc/services 파일의 소유자가 root가 아니거나 권한이 644가 아닙니다." \
        "chown root /etc/services; chmod 644 /etc/services 명령어로 설정을 변경하세요."
fi
progress_bar 12 $total_tasks

# U-13 SUID, SGID, Sticky bit 설정 파일 점검
suid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null)
if [ -n "$suid_files" ]; then
    print_result "U-13 SUID, SGID, Sticky bit 설정 파일 점검" "취약" \
        "SUID/SGID가 설정된 파일이 존재합니다." \
        "불필요한 SUID/SGID 설정을 제거하세요. (chmod -s <file>)"
else
    print_result "U-13 SUID, SGID, Sticky bit 설정 파일 점검" "양호" \
        "불필요한 SUID/SGID 설정이 없습니다."
fi
progress_bar 13 $total_tasks

# U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
env_files=".profile .cshrc .login .kshrc .bash_profile .bashrc .bash_login"
env_vuln=0

for user_dir in /home/*; do
    if [ -d "$user_dir" ]; then
        user=$(basename "$user_dir")
        for file in $env_files; do
            if [ -f "$user_dir/$file" ]; then
                owner=$(stat -c %U "$user_dir/$file")
                if [ "$owner" != "$user" ] && [ "$owner" != "root" ]; then
                    env_vuln=1
                    break 2
                fi
            fi
        done
    fi
done

if [ $env_vuln -eq 0 ]; then
    print_result "U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" "양호" \
        "모든 환경파일의 소유자가 적절히 설정되어 있습니다."
else
    print_result "U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" "취약" \
        "부적절한 소유자가 설정된 환경파일이 존재합니다." \
        "각 사용자의 환경파일 소유자를 해당 사용자나 root로 변경하세요."
fi
progress_bar 14 $total_tasks

# U-15 world writable 파일 점검
world_writable=$(find / -type f -perm -2 -ls 2>/dev/null)
if [ -n "$world_writable" ]; then
    print_result "U-15 world writable 파일 점검" "취약" \
        "누구나 쓰기 가능한 파일이 존재합니다." \
        "chmod o-w 명령어로 해당 파일들의 쓰기 권한을 제거하세요."
else
    print_result "U-15 world writable 파일 점검" "양호" \
        "누구나 쓰기 가능한 파일이 없습니다."
fi
progress_bar 15 $total_tasks

# U-16 /dev에 존재하지 않는 device 파일 점검
dev_files=$(find /dev -type f -exec ls -l {} \;)
if [ -n "$dev_files" ]; then
    print_result "U-16 /dev에 존재하지 않는 device 파일 점검" "취약" \
        "/dev 디렉터리에 일반 파일이 존재합니다." \
        "불필요한 파일을 제거하세요."
else
    print_result "U-16 /dev에 존재하지 않는 device 파일 점검" "양호" \
        "/dev 디렉터리에 불필요한 파일이 없습니다."
fi
progress_bar 16 $total_tasks

# U-17 $HOME/.rhosts, hosts.equiv 사용 금지
rhosts_check=$(find /home -name .rhosts 2>/dev/null)
hosts_equiv_check=$(find / -name hosts.equiv 2>/dev/null)
if [ -n "$rhosts_check" ] || [ -n "$hosts_equiv_check" ]; then
    print_result "U-17 .rhosts, hosts.equiv 사용 금지" "취약" \
        ".rhosts 또는 hosts.equiv 파일이 존재합니다." \
        "해당 파일들을 삭제하세요."
else
    print_result "U-17 .rhosts, hosts.equiv 사용 금지" "양호" \
        ".rhosts 및 hosts.equiv 파일이 존재하지 않습니다."
fi
progress_bar 17 $total_tasks

# U-18 접속 IP 및 포트 제한
tcp_wrapper_check=$(grep -E "^(all|ALL):" /etc/hosts.allow /etc/hosts.deny 2>/dev/null)
if [ -n "$tcp_wrapper_check" ]; then
    print_result "U-18 접속 IP 및 포트 제한" "양호" \
        "TCP Wrapper가 적절히 설정되어 있습니다."
else
    print_result "U-18 접속 IP 및 포트 제한" "취약" \
        "TCP Wrapper 설정이 미흡합니다." \
        "/etc/hosts.allow 및 /etc/hosts.deny 파일에 적절한 접근 제어를 설정하세요."
fi
progress_bar 18 $total_tasks

# U-19 finger 서비스 비활성화
finger_check=$(systemctl is-active finger 2>/dev/null)
if [ "$finger_check" = "active" ]; then
    print_result "U-19 finger 서비스 비활성화" "취약" \
        "finger 서비스가 활성화되어 있습니다." \
        "systemctl stop finger; systemctl disable finger 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-19 finger 서비스 비활성화" "양호" \
        "finger 서비스가 비활성화되어 있습니다."
fi
progress_bar 19 $total_tasks

# U-20 Anonymous FTP 비활성화
ftp_check=$(grep -i "anonymous_enable" /etc/vsftpd/vsftpd.conf 2>/dev/null | grep -i "yes")
if [ -n "$ftp_check" ]; then
    print_result "U-20 Anonymous FTP 비활성화" "취약" \
        "Anonymous FTP가 활성화되어 있습니다." \
        "/etc/vsftpd/vsftpd.conf 파일에서 anonymous_enable=NO로 설정하세요."
else
    print_result "U-20 Anonymous FTP 비활성화" "양호" \
        "Anonymous FTP가 비활성화되어 있습니다."
fi
progress_bar 20 $total_tasks

# U-21 r 계열 서비스 비활성화
r_services="rsh rlogin rexec"
r_vuln=0

for service in $r_services; do
    if systemctl is-active $service &>/dev/null; then
        r_vuln=1
        break
    fi
done

if [ $r_vuln -eq 0 ]; then
    print_result "U-21 r 계열 서비스 비활성화" "양호" \
        "r 계열 서비스가 모두 비활성화되어 있습니다."
else
    print_result "U-21 r 계열 서비스 비활성화" "취약" \
        "r 계열 서비스가 활성화되어 있습니다." \
        "불필요한 r 계열 서비스를 비활성화하세요."
fi
progress_bar 21 $total_tasks

# U-22 cron 파일 소유자 및 권한설정
cron_files="/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
cron_vuln=0

for file in $cron_files; do
    if [ -e "$file" ]; then
        owner=$(stat -c %U "$file")
        perm=$(stat -c %a "$file")
        if [ "$owner" != "root" ] || [ "$perm" != "600" ]; then
            cron_vuln=1
            break
        fi
    fi
done

if [ $cron_vuln -eq 0 ]; then
    print_result "U-22 cron 파일 소유자 및 권한설정" "양호" \
        "cron 관련 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-22 cron 파일 소유자 및 권한설정" "취약" \
        "cron 관련 파일의 소유자가 root가 아니거나 권한이 600이 아닙니다." \
        "cron 관련 파일의 소유자를 root로, 권한을 600으로 변경하세요."
fi
progress_bar 22 $total_tasks

# U-23 DOS 공격에 취약한 서비스 비활성화
dos_services="echo chargen daytime discard"
dos_vuln=0

for service in $dos_services; do
    if systemctl is-active $service &>/dev/null; then
        dos_vuln=1
        break
    fi
done

if [ $dos_vuln -eq 0 ]; then
    print_result "U-23 DOS 공격에 취약한 서비스 비활성화" "양호" \
        "DOS 공격에 취약한 서비스가 모두 비활성화되어 있습니다."
else
    print_result "U-23 DOS 공격에 취약한 서비스 비활성화" "취약" \
        "DOS 공격에 취약한 서비스가 활성화되어 있습니다." \
        "echo, chargen, daytime, discard 등의 서비스를 비활성화하세요."
fi
progress_bar 23 $total_tasks

# U-24 NFS 서비스 비활성화
nfs_check=$(systemctl is-active nfs-server 2>/dev/null)
if [ "$nfs_check" = "active" ]; then
    print_result "U-24 NFS 서비스 비활성화" "취약" \
        "NFS 서비스가 활성화되어 있습니다." \
        "systemctl stop nfs-server; systemctl disable nfs-server 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-24 NFS 서비스 비활성화" "양호" \
        "NFS 서비스가 비활성화되어 있습니다."
fi
progress_bar 24 $total_tasks

# U-25 NFS 접근통제
if [ -f "/etc/exports" ]; then
    exports_check=$(grep -E "no_root_squash|insecure" /etc/exports)
    if [ -n "$exports_check" ]; then
        print_result "U-25 NFS 접근통제" "취약" \
            "NFS 설정에 보안에 취약한 옵션이 포함되어 있습니다." \
            "/etc/exports 파일에서 no_root_squash, insecure 옵션을 제거하세요."
    else
        print_result "U-25 NFS 접근통제" "양호" \
            "NFS 접근통제가 적절히 설정되어 있습니다."
    fi
else
    print_result "U-25 NFS 접근통제" "양호" \
        "NFS가 설치되어 있지 않습니다."
fi
progress_bar 25 $total_tasks

# U-26 automountd 제거
automount_check=$(systemctl is-active autofs 2>/dev/null)
if [ "$automount_check" = "active" ]; then
    print_result "U-26 automountd 제거" "취약" \
        "automount 서비스가 활성화되어 있습니다." \
        "systemctl stop autofs; systemctl disable autofs 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-26 automountd 제거" "양호" \
        "automount 서비스가 비활성화되어 있습니다."
fi
progress_bar 26 $total_tasks

# U-27 RPC 서비스 확인
rpc_check=$(systemctl is-active rpcbind 2>/dev/null)
if [ "$rpc_check" = "active" ]; then
    print_result "U-27 RPC 서비스 확인" "취약" \
        "RPC 서비스가 활성화되어 있습니다." \
        "systemctl stop rpcbind; systemctl disable rpcbind 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-27 RPC 서비스 확인" "양호" \
        "RPC 서비스가 비활성화되어 있습니다."
fi
progress_bar 27 $total_tasks

# U-28 NIS, NIS+ 점검
nis_check=$(systemctl is-active ypserv 2>/dev/null)
if [ "$nis_check" = "active" ]; then
    print_result "U-28 NIS, NIS+ 점검" "취약" \
        "NIS 서비스가 활성화되어 있습니다." \
        "systemctl stop ypserv; systemctl disable ypserv 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-28 NIS, NIS+ 점검" "양호" \
        "NIS 서비스가 비활성화되어 있습니다."
fi
progress_bar 28 $total_tasks

# U-29 tftp, talk 서비스 비활성화
tftp_check=$(systemctl is-active tftp 2>/dev/null)
talk_check=$(systemctl is-active talk 2>/dev/null)

if [ "$tftp_check" = "active" ] || [ "$talk_check" = "active" ]; then
    print_result "U-29 tftp, talk 서비스 비활성화" "취약" \
        "tftp 또는 talk 서비스가 활성화되어 있습니다." \
        "systemctl stop tftp talk; systemctl disable tftp talk 명령어로 서비스를 중지하고 비활성화하세요."
else
    print_result "U-29 tftp, talk 서비스 비활성화" "양호" \
        "tftp 및 talk 서비스가 비활성화되어 있습니다."
fi
progress_bar 29 $total_tasks

# U-30 Sendmail 버전 점검
sendmail_version=$(sendmail -d0.1 < /dev/null 2>&1 | grep "Version")
if [ -n "$sendmail_version" ]; then
    print_result "U-30 Sendmail 버전 점검" "취약" \
        "Sendmail이 설치되어 있습니다. 최신 버전인지 확인이 필요합니다." \
        "최신 버전의 Sendmail로 업데이트하거나, 필요하지 않다면 제거하세요."
else
    print_result "U-30 Sendmail 버전 점검" "양호" \
        "Sendmail이 설치되어 있지 않습니다."
fi
progress_bar 30 $total_tasks

# U-31 스팸 메일 릴레이 제한
if [ -f "/etc/mail/sendmail.cf" ]; then
    relay_check=$(grep "R$\*" /etc/mail/sendmail.cf | grep "Relaying denied")
    if [ -n "$relay_check" ]; then
        print_result "U-31 스팸 메일 릴레이 제한" "양호" \
            "스팸 메일 릴레이가 제한되어 있습니다."
    else
        print_result "U-31 스팸 메일 릴레이 제한" "취약" \
            "스팸 메일 릴레이 제한이 설정되어 있지 않습니다." \
            "/etc/mail/sendmail.cf 파일에 릴레이 제한 설정을 추가하세요."
    fi
else
    print_result "U-31 스팸 메일 릴레이 제한" "양호" \
        "Sendmail이 설치되어 있지 않습니다."
fi
progress_bar 31 $total_tasks

# U-32 일반사용자의 Sendmail 실행 방지
if [ -f "/etc/mail/sendmail.cf" ]; then
    restrictqrun_check=$(grep -i "restrictqrun" /etc/mail/sendmail.cf)
    if [ -n "$restrictqrun_check" ]; then
        print_result "U-32 일반사용자의 Sendmail 실행 방지" "양호" \
            "일반 사용자의 Sendmail 실행이 제한되어 있습니다."
    else
        print_result "U-32 일반사용자의 Sendmail 실행 방지" "취약" \
            "일반 사용자의 Sendmail 실행이 제한되어 있지 않습니다." \
            "/etc/mail/sendmail.cf 파일에 restrictqrun 옵션을 추가하세요."
    fi
else
    print_result "U-32 일반사용자의 Sendmail 실행 방지" "양호" \
        "Sendmail이 설치되어 있지 않습니다."
fi
progress_bar 32 $total_tasks

# U-33 DNS 보안 버전 패치
named_version=$(named -v 2>/dev/null | grep "BIND")
if [ -n "$named_version" ]; then
    print_result "U-33 DNS 보안 버전 패치" "취약" \
        "DNS 서비스(BIND)가 설치되어 있습니다. 최신 버전인지 확인이 필요합니다." \
        "최신 버전의 BIND로 업데이트하세요."
else
    print_result "U-33 DNS 보안 버전 패치" "양호" \
        "DNS 서비스(BIND)가 설치되어 있지 않습니다."
fi
progress_bar 33 $total_tasks

# U-34 DNS Zone Transfer 설정
if [ -f "/etc/named.conf" ]; then
    zone_transfer_check=$(grep "allow-transfer" /etc/named.conf)
    if [ -n "$zone_transfer_check" ]; then
        print_result "U-34 DNS Zone Transfer 설정" "양호" \
            "DNS Zone Transfer가 제한되어 있습니다."
    else
        print_result "U-34 DNS Zone Transfer 설정" "취약" \
            "DNS Zone Transfer 제한이 설정되어 있지 않습니다." \
            "/etc/named.conf 파일에 allow-transfer 설정을 추가하세요."
    fi
else
    print_result "U-34 DNS Zone Transfer 설정" "양호" \
        "DNS 서비스가 설치되어 있지 않습니다."
fi
progress_bar 34 $total_tasks

# U-35 웹서비스 디렉토리 리스팅 제거
apache_conf="/etc/httpd/conf/httpd.conf"
if [ -f "$apache_conf" ]; then
    directory_listing=$(grep -i "Options.*Indexes" "$apache_conf")
    if [ -n "$directory_listing" ]; then
        print_result "U-35 웹서비스 디렉토리 리스팅 제거" "취약" \
            "디렉토리 리스팅이 활성화되어 있습니다." \
            "httpd.conf 파일에서 Options 지시자에서 Indexes를 제거하세요."
    else
        print_result "U-35 웹서비스 디렉토리 리스팅 제거" "양호" \
            "디렉토리 리스팅이 비활성화되어 있습니다."
    fi
else
    print_result "U-35 웹서비스 디렉토리 리스팅 제거" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 35 $total_tasks

# U-36 웹서비스 웹 프로세스 권한 제한
apache_user=$(grep -i "^User" /etc/httpd/conf/httpd.conf 2>/dev/null | awk '{print $2}')
apache_group=$(grep -i "^Group" /etc/httpd/conf/httpd.conf 2>/dev/null | awk '{print $2}')

if [ -n "$apache_user" ] && [ -n "$apache_group" ]; then
    if [ "$apache_user" != "root" ] && [ "$apache_group" != "root" ]; then
        print_result "U-36 웹서비스 웹 프로세스 권한 제한" "양호" \
            "웹 프로세스가 root 권한으로 실행되지 않습니다."
    else
        print_result "U-36 웹서비스 웹 프로세스 권한 제한" "취약" \
            "웹 프로세스가 root 권한으로 실행되고 있습니다." \
            "httpd.conf 파일에서 User와 Group을 root가 아닌 다른 계정으로 변경하세요."
    fi
else
    print_result "U-36 웹서비스 웹 프로세스 권한 제한" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 36 $total_tasks

# U-37 웹서비스 상위 디렉토리 접근 금지
if [ -f "/etc/httpd/conf/httpd.conf" ]; then
    allowoverride_check=$(grep -i "AllowOverride.*None" /etc/httpd/conf/httpd.conf)
    if [ -n "$allowoverride_check" ]; then
        print_result "U-37 웹서비스 상위 디렉토리 접근 금지" "취약" \
            "상위 디렉토리 접근이 허용될 수 있습니다." \
            "httpd.conf 파일에서 AllowOverride 지시자를 적절히 설정하세요."
    else
        print_result "U-37 웹서비스 상위 디렉토리 접근 금지" "양호" \
            "상위 디렉토리 접근이 제한되어 있습니다."
    fi
else
    print_result "U-37 웹서비스 상위 디렉토리 접근 금지" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 37 $total_tasks

# U-38 웹서비스 불필요한 파일 제거
web_sample_files=$(find /var/www/html -name "manual" -o -name "test.php" 2>/dev/null)
if [ -n "$web_sample_files" ]; then
    print_result "U-38 웹서비스 불필요한 파일 제거" "취약" \
        "웹 서버에 불필요한 샘플 파일이 존재합니다." \
        "불필요한 샘플 파일 및 디렉토리를 제거하세요."
else
    print_result "U-38 웹서비스 불필요한 파일 제거" "양호" \
        "웹 서버에 불필요한 샘플 파일이 없습니다."
fi
progress_bar 38 $total_tasks

# U-39 웹서비스 링크 사용금지
if [ -f "/etc/httpd/conf/httpd.conf" ]; then
    symlinks_check=$(grep -i "FollowSymLinks" /etc/httpd/conf/httpd.conf)
    if [ -n "$symlinks_check" ]; then
        print_result "U-39 웹서비스 링크 사용금지" "취약" \
            "심볼릭 링크 사용이 허용되어 있습니다." \
            "httpd.conf 파일에서 FollowSymLinks 옵션을 제거하세요."
    else
        print_result "U-39 웹서비스 링크 사용금지" "양호" \
            "심볼릭 링크 사용이 제한되어 있습니다."
    fi
else
    print_result "U-39 웹서비스 링크 사용금지" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 39 $total_tasks

# U-40 웹서비스 파일 업로드 및 다운로드 제한
apache_conf="/etc/httpd/conf/httpd.conf"
if [ -f "$apache_conf" ]; then
    limit_check=$(grep -i "LimitRequestBody" "$apache_conf")
    if [ -n "$limit_check" ]; then
        print_result "U-40 웹서비스 파일 업로드 및 다운로드 제한" "양호" \
            "파일 업로드 크기가 제한되어 있습니다."
    else
        print_result "U-40 웹서비스 파일 업로드 및 다운로드 제한" "취약" \
            "파일 업로드 크기 제한이 설정되어 있지 않습니다." \
            "httpd.conf 파일에 LimitRequestBody 지시자를 추가하여 업로드 크기를 제한하세요."
    fi
else
    print_result "U-40 웹서비스 파일 업로드 및 다운로드 제한" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 40 $total_tasks

# U-41 웹서비스 영역의 분리
web_root="/var/www/html"
if [ -d "$web_root" ]; then
    root_check=$(find "$web_root" -type f -perm /o+w)
    if [ -n "$root_check" ]; then
        print_result "U-41 웹서비스 영역의 분리" "취약" \
            "웹 서비스 영역에 다른 사용자가 쓰기 가능한 파일이 있습니다." \
            "웹 서비스 영역의 파일 권한을 적절히 설정하세요."
    else
        print_result "U-41 웹서비스 영역의 분리" "양호" \
            "웹 서비스 영역이 적절히 보호되어 있습니다."
    fi
else
    print_result "U-41 웹서비스 영역의 분리" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 41 $total_tasks

# U-42 최신 보안패치 및 벤더 권고사항 적용
os_version=$(cat /etc/redhat-release 2>/dev/null)
kernel_version=$(uname -r)
print_result "U-42 최신 보안패치 및 벤더 권고사항 적용" "정보" \
    "현재 OS 버전: $os_version\n현재 커널 버전: $kernel_version\n" \
    "주기적으로 보안 업데이트를 확인하고 적용하세요."
progress_bar 42 $total_tasks

# U-43 로그의 정기적 검토 및 보고
if [ -d "/var/log" ]; then
    log_files=$(find /var/log -type f -name "*.log" -mtime +30)
    if [ -n "$log_files" ]; then
        print_result "U-43 로그의 정기적 검토 및 보고" "취약" \
            "30일 이상 검토되지 않은 로그 파일이 존재합니다." \
            "로그 파일을 정기적으로 검토하고 보관 정책을 수립하세요."
    else
        print_result "U-43 로그의 정기적 검토 및 보고" "양호" \
            "로그 파일이 정기적으로 검토되고 있습니다."
    fi
else
    print_result "U-43 로그의 정기적 검토 및 보고" "취약" \
        "로그 디렉터리가 존재하지 않습니다."
fi
progress_bar 43 $total_tasks

# U-44 root 이외의 UID가 '0' 금지
uid_zero_count=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | wc -l)
if [ $uid_zero_count -eq 0 ]; then
    print_result "U-44 root 이외의 UID가 '0' 금지" "양호" \
        "root 이외의 UID가 0인 계정이 없습니다."
else
    print_result "U-44 root 이외의 UID가 '0' 금지" "취약" \
        "root 이외의 계정에 UID 0이 할당되어 있습니다." \
        "해당 계정의 UID를 변경하거나 삭제하세요."
fi
progress_bar 44 $total_tasks

# U-45 root 계정 su 제한
wheel_group_check=$(grep wheel /etc/group)
su_restriction=$(grep pam_wheel.so /etc/pam.d/su)
if [ -n "$wheel_group_check" ] && [ -n "$su_restriction" ]; then
    print_result "U-45 root 계정 su 제한" "양호" \
        "su 명령어 사용이 wheel 그룹으로 제한되어 있습니다."
else
    print_result "U-45 root 계정 su 제한" "취약" \
        "su 명령어 사용제한이 설정되어 있지 않습니다." \
        "wheel 그룹을 생성하고 su 명령어 사용을 제한하세요."
fi
progress_bar 45 $total_tasks

# U-46 패스워드 최소 길이 설정
pass_min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
if [ -n "$pass_min_len" ] && [ "$pass_min_len" -ge 8 ]; then
    print_result "U-46 패스워드 최소 길이 설정" "양호" \
        "패스워드 최소 길이가 8자 이상으로 설정되어 있습니다."
else
    print_result "U-46 패스워드 최소 길이 설정" "취약" \
        "패스워드 최소 길이가 8자 미만으로 설정되어 있습니다." \
        "/etc/login.defs 파일에서 PASS_MIN_LEN 값을 8 이상으로 설정하세요."
fi
progress_bar 46 $total_tasks

# U-47 패스워드 최대 사용기간 설정
pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
    print_result "U-47 패스워드 최대 사용기간 설정" "양호" \
        "패스워드 최대 사용기간이 90일 이하로 설정되어 있습니다."
else
    print_result "U-47 패스워드 최대 사용기간 설정" "취약" \
        "패스워드 최대 사용기간이 90일을 초과하여 설정되어 있습니다." \
        "/etc/login.defs 파일에서 PASS_MAX_DAYS 값을 90 이하로 설정하세요."
fi
progress_bar 47 $total_tasks

# U-48 패스워드 최소 사용기간 설정
pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
if [ -n "$pass_min_days" ] && [ "$pass_min_days" -ge 1 ]; then
    print_result "U-48 패스워드 최소 사용기간 설정" "양호" \
        "패스워드 최소 사용기간이 1일 이상으로 설정되어 있습니다."
else
    print_result "U-48 패스워드 최소 사용기간 설정" "취약" \
        "패스워드 최소 사용기간이 1일 미만으로 설정되어 있습니다." \
        "/etc/login.defs 파일에서 PASS_MIN_DAYS 값을 1 이상으로 설정하세요."
fi
progress_bar 48 $total_tasks

# U-49 불필요한 계정 제거
unnecessary_accounts="lp uucp nuucp"
found_accounts=0
for account in $unnecessary_accounts; do
    if grep -q "^$account:" /etc/passwd; then
        found_accounts=1
        break
    fi
done

if [ $found_accounts -eq 0 ]; then
    print_result "U-49 불필요한 계정 제거" "양호" \
        "불필요한 계정이 존재하지 않습니다."
else
    print_result "U-49 불필요한 계정 제거" "취약" \
        "시스템에 불필요한 계정이 존재합니다." \
        "불필요한 계정을 확인하고 제거하세요."
fi
progress_bar 49 $total_tasks

# U-50 관리자 그룹에 최소한의 계정 포함
admin_group_members=$(grep "^wheel:" /etc/group | cut -d: -f4)
admin_count=$(echo "$admin_group_members" | tr ',' '\n' | wc -l)
if [ "$admin_count" -le 3 ]; then
    print_result "U-50 관리자 그룹에 최소한의 계정 포함" "양호" \
        "관리자 그룹에 포함된 계정이 3개 이하입니다."
else
    print_result "U-50 관리자 그룹에 최소한의 계정 포함" "취약" \
        "관리자 그룹에 너무 많은 계정이 포함되어 있습니다." \
        "불필요한 관리자 권한을 가진 계정을 제거하세요."
fi
progress_bar 50 $total_tasks

# U-51 계정이 존재하지 않는 GID 금지
invalid_gid=0
while read -r line; do
    gid=$(echo "$line" | cut -d: -f3)
    if ! grep -q ":$gid:" /etc/passwd; then
        invalid_gid=1
        break
    fi
done < /etc/group

if [ $invalid_gid -eq 0 ]; then
    print_result "U-51 계정이 존재하지 않는 GID 금지" "양호" \
        "존재하지 않는 계정에 할당된 GID가 없습니다."
else
    print_result "U-51 계정이 존재하지 않는 GID 금지" "취약" \
        "존재하지 않는 계정에 할당된 GID가 있습니다." \
        "불필요한 GID를 확인하고 제거하세요."
fi
progress_bar 51 $total_tasks

# U-52 동일한 UID 금지
duplicate_uid=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
if [ -z "$duplicate_uid" ]; then
    print_result "U-52 동일한 UID 금지" "양호" \
        "동일한 UID를 공유하는 사용자 계정이 없습니다."
else
    print_result "U-52 동일한 UID 금지" "취약" \
        "동일한 UID를 공유하는 사용자 계정이 있습니다." \
        "중복된 UID를 가진 계정을 확인하고 수정하세요."
fi
progress_bar 52 $total_tasks

# U-53 사용자 shell 점검
invalid_shells=0
while IFS=: read -r username _ _ _ _ _ shell; do
    if [ "$shell" = "/bin/bash" ] || [ "$shell" = "/bin/sh" ]; then
        if ! grep -q "^$username:" /etc/passwd; then
            invalid_shells=1
            break
        fi
    fi
done < /etc/passwd

if [ $invalid_shells -eq 0 ]; then
    print_result "U-53 사용자 shell 점검" "양호" \
        "모든 사용자의 shell이 적절하게 설정되어 있습니다."
else
    print_result "U-53 사용자 shell 점검" "취약" \
        "부적절한 shell이 설정된 계정이 있습니다." \
        "불필요한 계정의 shell을 /bin/false 또는 /sbin/nologin으로 변경하세요."
fi
progress_bar 53 $total_tasks

# U-54 Session Timeout 설정
timeout_set=0
for profile in /etc/profile /etc/bashrc $HOME/.bashrc; do
    if [ -f "$profile" ]; then
        if grep -q "TMOUT=" "$profile"; then
            timeout_set=1
            break
        fi
    fi
done

if [ $timeout_set -eq 1 ]; then
    print_result "U-54 Session Timeout 설정" "양호" \
        "Session Timeout이 설정되어 있습니다."
else
    print_result "U-54 Session Timeout 설정" "취약" \
        "Session Timeout이 설정되어 있지 않습니다." \
        "/etc/profile 파일에 TMOUT=600 설정을 추가하세요."
fi
progress_bar 54 $total_tasks

# U-55 hosts.lpd 파일 소유자 및 권한 설정
if [ -f "/etc/hosts.lpd" ]; then
    owner=$(stat -c %U /etc/hosts.lpd)
    perm=$(stat -c %a /etc/hosts.lpd)
    if [ "$owner" = "root" ] && [ "$perm" = "600" ]; then
        print_result "U-55 hosts.lpd 파일 소유자 및 권한 설정" "양호" \
            "hosts.lpd 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        print_result "U-55 hosts.lpd 파일 소유자 및 권한 설정" "취약" \
            "hosts.lpd 파일의 소유자가 root가 아니거나 권한이 600이 아닙니다." \
            "chown root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd 명령어로 설정을 변경하세요."
    fi
else
    print_result "U-55 hosts.lpd 파일 소유자 및 권한 설정" "양호" \
        "hosts.lpd 파일이 존재하지 않습니다."
fi
progress_bar 55 $total_tasks

# U-56 UMASK 설정 관리
umask_check=0
for profile in /etc/profile /etc/bashrc; do
    if [ -f "$profile" ]; then
        if grep -q "umask 022" "$profile" || grep -q "umask 027" "$profile"; then
            umask_check=1
            break
        fi
    fi
done

if [ $umask_check -eq 1 ]; then
    print_result "U-56 UMASK 설정 관리" "양호" \
        "UMASK가 적절히 설정되어 있습니다."
else
    print_result "U-56 UMASK 설정 관리" "취약" \
        "UMASK가 적절히 설정되어 있지 않습니다." \
        "/etc/profile 파일에 umask 022 또는 umask 027을 설정하세요."
fi
progress_bar 56 $total_tasks

# U-57 홈디렉토리 소유자 및 권한 설정
home_vuln=0
while IFS=: read -r username _ _ _ _ home_dir _; do
    if [ -d "$home_dir" ] && [ "$home_dir" != "/" ]; then
        owner=$(stat -c %U "$home_dir")
        perm=$(stat -c %a "$home_dir")
        if [ "$owner" != "$username" ] || [ "$perm" -gt "755" ]; then
            home_vuln=1
            break
        fi
    fi
done < /etc/passwd

if [ $home_vuln -eq 0 ]; then
    print_result "U-57 홈디렉토리 소유자 및 권한 설정" "양호" \
        "모든 홈디렉토리의 소유자와 권한이 적절히 설정되어 있습니다."
else
    print_result "U-57 홈디렉토리 소유자 및 권한 설정" "취약" \
        "부적절한 소유자나 권한이 설정된 홈디렉토리가 있습니다." \
        "홈디렉토리의 소유자와 권한을 적절히 설정하세요."
fi
progress_bar 57 $total_tasks

# U-58 홈디렉토리로 지정한 디렉토리의 존재 관리
missing_home=0
while IFS=: read -r username _ _ _ _ home_dir _; do
    if [ "$home_dir" != "/" ] && [ ! -d "$home_dir" ]; then
        missing_home=1
        break
    fi
done < /etc/passwd

if [ $missing_home -eq 0 ]; then
    print_result "U-58 홈디렉토리로 지정한 디렉토리의 존재 관리" "양호" \
        "모든 사용자의 홈디렉토리가 존재합니다."
else
    print_result "U-58 홈디렉토리로 지정한 디렉토리의 존재 관리" "취약" \
        "존재하지 않는 홈디렉토리가 지정된 계정이 있습니다." \
        "누락된 홈디렉토리를 생성하거나 해당 계정을 수정하세요."
fi
progress_bar 58 $total_tasks

# U-59 숨겨진 파일 및 디렉토리 검색 및 제거
hidden_files=$(find / -name ".*" -type f -ls 2>/dev/null)
if [ -z "$hidden_files" ]; then
    print_result "U-59 숨겨진 파일 및 디렉토리 검색 및 제거" "양호" \
        "불필요한 숨겨진 파일이 발견되지 않았습니다."
else
    print_result "U-59 숨겨진 파일 및 디렉토리 검색 및 제거" "취약" \
        "숨겨진 파일이 발견되었습니다." \
        "불필요한 숨겨진 파일을 검토하고 제거하세요."
fi
progress_bar 59 $total_tasks

# U-60 ssh 원격접속 허용
ssh_config="/etc/ssh/sshd_config"
if [ -f "$ssh_config" ]; then
    protocol_check=$(grep "^Protocol" "$ssh_config" | awk '{print $2}')
    if [ "$protocol_check" = "2" ]; then
        print_result "U-60 ssh 원격접속 허용" "양호" \
            "SSH 프로토콜 버전 2만 사용하도록 설정되어 있습니다."
    else
        print_result "U-60 ssh 원격접속 허용" "취약" \
            "SSH 프로토콜 설정이 취약합니다." \
            "sshd_config 파일에서 Protocol 2로 설정하세요."
    fi
else
    print_result "U-60 ssh 원격접속 허용" "취약" \
        "SSH 서버가 설치되어 있지 않습니다."
fi
progress_bar 60 $total_tasks

# U-61 FTP 서비스 구동 점검
ftp_check=$(systemctl is-active vsftpd 2>/dev/null)
if [ "$ftp_check" = "active" ]; then
    print_result "U-61 FTP 서비스 구동 점검" "취약" \
        "FTP 서비스가 활성화되어 있습니다." \
        "불필요한 FTP 서비스를 비활성화하세요."
else
    print_result "U-61 FTP 서비스 구동 점검" "양호" \
        "FTP 서비스가 비활성화되어 있습니다."
fi
progress_bar 61 $total_tasks

# U-62 FTP 계정 shell 제한
ftp_accounts=$(grep -i "^ftp" /etc/passwd)
if [ -n "$ftp_accounts" ]; then
    ftp_shell=$(echo "$ftp_accounts" | awk -F: '{print $7}')
    if [ "$ftp_shell" = "/sbin/nologin" ] || [ "$ftp_shell" = "/bin/false" ]; then
        print_result "U-62 FTP 계정 shell 제한" "양호" \
            "FTP 계정의 shell이 적절히 제한되어 있습니다."
    else
        print_result "U-62 FTP 계정 shell 제한" "취약" \
            "FTP 계정의 shell이 제한되어 있지 않습니다." \
            "FTP 계정의 shell을 /sbin/nologin 또는 /bin/false로 변경하세요."
    fi
else
    print_result "U-62 FTP 계정 shell 제한" "양호" \
        "FTP 계정이 존재하지 않습니다."
fi
progress_bar 62 $total_tasks

# U-63 ftpusers 파일 소유자 및 권한 설정
ftpusers="/etc/ftpusers"
if [ -f "$ftpusers" ]; then
    owner=$(stat -c %U "$ftpusers")
    perm=$(stat -c %a "$ftpusers")
    if [ "$owner" = "root" ] && [ "$perm" = "600" ]; then
        print_result "U-63 ftpusers 파일 소유자 및 권한 설정" "양호" \
            "ftpusers 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        print_result "U-63 ftpusers 파일 소유자 및 권한 설정" "취약" \
            "ftpusers 파일의 소유자가 root가 아니거나 권한이 600이 아닙니다." \
            "chown root /etc/ftpusers; chmod 600 /etc/ftpusers 명령어로 설정을 변경하세요."
    fi
else
    print_result "U-63 ftpusers 파일 소유자 및 권한 설정" "양호" \
        "ftpusers 파일이 존재하지 않습니다."
fi
progress_bar 63 $total_tasks

# U-64 FTP 서비스 root 계정 접근제한
if [ -f "$ftpusers" ]; then
    if grep -q "^root" "$ftpusers"; then
        print_result "U-64 FTP 서비스 root 계정 접근제한" "양호" \
            "root 계정의 FTP 접근이 제한되어 있습니다."
    else
        print_result "U-64 FTP 서비스 root 계정 접근제한" "취약" \
            "root 계정의 FTP 접근이 제한되어 있지 않습니다." \
            "ftpusers 파일에 root 계정을 추가하세요."
    fi
else
    print_result "U-64 FTP 서비스 root 계정 접근제한" "양호" \
        "FTP 서비스가 설치되어 있지 않습니다."
fi
progress_bar 64 $total_tasks

# U-65 at 파일 소유자 및 권한 설정
at_dirs="/etc/at.allow /etc/at.deny"
at_vuln=0
for file in $at_dirs; do
    if [ -f "$file" ]; then
        owner=$(stat -c %U "$file")
        perm=$(stat -c %a "$file")
        if [ "$owner" != "root" ] || [ "$perm" != "640" ]; then
            at_vuln=1
            break
        fi
    fi
done

if [ $at_vuln -eq 0 ]; then
    print_result "U-65 at 파일 소유자 및 권한 설정" "양호" \
        "at 관련 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
else
    print_result "U-65 at 파일 소유자 및 권한 설정" "취약" \
        "at 관련 파일의 소유자가 root가 아니거나 권한이 640이 아닙니다." \
        "at 관련 파일의 소유자를 root로, 권한을 640으로 변경하세요."
fi
progress_bar 65 $total_tasks

# U-66 SNMP 서비스 구동 점검
snmp_check=$(systemctl is-active snmpd 2>/dev/null)
if [ "$snmp_check" = "active" ]; then
    print_result "U-66 SNMP 서비스 구동 점검" "취약" \
        "SNMP 서비스가 활성화되어 있습니다." \
        "불필요한 SNMP 서비스를 비활성화하세요."
else
    print_result "U-66 SNMP 서비스 구동 점검" "양호" \
        "SNMP 서비스가 비활성화되어 있습니다."
fi
progress_bar 66 $total_tasks

# U-67 SNMP 서비스 커뮤니티스트링의 복잡성 설정
if [ -f "/etc/snmp/snmpd.conf" ]; then
    community_check=$(grep -i "^com2sec" /etc/snmp/snmpd.conf | grep -i "public\|private")
    if [ -n "$community_check" ]; then
        print_result "U-67 SNMP 서비스 커뮤니티스트링의 복잡성 설정" "취약" \
            "기본 커뮤니티스트링이 사용되고 있습니다." \
            "SNMP 커뮤니티스트링을 복잡한 문자열로 변경하세요."
    else
        print_result "U-67 SNMP 서비스 커뮤니티스트링의 복잡성 설정" "양호" \
            "기본 커뮤니티스트링이 사용되지 않고 있습니다."
    fi
else
    print_result "U-67 SNMP 서비스 커뮤니티스트링의 복잡성 설정" "양호" \
        "SNMP 서비스가 설치되어 있지 않습니다."
fi
progress_bar 67 $total_tasks

# U-68 로그온 시 경고메시지 제공
warning_files="/etc/issue.net /etc/motd"
warning_set=0
for file in $warning_files; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        warning_set=1
        break
    fi
done

if [ $warning_set -eq 1 ]; then
    print_result "U-68 로그온 시 경고메시지 제공" "양호" \
        "로그온 경고메시지가 설정되어 있습니다."
else
    print_result "U-68 로그온 시 경고메시지 제공" "취약" \
        "로그온 경고메시지가 설정되어 있지 않습니다." \
        "/etc/issue.net 또는 /etc/motd 파일에 적절한 경고메시지를 설정하세요."
fi
progress_bar 68 $total_tasks

# U-69 NFS 설정파일 접근권한
nfs_conf="/etc/exports"
if [ -f "$nfs_conf" ]; then
    nfs_perm=$(stat -c %a "$nfs_conf")
    if [ "$nfs_perm" -le "644" ]; then
        print_result "U-69 NFS 설정파일 접근권한" "양호" \
            "NFS 설정파일의 권한이 적절히 설정되어 있습니다."
    else
        print_result "U-69 NFS 설정파일 접근권한" "취약" \
            "NFS 설정파일의 권한이 너무 허용적입니다." \
            "chmod 644 /etc/exports 명령어로 권한을 제한하세요."
    fi
else
    print_result "U-69 NFS 설정파일 접근권한" "양호" \
        "NFS 서비스가 설치되어 있지 않습니다."
fi
progress_bar 69 $total_tasks

# U-70 expn, vrfy 명령어 제한
if [ -f "/etc/postfix/main.cf" ]; then
    smtp_check=$(grep -E "^disable_vrfy_command|^disable_expn_command" /etc/postfix/main.cf)
    if [ -n "$smtp_check" ]; then
        print_result "U-70 expn, vrfy 명령어 제한" "양호" \
            "SMTP 서비스에서 expn/vrfy 명령어가 제한되어 있습니다."
    else
        print_result "U-70 expn, vrfy 명령어 제한" "취약" \
            "SMTP 서비스에서 expn/vrfy 명령어가 제한되어 있지 않습니다." \
            "/etc/postfix/main.cf 파일에 disable_vrfy_command=yes를 추가하세요."
    fi
else
    print_result "U-70 expn, vrfy 명령어 제한" "양호" \
        "SMTP 서비스가 설치되어 있지 않습니다."
fi
progress_bar 70 $total_tasks

# U-71 Apache 웹서비스 정보 숨김
if [ -f "/etc/httpd/conf/httpd.conf" ]; then
    server_tokens=$(grep -i "ServerTokens" /etc/httpd/conf/httpd.conf)
    server_signature=$(grep -i "ServerSignature" /etc/httpd/conf/httpd.conf)
    if [[ "$server_tokens" =~ "Prod" ]] && [[ "$server_signature" =~ "Off" ]]; then
        print_result "U-71 Apache 웹서비스 정보 숨김" "양호" \
            "Apache 버전 정보가 숨겨져 있습니다."
    else
        print_result "U-71 Apache 웹서비스 정보 숨김" "취약" \
            "Apache 버전 정보가 노출될 수 있습니다." \
            "httpd.conf 파일에 ServerTokens Prod와 ServerSignature Off를 설정하세요."
    fi
else
    print_result "U-71 Apache 웹서비스 정보 숨김" "양호" \
        "Apache 웹 서버가 설치되어 있지 않습니다."
fi
progress_bar 71 $total_tasks

# U-72 정책에 따른 시스템 로깅 설정
if [ -f "/etc/rsyslog.conf" ]; then
    auth_log=$(grep -E "auth\.\*|authpriv\.\*" /etc/rsyslog.conf)
    if [ -n "$auth_log" ]; then
        print_result "U-72 정책에 따른 시스템 로깅 설정" "양호" \
            "로그 기록 정책이 적절히 설정되어 있습니다."
    else
        print_result "U-72 정책에 따른 시스템 로깅 설정" "취약" \
            "로그 기록 정책이 미흡합니다." \
            "/etc/rsyslog.conf 파일에 적절한 로깅 설정을 추가하세요."
    fi
else
    print_result "U-72 정책에 따른 시스템 로깅 설정" "취약" \
        "rsyslog가 설치되어 있지 않습니다."
fi
progress_bar 72 $total_tasks

# U-73 정책에 따른 시스템 백업 설정
backup_check=0
cron_backup=$(find /etc/cron.* -type f -exec grep -l "backup" {} \;)
if [ -n "$cron_backup" ]; then
    backup_check=1
fi

if [ $backup_check -eq 1 ]; then
    print_result "U-73 정책에 따른 시스템 백업 설정" "양호" \
        "정기적인 백업이 설정되어 있습니다."
else
    print_result "U-73 정책에 따른 시스템 백업 설정" "취약" \
        "정기적인 백업이 설정되어 있지 않습니다." \
        "cron을 이용하여 정기적인 백업 작업을 설정하세요."
fi
progress_bar 73 $total_tasks

# 마지막에 전체 요약 출력
echo $bline
echo -e "\n                   \e[31m취약점 진단 결과 요약\e[0m\n"
echo $bline
echo -e "\n전체 점검 항목 수: $total_tasks"
echo -e "\e[32m양호 항목 수: $good_count\e[0m"
echo -e "\e[31m취약 항목 수: $vuln_count\e[0m"
echo -e "\n취약점 비율: $(( (vuln_count * 100) / total_tasks ))%"
echo $bline



