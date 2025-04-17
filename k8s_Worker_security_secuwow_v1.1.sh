#!/bin/bash

# 출력 파일 경로 설정
OUTPUT_FILE="/tmp/k8s_worker/k8s_W_secuwow_$(date +%Y%m%d).txt"

# 이전 결과 파일이 있다면 삭제
[ -f "$OUTPUT_FILE" ] && rm "$OUTPUT_FILE"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# 터미널과 파일에 동시에 출력하는 함수
print_output() {
    local terminal_output="$1"
    local file_output="$2"
    
    # 터미널에는 색상과 함께 출력하고 67자 너비로 줄바꿈
    echo -e "$terminal_output" | fold -w 67 -s
    # 파일에는 색상 코드를 제거하고 출력하고 67자 너비로 줄바꿈
    echo -e "$file_output" | fold -w 67 -s >> "$OUTPUT_FILE"
}

# ASCII 아트 로고 출력
print_logo() {
    echo -e "\033[34m"  # 파란색
    echo ' ███████ ███████  ██████ ██    ██ ██     ██  ██████  ██     ██' | tee -a "$OUTPUT_FILE"
    echo ' ██      ██      ██      ██    ██ ██     ██ ██    ██ ██     ██' | tee -a "$OUTPUT_FILE"
    echo ' ███████ █████   ██      ██    ██ ██  █  ██ ██    ██ ██  █  ██' | tee -a "$OUTPUT_FILE"
    echo '      ██ ██      ██      ██    ██ ██ ███ ██ ██    ██ ██ ███ ██' | tee -a "$OUTPUT_FILE"
    echo ' ███████ ███████  ██████  ██████   ███ ███   ██████   ███ ███ ' | tee -a "$OUTPUT_FILE"
    echo -e "\033[36m"  # 청록색
    echo '       Secuwow Kubernetes Security Compliance Check Tool v1.1' | tee -a "$OUTPUT_FILE"
    echo -e "\033[0m"   # 색상 초기화
    print_output '===================================================================' \
                '==================================================================='
    echo
}

# 개발 모드 기본값 설정
DEV_MODE=false

# 명령행 인자 처리
while getopts "d" opt; do
  case $opt in
    d)
      DEV_MODE=true
      ;;
    \?)
      echo "올바르지 않은 옵션: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# 루트 권한 체크
if [ "$(id -u)" != "0" ]; then
    echo "이 스크립트는 루트 권한으로 실행해야 합니다."
    exit 1
fi

# kubernetes 설치 여부 체크 (개발 모드가 아닐 때만)
if [ "$DEV_MODE" = false ]; then
    command -v kubectl >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Kubernetes가 설치되어 있지 않습니다."
        exit 1
    fi
else
    echo -e "\n[개발 모드] Kubernetes 설치 체크를 건너뜁니다."
fi

# 결과 카운터 초기화
total_checks=0
pass_checks=0
fail_checks=0

# 구분선 함수
print_line() {
    print_output "===================================================================" \
                "==================================================================="
}

# 결과 출력 함수
print_result() {
    local check_name=$1
    local status=$2
    local detail=$3
    local recommendation=$4

    print_line
    print_output "<DETAIL>" "<DETAIL>"
    print_output "$detail" "$detail"
    
    # 상태에 따른 색상 및 메시지 설정
    case "$status" in
        "양호")
            color="${GREEN}"
            message="$check_name이 적절하게 설정되어 있습니다."
            ;;
        "취약")
            color="${RED}"
            message="$check_name이 적절하게 설정되어 있지 않습니다."
            ;;
        "부분만족")
            color="${YELLOW}"
            message="$check_name이 일부만 적절하게 설정되어 있습니다."
            ;;
        "N/A")
            color="${BLUE}"
            message="$check_name에 대한 진단이 필요하지 않습니다."
            ;;
        "인터뷰")
            color="${CYAN}"
            message="$check_name에 대한 추가 확인이 필요합니다."
            ;;
        *)
            color="${NC}"
            message="$check_name의 상태를 확인할 수 없습니다."
            ;;
    esac
    
    print_output "<RESULT>${color}$status${NC}" "<RESULT>$status"
    print_output "$message\n" "$message\n"
    
    if [ "$status" == "양호" ]; then
        pass_checks=$((pass_checks + 1))
    elif [ "$status" == "취약" ]; then
        fail_checks=$((fail_checks + 1))
    fi
    
    if [ ! -z "$recommendation" ]; then
        print_output "$recommendation" "$recommendation"
    fi
    
    print_output "<END>" "<END>"
    total_checks=$((total_checks + 1))
}

# Kubelet 인증 제어 검사
check_kubelet_auth() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # Kubelet service 파일 검사
    local service_file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
    local config_file="/var/lib/kubelet/config.yaml"
    
    detail+="[ 현재 설정 상태 ]\n"
    detail+="# cat $service_file\n"
    if [ -f "$service_file" ]; then
        detail+="$(cat $service_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    detail+="# cat $config_file\n"
    if [ -f "$config_file" ]; then
        detail+="$(cat $config_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    # Service 파일 검사
    if [ -f "$service_file" ]; then
        local anonymous_auth_service=$(grep "anonymous-auth" "$service_file" | grep -v "#")
        local readonly_port_service=$(grep "read-only-port" "$service_file" | grep -v "#")
        
        if [ -z "$anonymous_auth_service" ] || ! echo "$anonymous_auth_service" | grep -q "false"; then
            is_secure=false
        fi
        
        if [ -z "$readonly_port_service" ] || ! echo "$readonly_port_service" | grep -q "=0"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi
    
    # Config 파일 검사
    if [ -f "$config_file" ]; then
        local anonymous_auth_config=$(grep "anonymousAuth:" "$config_file" | grep -v "#")
        local readonly_port_config=$(grep "readOnlyPort:" "$config_file" | grep -v "#")
        
        if [ -z "$anonymous_auth_config" ] || echo "$anonymous_auth_config" | grep -q "true"; then
            is_secure=false
        fi
        
        if [ -z "$readonly_port_config" ] || ! echo "$readonly_port_config" | grep -q ": 0"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi

    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        if [ -f "$service_file" ]; then
            local anonymous_auth_service=$(grep "anonymous-auth" "$service_file" | grep -v "#")
            local readonly_port_service=$(grep "read-only-port" "$service_file" | grep -v "#")
            
            if [ -z "$anonymous_auth_service" ] || ! echo "$anonymous_auth_service" | grep -q "false"; then
                detail+="- Service 파일에서 anonymous-auth=false 설정이 없거나 잘못 설정됨\n"
            fi
            
            if [ -z "$readonly_port_service" ] || ! echo "$readonly_port_service" | grep -q "=0"; then
                detail+="- Service 파일에서 read-only-port=0 설정이 없거나 잘못 설정됨\n"
            fi
        else
            detail+="- Kubelet service 파일($service_file)이 존재하지 않음\n"
        fi
        
        if [ -f "$config_file" ]; then
            local anonymous_auth_config=$(grep "anonymousAuth:" "$config_file" | grep -v "#")
            local readonly_port_config=$(grep "readOnlyPort:" "$config_file" | grep -v "#")
            
            if [ -z "$anonymous_auth_config" ] || echo "$anonymous_auth_config" | grep -q "true"; then
                detail+="- Config 파일에서 anonymousAuth가 true로 설정됨\n"
            fi
            
            if [ -z "$readonly_port_config" ] || ! echo "$readonly_port_config" | grep -q ": 0"; then
                detail+="- Config 파일에서 readOnlyPort가 0이 아님\n"
            fi
        else
            detail+="- Kubelet config 파일($config_file)이 존재하지 않음\n"
        fi

        recommendation="[진단 방법]\n"
        recommendation+="1. Kubelet service 파일을 사용하는 경우\n"
        recommendation+="   $ cat $service_file | grep \"anonymous-auth\\|read-only-port\" | grep -v \"#\"\n\n"
        recommendation+="2. Kubelet config 파일을 사용하는 경우\n"
        recommendation+="   $ cat $config_file\n\n"
        recommendation+="[조치 방법]\n"
        recommendation+="1. Kubelet service 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $service_file\n"
        recommendation+="   Environment=\"KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false --read-only-port=0\" 설정 추가\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="2. Kubelet config 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $config_file\n"
        recommendation+="   anonymousAuth: false\n"
        recommendation+="   readOnlyPort: 0\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="[보안 위험]\n"
        recommendation+="1. 비인가자가 Kubelet API에 접근할 수 있습니다.\n"
        recommendation+="2. Pod와 컨테이너의 정보가 노출될 수 있습니다.\n"
        recommendation+="3. 리소스 수정이 가능합니다."
    fi

    if [ "$is_secure" = true ]; then
        print_result "Kubelet 인증 제어" "양호" \
            "Kubelet 비인증 접근이 적절히 차단되어 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "Kubelet 인증 제어" "취약" \
            "Kubelet 비인증 접근이 허용되어 있습니다.\n\n$detail" \
            "$recommendation"
    fi
}

# Kubelet 권한 제어 검사
check_kubelet_authorization() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # Kubelet service 파일 검사
    local service_file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
    local config_file="/var/lib/kubelet/config.yaml"
    
    detail+="[ 현재 설정 상태 ]\n"
    detail+="# cat $service_file\n"
    if [ -f "$service_file" ]; then
        detail+="$(cat $service_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    detail+="# cat $config_file\n"
    if [ -f "$config_file" ]; then
        detail+="$(cat $config_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    # Service 파일 검사
    if [ -f "$service_file" ]; then
        local auth_mode_service=$(grep "authorization-mode" "$service_file" | grep -v "#")
        
        if [ -z "$auth_mode_service" ]; then
            is_secure=false
        elif echo "$auth_mode_service" | grep -q "AlwaysAllow"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi
    
    # Config 파일 검사
    if [ -f "$config_file" ]; then
        local auth_mode_config=$(grep "authorization:" -A 5 "$config_file" | grep "mode:" | grep -v "#")
        
        if [ -z "$auth_mode_config" ]; then
            is_secure=false
        elif echo "$auth_mode_config" | grep -q "AlwaysAllow"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi

    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        if [ -f "$service_file" ]; then
            local auth_mode_service=$(grep "authorization-mode" "$service_file" | grep -v "#")
            
            if [ -z "$auth_mode_service" ]; then
                detail+="- Service 파일에서 authorization-mode 설정이 없음\n"
            elif echo "$auth_mode_service" | grep -q "AlwaysAllow"; then
                detail+="- Service 파일에서 authorization-mode가 AlwaysAllow로 설정됨\n"
            fi
        else
            detail+="- Kubelet service 파일($service_file)이 존재하지 않음\n"
        fi
        
        if [ -f "$config_file" ]; then
            local auth_mode_config=$(grep "authorization:" -A 5 "$config_file" | grep "mode:" | grep -v "#")
            
            if [ -z "$auth_mode_config" ]; then
                detail+="- Config 파일에서 authorization.mode 설정이 없음\n"
            elif echo "$auth_mode_config" | grep -q "AlwaysAllow"; then
                detail+="- Config 파일에서 authorization.mode가 AlwaysAllow로 설정됨\n"
            fi
        else
            detail+="- Kubelet config 파일($config_file)이 존재하지 않음\n"
        fi

        recommendation="[조치 방법]\n"
        recommendation+="1. Kubelet service 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $service_file\n"
        recommendation+="   Environment=\"KUBELET_SYSTEM_PODS_ARGS=--authorization-mode=Webhook\" 설정 추가\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="2. Kubelet config 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $config_file\n"
        recommendation+="   authorization:\n"
        recommendation+="     mode: Webhook\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="[보안 위험]\n"
        recommendation+="1. 권한이 없는 사용자가 Kubelet API에 접근할 수 있습니다.\n"
        recommendation+="2. 시스템 리소스에 대한 무단 접근이 가능합니다.\n"
        recommendation+="3. 악의적인 사용자가 시스템 설정을 변경할 수 있습니다."
    fi

    if [ "$is_secure" = true ]; then
        print_result "Kubelet 권한 제어" "양호" \
            "API server 권한이 적절하게 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "Kubelet 권한 제어" "취약" \
            "API server 권한이 AlwaysAllow로 설정되어 있거나 설정이 없어 모든 요청이 허용됩니다.\n\n$detail" \
            "$recommendation"
    fi
}

# Kubelet SSL/TLS 적용 검사
check_kubelet_ssl_tls() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # 설정 파일 경로
    local service_file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
    local config_file="/var/lib/kubelet/config.yaml"
    
    detail+="[ 현재 설정 상태 ]\n"
    detail+="# cat $service_file\n"
    if [ -f "$service_file" ]; then
        detail+="$(cat $service_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    detail+="# cat $config_file\n"
    if [ -f "$config_file" ]; then
        detail+="$(cat $config_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    # Config 파일 검사
    if [ -f "$config_file" ]; then
        # 클라이언트 CA 인증서 설정 확인
        local client_ca=$(grep "clientCAFile:" "$config_file" | grep -v "#")
        if [ -z "$client_ca" ]; then
            is_secure=false
        fi
        
        # TLS 인증서와 Private key 설정 확인
        local tls_cert=$(grep "tlsCertFile:" "$config_file" | grep -v "#")
        local tls_key=$(grep "tlsPrivateKeyFile:" "$config_file" | grep -v "#")
        if [ -z "$tls_cert" ] || [ -z "$tls_key" ]; then
            is_secure=false
        fi
        
        # TLS Cipher Suites 설정 확인
        local tls_cipher=$(grep -A 8 "TLSCipherSuites:" "$config_file" | grep -v "#")
        if [ -z "$tls_cipher" ]; then
            is_secure=false
        fi
    else
        is_secure=false
    fi
    
    # Service 파일 검사
    if [ -f "$service_file" ]; then
        # hostname-override 설정 확인
        local hostname_override=$(grep "hostname-override" "$service_file" | grep -v "#")
        if [ ! -z "$hostname_override" ]; then
            is_secure=false
        fi
    else
        is_secure=false
    fi

    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        if [ -f "$config_file" ]; then
            # 클라이언트 CA 인증서 설정 확인
            local client_ca=$(grep "clientCAFile:" "$config_file" | grep -v "#")
            if [ -z "$client_ca" ]; then
                detail+="- 클라이언트 CA 인증서 설정이 없음\n"
            fi
            
            # TLS 인증서와 Private key 설정 확인
            local tls_cert=$(grep "tlsCertFile:" "$config_file" | grep -v "#")
            local tls_key=$(grep "tlsPrivateKeyFile:" "$config_file" | grep -v "#")
            if [ -z "$tls_cert" ] || [ -z "$tls_key" ]; then
                detail+="- TLS 인증서 또는 Private key 설정이 없음\n"
            fi
            
            # TLS Cipher Suites 설정 확인
            local tls_cipher=$(grep -A 8 "TLSCipherSuites:" "$config_file" | grep -v "#")
            if [ -z "$tls_cipher" ]; then
                detail+="- TLS Cipher Suites 설정이 없음\n"
            fi
        else
            detail+="- Kubelet config 파일($config_file)이 존재하지 않음\n"
        fi
        
        if [ -f "$service_file" ]; then
            # hostname-override 설정 확인
            local hostname_override=$(grep "hostname-override" "$service_file" | grep -v "#")
            if [ ! -z "$hostname_override" ]; then
                detail+="- hostname-override 설정이 존재함 (보안 취약)\n"
            fi
        else
            detail+="- Kubelet service 파일($service_file)이 존재하지 않음\n"
        fi

        recommendation="[조치 방법]\n"
        recommendation+="1. Kubelet config 파일 설정:\n"
        recommendation+="   $ vi $config_file\n"
        recommendation+="   clientCAFile: /etc/kubernetes/pki/ca.crt\n"
        recommendation+="   tlsCertFile: /etc/kubernetes/pki/kubelet-client-current.pem\n"
        recommendation+="   tlsPrivateKeyFile: /etc/kubernetes/pki/kubelet-client-current.pem\n"
        recommendation+="   TLSCipherSuites:\n"
        recommendation+="     - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n"
        recommendation+="     - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n"
        recommendation+="     - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305\n"
        recommendation+="     - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
        recommendation+="     - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305\n"
        recommendation+="     - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n"
        recommendation+="     - TLS_RSA_WITH_AES_256_GCM_SHA384\n"
        recommendation+="     - TLS_RSA_WITH_AES_128_GCM_SHA256\n\n"
        recommendation+="2. Service 파일 설정:\n"
        recommendation+="   $ vi $service_file\n"
        recommendation+="   hostname-override 설정이 있다면 제거\n\n"
        recommendation+="3. 설정 적용:\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="[보안 위험]\n"
        recommendation+="1. SSL/TLS 통신이 적용되지 않아 민감한 데이터가 평문으로 전송될 수 있습니다.\n"
        recommendation+="2. 안전하지 않은 cipher suite 사용으로 통신이 노출될 수 있습니다.\n"
        recommendation+="3. hostname 변경 설정으로 인해 잘못된 노드 인증이 발생할 수 있습니다."
    fi

    if [ "$is_secure" = true ]; then
        print_result "Kubelet SSL/TLS 적용" "양호" \
            "SSL/TLS 통신이 적절하게 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "Kubelet SSL/TLS 적용" "취약" \
            "SSL/TLS 통신 설정이 미흡합니다. (인증서, 비밀키, cipher suite 설정 부재 또는 hostname-override 설정 존재)\n\n$detail" \
            "$recommendation"
    fi
}

# Kubelet Kernel 파라미터 설정 검사
check_kubelet_kernel_params() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # 설정 파일 경로
    local service_file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
    local config_file="/var/lib/kubelet/config.yaml"
    
    detail+="[ 현재 설정 상태 ]\n"
    detail+="# cat $service_file | grep \"protect-kernel-defaults\" | grep -v \"#\"\n"
    if [ -f "$service_file" ]; then
        local protect_kernel=$(grep "protect-kernel-defaults" "$service_file" | grep -v "#")
        if [ ! -z "$protect_kernel" ]; then
            detail+="$protect_kernel\n\n"
        else
            detail+="설정이 없습니다.\n\n"
        fi
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    detail+="# cat $config_file\n"
    if [ -f "$config_file" ]; then
        detail+="$(cat $config_file)\n\n"
    else
        detail+="파일이 존재하지 않습니다.\n\n"
    fi
    
    # Service 파일 검사
    if [ -f "$service_file" ]; then
        local protect_kernel=$(grep "protect-kernel-defaults" "$service_file" | grep -v "#")
        
        if [ -z "$protect_kernel" ]; then
            is_secure=false
        elif ! echo "$protect_kernel" | grep -q "=true"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi
    
    # Config 파일 검사
    if [ -f "$config_file" ]; then
        local protect_kernel_config=$(grep "protectKernelDefaults:" "$config_file" | grep -v "#")
        
        if [ -z "$protect_kernel_config" ]; then
            is_secure=false
        elif ! echo "$protect_kernel_config" | grep -q "true"; then
            is_secure=false
        fi
    else
        is_secure=false
    fi

    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        if [ -f "$service_file" ]; then
            local protect_kernel=$(grep "protect-kernel-defaults" "$service_file" | grep -v "#")
            
            if [ -z "$protect_kernel" ]; then
                detail+="- Service 파일에서 protect-kernel-defaults 설정이 없음\n"
            elif ! echo "$protect_kernel" | grep -q "=true"; then
                detail+="- Service 파일에서 protect-kernel-defaults가 true로 설정되지 않음\n"
            fi
        else
            detail+="- Kubelet service 파일($service_file)이 존재하지 않음\n"
        fi
        
        if [ -f "$config_file" ]; then
            local protect_kernel_config=$(grep "protectKernelDefaults:" "$config_file" | grep -v "#")
            
            if [ -z "$protect_kernel_config" ]; then
                detail+="- Config 파일에서 protectKernelDefaults 설정이 없음\n"
            elif ! echo "$protect_kernel_config" | grep -q "true"; then
                detail+="- Config 파일에서 protectKernelDefaults가 true로 설정되지 않음\n"
            fi
        else
            detail+="- Kubelet config 파일($config_file)이 존재하지 않음\n"
        fi

        recommendation="[조치 방법]\n"
        recommendation+="1. kubelet service 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $service_file\n"
        recommendation+="   Environment=\"KUBELET_SYSTEM_PODS_ARGS=--protect-kernel-defaults=true\" 설정 추가\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service\n\n"
        recommendation+="2. Kubelet config 파일을 사용하는 경우:\n"
        recommendation+="   $ vi $config_file\n"
        recommendation+="   protectKernelDefaults: true\n"
        recommendation+="   $ systemctl daemon-reload\n"
        recommendation+="   $ systemctl restart kubelet.service"
    fi

    if [ "$is_secure" = true ]; then
        print_result "Kubelet Kernel 파라미터 설정" "양호" \
            "Kubelet Default Kernel 값을 보호하고 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "Kubelet Kernel 파라미터 설정" "취약" \
            "Kubelet Default Kernel 값을 보호하지 않고 있습니다.\n\n$detail" \
            "$recommendation"
    fi
}

# 환경설정 파일 권한 설정 검사
check_config_file_permissions() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # 검사할 파일 목록
    local files=(
        "/etc/kubernetes/kubelet.conf"
        "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf"
        "/var/lib/kubelet/config.yaml"
    )
    
    detail+="[ 현재 설정 상태 ]\n"
    for file in "${files[@]}"; do
        detail+="# stat -c %a:%U:%G $file\n"
        if [ -f "$file" ]; then
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")
            local group=$(stat -c "%G" "$file")
            detail+="$perms:$owner:$group\n\n"
        else
            detail+="파일이 존재하지 않습니다.\n\n"
        fi
    done
    
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")
            local group=$(stat -c "%G" "$file")
            
            if [ "$((8#$perms))" -gt "$((8#644))" ]; then
                is_secure=false
            fi
            
            if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                is_secure=false
            fi
        else
            is_secure=false
        fi
    done

    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        for file in "${files[@]}"; do
            if [ -f "$file" ]; then
                local perms=$(stat -c "%a" "$file")
                local owner=$(stat -c "%U" "$file")
                local group=$(stat -c "%G" "$file")
                
                if [ "$((8#$perms))" -gt "$((8#644))" ]; then
                    detail+="- $file의 권한이 644보다 큼 (현재: $perms)\n"
                fi
                
                if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                    detail+="- $file의 소유자 또는 그룹이 root가 아님 (현재: $owner:$group)\n"
                fi
            else
                detail+="- $file이 존재하지 않음\n"
            fi
        done

        recommendation="[조치 방법]\n"
        recommendation+="1. 설정파일의 소유자 및 소유 그룹이 root가 아닌 경우 root로 조치:\n"
        for file in "${files[@]}"; do
            recommendation+="   $ chown root:root $file\n"
        done
        recommendation+="\n2. 설정파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치:\n"
        for file in "${files[@]}"; do
            recommendation+="   $ chmod 644 $file\n"
        done
    fi

    if [ "$is_secure" = true ]; then
        print_result "환경설정 파일 권한 설정" "양호" \
            "환경설정 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "환경설정 파일 권한 설정" "취약" \
            "환경설정 파일의 소유자 및 소유 그룹이 root가 아니거나, 접근 권한이 644 초과로 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    fi
}

# 인증서 파일 권한 설정 검사
check_cert_file_permissions() {
    local detail=""
    local recommendation=""
    local is_secure=true
    local has_issues=false
    local has_critical_issues=false
    
    # 검사할 인증서 디렉터리와 파일 목록
    local cert_dirs=(
        "/etc/kubernetes/pki"
        "/etc/kubernetes/pki/etcd"
        "/var/lib/kubelet/pki"
    )
    
    detail+="[ 현재 설정 상태 ]\n"
    for dir in "${cert_dirs[@]}"; do
        detail+="# ls -al $dir\n"
        if [ -d "$dir" ]; then
            detail+="$(ls -al $dir)\n\n"
        else
            detail+="디렉터리가 존재하지 않습니다.\n\n"
        fi
    done
    
    for dir in "${cert_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # 디렉터리 내의 모든 .crt, .key, .pem 파일 검사
            for cert_file in $(find "$dir" -type f \( -name "*.crt" -o -name "*.key" -o -name "*.pem" \)); do
                if [ -f "$cert_file" ]; then
                    # 파일 권한, 소유자, 그룹 확인
                    local perms=$(stat -c "%a" "$cert_file")
                    local owner=$(stat -c "%U" "$cert_file")
                    local group=$(stat -c "%G" "$cert_file")
                    
                    # 권한이 644보다 큰지 확인 (8진수로 변환하여 비교)
                    if [ "$((8#$perms))" -gt "$((8#644))" ]; then
                        has_critical_issues=true
                    fi
                    
                    # 소유자와 그룹이 root가 아닌지 확인
                    if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                        has_critical_issues=true
                    fi
                fi
            done
        else
            has_issues=true
        fi
    done

    if [ "$has_critical_issues" = true ]; then
        is_secure=false
        detail+="[문제점]\n"
        for dir in "${cert_dirs[@]}"; do
            if [ -d "$dir" ]; then
                # 디렉터리 내의 모든 .crt, .key, .pem 파일 검사
                for cert_file in $(find "$dir" -type f \( -name "*.crt" -o -name "*.key" -o -name "*.pem" \)); do
                    if [ -f "$cert_file" ]; then
                        # 파일 권한, 소유자, 그룹 확인
                        local perms=$(stat -c "%a" "$cert_file")
                        local owner=$(stat -c "%U" "$cert_file")
                        local group=$(stat -c "%G" "$cert_file")
                        
                        # 권한이 644보다 큰지 확인 (8진수로 변환하여 비교)
                        if [ "$((8#$perms))" -gt "$((8#644))" ]; then
                            detail+="- $cert_file의 권한이 644보다 큼 (현재: $perms)\n"
                        fi
                        
                        # 소유자와 그룹이 root가 아닌지 확인
                        if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                            detail+="- $cert_file의 소유자 또는 그룹이 root가 아님 (현재: $owner:$group)\n"
                        fi
                    fi
                done
            else
                detail+="- $dir 디렉터리가 존재하지 않음\n"
            fi
        done

        recommendation="[조치 방법]\n"
        recommendation+="1. 인증서 파일의 소유자 및 소유 그룹이 root가 아닌 경우 root로 조치:\n"
        for dir in "${cert_dirs[@]}"; do
            if [ -d "$dir" ]; then
                recommendation+="   $ find $dir -type f \\( -name \"*.crt\" -o -name \"*.key\" -o -name \"*.pem\" \\) -exec chown root:root {} \\;\n"
            fi
        done
        recommendation+="\n2. 인증서 파일의 접근 권한이 644를 초과하는 경우 644 이하로 조치:\n"
        for dir in "${cert_dirs[@]}"; do
            if [ -d "$dir" ]; then
                recommendation+="   $ find $dir -type f \\( -name \"*.crt\" -o -name \"*.key\" -o -name \"*.pem\" \\) -exec chmod 644 {} \\;\n"
            fi
        done
    fi

    if [ "$is_secure" = true ] && [ "$has_issues" = false ]; then
        print_result "인증서 파일 권한 설정" "양호" \
            "인증서 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    elif [ "$is_secure" = true ] && [ "$has_issues" = true ]; then
        print_result "인증서 파일 권한 설정" "부분만족" \
            "인증서 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정되어 있으나, 일부 디렉터리가 존재하지 않습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "인증서 파일 권한 설정" "취약" \
            "인증서 파일의 소유자 및 소유 그룹이 root가 아니거나, 접근 권한이 644 초과로 설정되어 있습니다.\n\n$detail" \
            "$recommendation"
    fi
}

# 최신 보안 패치 적용 검사
check_version_update() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    detail+="[ 현재 설정 상태 ]\n"
    detail+="# kubectl version\n"
    
    # 개발 모드인 경우 검사 제외
    if [ "$DEV_MODE" = true ]; then
        detail+="개발 모드: 버전 확인을 건너뜁니다.\n"
    else
        # kubectl version 명령어 실행 결과 확인
        local version_info=$(kubectl version --kubeconfig=/etc/kubernetes/kubelet.conf 2>/dev/null)
        if [ $? -eq 0 ]; then
            detail+="$version_info\n\n"
            
            # Server 버전 확인 (새로운 형식)
            local server_version=$(echo "$version_info" | grep "Server Version:" | cut -d' ' -f3)
            if [ ! -z "$server_version" ]; then
                # 버전 번호만 추출 (예: v1.20.1 -> 1.20.1)
                local version_num=${server_version#v}
                local major_version=$(echo $version_num | cut -d. -f1)
                local minor_version=$(echo $version_num | cut -d. -f2)
                
                # 버전 1.25.0 이하를 취약으로 판단
                if [ "$major_version" -lt 1 ] || ([ "$major_version" -eq 1 ] && [ "$minor_version" -lt 25 ]); then
                    is_secure=false
                fi
            else
                detail+="- Server 버전 정보를 가져올 수 없습니다.\n"
                is_secure=false
            fi
        else
            detail+="- kubectl version 명령어 실행 실패\n"
            is_secure=false
        fi
    fi
    
    if [ "$is_secure" = false ]; then
        detail+="[문제점]\n"
        detail+="- 현재 버전이 1.25.0 미만입니다 (취약점이 존재할 수 있음)\n"
    fi

    if [ "$is_secure" = false ]; then
        recommendation="[조치 방법]\n"
        recommendation+="1. 최신 보안 패치 확인 후 업데이트 및 패치 수행\n"
        recommendation+="   ※ 최신 버전을 사용하도록 권고하고 있으나 시스템 운영상 적용이 어려운 경우\n"
        recommendation+="   ※ 최신이 아닌 취약점이 존재하지 않는 버전도 허용\n\n"
        recommendation+="[주의사항]\n"
        recommendation+="- 보안 패치를 적용할 경우, 시스템 영향도를 파악하여 충분한 테스트 후 적용 권고"
    fi

    if [ "$is_secure" = true ]; then
        print_result "최신 보안 패치 적용" "양호" \
            "최신 보안 패치가 적용되어 있습니다.\n\n$detail" \
            "$recommendation"
    else
        print_result "최신 보안 패치 적용" "취약" \
            "최신 보안 패치가 적용되지 않았습니다.\n\n$detail" \
            "$recommendation"
    fi
}

# 메인 함수
main() {
    print_logo
    print_output "${BOLD}[Kubernetes Worker 노드 보안 진단 시작]${NC}\n" \
                "[Kubernetes Worker 노드 보안 진단 시작]"
    
    # Kubelet Configuration 검사
    print_output "\n${BLUE}[KuW-01] Kubelet 인증 제어${NC}" \
                "\n[KuW-01] Kubelet 인증 제어"
    
    check_kubelet_auth
    print_output "\n${BLUE}[KuW-02] Kubelet 권한 제어${NC}" \
                "\n[KuW-02] Kubelet 권한 제어"
    check_kubelet_authorization
    print_output "\n${BLUE}[KuW-03] Kubelet SSL/TLS 적용${NC}" \
                "\n[KuW-03] Kubelet SSL/TLS 적용"
    check_kubelet_ssl_tls
    print_output "\n${BLUE}[KuW-04] Kubelet Kernel 파라미터 설정${NC}" \
                "\n[KuW-04] Kubelet Kernel 파라미터 설정"
    check_kubelet_kernel_params
    
    # 파일 권한 설정 검사
    print_output "\n${BLUE}[KuW-05] 환경설정 파일 권한 설정${NC}" \
                "\n[KuW-05] 환경설정 파일 권한 설정"
    check_config_file_permissions
    print_output "\n${BLUE}[KuW-06] 인증서 파일 권한 설정${NC}" \
                "\n[KuW-06] 인증서 파일 권한 설정"
    check_cert_file_permissions
    
    # 패치 관리 검사
    print_output "\n${BLUE}[KuW-07] 최신 보안 패치 적용${NC}" \
                "\n[KuW-07] 최신 보안 패치 적용"
    check_version_update
    
    # 결과 요약
    print_line
    print_output "\n${BOLD}[진단 결과 요약]${NC}" "\n[진단 결과 요약]"
    print_output "전체 검사 항목: $total_checks" "전체 검사 항목: $total_checks"
    print_output "${GREEN}양호 항목 수: $pass_checks${NC}" "양호 항목 수: $pass_checks"
    print_output "${RED}취약 항목 수: $fail_checks${NC}" "취약 항목 수: $fail_checks"
    print_output "취약점 비율: $(( (fail_checks * 100) / total_checks ))%\n" \
                "취약점 비율: $(( (fail_checks * 100) / total_checks ))%\n"
    print_line

    echo -e "\n진단 결과가 다음 파일에 저장되었습니다: $OUTPUT_FILE"
}

# 스크립트 실행
main 