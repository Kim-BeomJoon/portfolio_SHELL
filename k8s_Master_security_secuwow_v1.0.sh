#!/bin/bash

# 출력 파일 경로 설정
OUTPUT_FILE="/tmp/k8s_master/k8s_M_secuwow.txt"

# 이전 결과 파일이 있다면 삭제
[ -f "$OUTPUT_FILE" ] && rm "$OUTPUT_FILE"


# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD='\033[1m'
BLUE='\033[0;34m'

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
    echo '       Secuwow Kubernetes Security Compliance Check Tool v1.0' | tee -a "$OUTPUT_FILE"
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

    # Master 노드 여부 체크
    if ! kubectl get nodes 2>/dev/null | grep -q "control-plane"; then
        echo "이 노드는 Kubernetes Master 노드가 아닙니다."
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
    print_output "${BOLD}[검사항목]${NC}" "[검사항목]"
    print_output "${BLUE}$check_name${NC}" "$check_name"
    
    if [ "$status" == "양호" ]; then
        print_output "${BOLD}[진단결과]${NC} ${GREEN}$status${NC}" "[진단결과] $status"
        pass_checks=$((pass_checks + 1))
    else
        print_output "${BOLD}[진단결과]${NC} ${RED}$status${NC}" "[진단결과] $status"
        fail_checks=$((fail_checks + 1))
    fi
    
    print_output "${BOLD}[현재상태]${NC}" "[현재상태]"
    print_output "$detail" "$detail"
    
    if [ ! -z "$recommendation" ]; then
        print_output "${BOLD}[조치방법]${NC}" "[조치방법]"
        print_output "$recommendation" "$recommendation"
    fi
    
    total_checks=$((total_checks + 1))
}

# API Server 비인증 접근 차단 검사
check_anonymous_auth() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "API Server 비인증 접근 차단" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    local anonymous_auth=$(grep "\-\-anonymous-auth=false" "$api_server_yaml")
    local service_account_lookup=$(grep "\-\-service-account-lookup=true" "$api_server_yaml")

    if [ ! -z "$anonymous_auth" ] && [ ! -z "$service_account_lookup" ]; then
        print_result "API Server 비인증 접근 차단" "양호" \
            "API Server 비인증 접근이 적절히 차단되어 있습니다."
    else
        print_result "API Server 비인증 접근 차단" "취약" \
            "API Server 비인증 접근 설정이 미흡합니다." \
            "1) --anonymous-auth=false 설정을 추가하세요.\n2) --service-account-lookup=true 설정을 추가하세요."
    fi
}

# API Server 취약한 방식의 인증 사용 제한 검사
check_insecure_auth() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "API Server 취약한 방식의 인증 사용 제한" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    local token_auth_file=$(grep "\-\-token-auth-file" "$api_server_yaml")

    if [ -z "$token_auth_file" ]; then
        print_result "API Server 취약한 방식의 인증 사용 제한" "양호" \
            "취약한 방식의 인증(token-auth-file)이 사용되지 않고 있습니다."
    else
        print_result "API Server 취약한 방식의 인증 사용 제한" "취약" \
            "취약한 방식의 인증(token-auth-file)이 사용되고 있습니다." \
            "--token-auth-file 파라미터를 설정에서 제거하세요."
    fi
}

# API Server 서비스 API 외부 오픈 금지 검사
check_service_api_binding() {
    local scheduler_yaml="/etc/kubernetes/manifests/kube-scheduler.yaml"
    local controller_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    local is_secure=true
    local detail=""
    local recommendation=""

    # kube-scheduler.yaml 검사
    if [ ! -f "$scheduler_yaml" ]; then
        detail="kube-scheduler.yaml 파일을 찾을 수 없습니다."
        recommendation="$scheduler_yaml 파일의 위치를 확인하세요."
        is_secure=false
    else
        local scheduler_bind=$(grep "\-\-bind-address" "$scheduler_yaml")
        if [ -z "$scheduler_bind" ]; then
            detail="kube-scheduler의 bind-address 설정이 없습니다."
            recommendation="${recommendation}1) kube-scheduler.yaml 파일에 --bind-address=127.0.0.1 설정을 추가하세요.\n"
            is_secure=false
        else
            local scheduler_bind_value=$(echo "$scheduler_bind" | grep -E "0\.0\.0\.0|\:\:|\"\"")
            if [ ! -z "$scheduler_bind_value" ]; then
                detail="kube-scheduler가 모든 인터페이스에 바인딩되어 있습니다."
                recommendation="${recommendation}1) kube-scheduler.yaml 파일의 bind-address를 127.0.0.1로 설정하세요.\n"
                is_secure=false
            fi
        fi
    fi

    # kube-controller-manager.yaml 검사
    if [ ! -f "$controller_yaml" ]; then
        detail="${detail}\nkube-controller-manager.yaml 파일을 찾을 수 없습니다."
        recommendation="${recommendation}2) $controller_yaml 파일의 위치를 확인하세요."
        is_secure=false
    else
        local controller_bind=$(grep "\-\-bind-address" "$controller_yaml")
        if [ -z "$controller_bind" ]; then
            detail="${detail}\nkube-controller-manager의 bind-address 설정이 없습니다."
            recommendation="${recommendation}2) kube-controller-manager.yaml 파일에 --bind-address=127.0.0.1 설정을 추가하세요."
            is_secure=false
        else
            local controller_bind_value=$(echo "$controller_bind" | grep -E "0\.0\.0\.0|\:\:|\"\"")
            if [ ! -z "$controller_bind_value" ]; then
                detail="${detail}\nkube-controller-manager가 모든 인터페이스에 바인딩되어 있습니다."
                recommendation="${recommendation}2) kube-controller-manager.yaml 파일의 bind-address를 127.0.0.1로 설정하세요."
                is_secure=false
            fi
        fi
    fi

    if [ "$is_secure" = true ]; then
        print_result "API Server 서비스 API 외부 오픈 금지" "양호" \
            "API Server 서비스가 로컬호스트에만 바인딩되어 있습니다."
    else
        print_result "API Server 서비스 API 외부 오픈 금지" "취약" \
            "$detail" "$recommendation"
    fi
}

# API Server 권한 제어 검사
check_api_authorization() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "API Server 권한 제어" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    local auth_mode=$(grep "\-\-authorization-mode" "$api_server_yaml")
    
    if [ -z "$auth_mode" ]; then
        print_result "API Server 권한 제어" "취약" \
            "authorization-mode 설정이 없습니다. 기본값으로 AlwaysAllow가 사용될 수 있습니다." \
            "authorization-mode를 명시적으로 설정하세요. (예: --authorization-mode=Node,RBAC)"
        return
    fi

    local always_allow=$(echo "$auth_mode" | grep -i "AlwaysAllow")
    if [ ! -z "$always_allow" ]; then
        print_result "API Server 권한 제어" "취약" \
            "API Server 권한이 AlwaysAllow로 설정되어 있어 모든 요청이 허용됩니다." \
            "authorization-mode를 보다 안전한 값으로 변경하세요. (권장: --authorization-mode=Node,RBAC)\n\n\
[참고] 권한 모드 설명:\n\
- ABAC: 속성 기반 접근제어, 로컬 파일로 정책 구성\n\
- RBAC: 역할 기반 접근제어, 쿠버네티스 API로 정책 구성\n\
- Webhook: 원격 REST 엔드포인트로 인가 관리\n\
- Node: Kubelet API 요청 특별 인가\n\
- AlwaysDeny: 모든 요청 차단 (테스트용)\n\
- AlwaysAllow: 모든 요청 허용 (보안에 취약)"
    else
        local has_node=$(echo "$auth_mode" | grep -i "Node")
        local has_rbac=$(echo "$auth_mode" | grep -i "RBAC")
        
        if [ ! -z "$has_node" ] && [ ! -z "$has_rbac" ]; then
            print_result "API Server 권한 제어" "양호" \
                "API Server 권한이 Node,RBAC으로 안전하게 설정되어 있습니다."
        else
            print_result "API Server 권한 제어" "양호" \
                "API Server 권한이 AlwaysAllow가 아닌 값으로 설정되어 있습니다." \
                "보다 안전한 설정을 위해 Node,RBAC 조합 사용을 권장합니다."
        fi
    fi
}

# API Server Admission Control Plugin 설정 검사
check_admission_control() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "Admission Control Plugin 설정" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    # 필수 플러그인 목록
    local required_plugins=(
        "AlwaysPullImages"
        "NodeRestriction"
        "SecurityContextDeny"
        "EventRateLimit"
    )

    # 제거해야 할 플러그인 목록
    local remove_plugins=(
        "AlwaysAdmin"
        "NamespaceLifecycle"
    )

    # enable-admission-plugins 설정 확인
    local enabled_plugins=$(grep "\-\-enable-admission-plugins" "$api_server_yaml")
    if [ -z "$enabled_plugins" ]; then
        detail="--enable-admission-plugins 설정이 없습니다."
        recommendation="필수 Admission Plugin을 활성화하세요:\n"
        for plugin in "${required_plugins[@]}"; do
            recommendation+="- $plugin\n"
        done
        is_secure=false
    else
        # 필수 플러그인 존재 여부 확인
        for plugin in "${required_plugins[@]}"; do
            if ! echo "$enabled_plugins" | grep -q "$plugin"; then
                detail+="필수 플러그인 $plugin이 활성화되어 있지 않습니다.\n"
                is_secure=false
            fi
        done
        
        # 제거해야 할 플러그인 확인
        for plugin in "${remove_plugins[@]}"; do
            if echo "$enabled_plugins" | grep -q "$plugin"; then
                detail+="제거해야 할 플러그인 $plugin이 활성화되어 있습니다.\n"
                is_secure=false
            fi
        done
    fi

    # admission-control-config-file 설정 확인
    local config_file=$(grep "\-\-admission-control-config-file" "$api_server_yaml")
    if [ -z "$config_file" ]; then
        detail+="--admission-control-config-file 설정이 없습니다.\n"
        recommendation+="admission-control-config-file을 설정하세요.\n"
        is_secure=false
    fi

    # disable-admission-plugins 설정 확인
    local disabled_plugins=$(grep "\-\-disable-admission-plugins" "$api_server_yaml")
    if [ ! -z "$disabled_plugins" ]; then
        for plugin in "${required_plugins[@]}"; do
            if echo "$disabled_plugins" | grep -q "$plugin"; then
                detail+="필수 플러그인 $plugin이 비활성화되어 있습니다.\n"
                is_secure=false
            fi
        done
    fi

    # PodSecurityPolicy 관련 안내
    detail+="\n참고: Kubernetes 1.25 버전 이상에서는 PodSecurityPolicy 대신 \
PodSecurityAdmission을 통해 PodSecurityStandard를 적용해야 합니다."

    if [ "$is_secure" = true ]; then
        print_result "Admission Control Plugin 설정" "양호" \
            "Admission Control Plugin이 적절하게 설정되어 있습니다.\n$detail"
    else
        if [ -z "$recommendation" ]; then
            recommendation="다음 설정을 적용하세요:\n"
            recommendation+="1) 필수 플러그인 활성화:\n"
            for plugin in "${required_plugins[@]}"; do
                recommendation+="   --enable-admission-plugins=$plugin\n"
            done
            recommendation+="\n2) 제거해야 할 플러그인:\n"
            for plugin in "${remove_plugins[@]}"; do
                recommendation+="   $plugin을 제거하세요.\n"
            done
            recommendation+="\n3) admission-control-config-file 설정을 추가하세요."
        fi
        print_result "Admission Control Plugin 설정" "취약" "$detail" "$recommendation"
    fi
}

# API Server SSL/TLS 적용 검사
check_api_ssl_tls() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "API Server SSL/TLS 적용" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    # SSL/TLS 적용을 통한 네트워크 구간 데이터 보호 검사
    local secure_port=$(grep "\-\-secure-port" "$api_server_yaml")
    if [ -z "$secure_port" ] || echo "$secure_port" | grep -q "=0"; then
        detail+="--secure-port가 설정되지 않았거나 0으로 설정되어 있습니다.\n"
        recommendation+="1) --secure-port를 0이 아닌 값으로 설정하세요.\n"
        is_secure=false
    fi

    # API Server to kubelet 인증서 관리 검사
    local kubelet_params=(
        "kubelet-certificate-authority"
        "kubelet-client-certificate"
        "kubelet-client-key"
        "kubelet-account-key-file"
    )
    
    for param in "${kubelet_params[@]}"; do
        local value=$(grep "\-\-$param" "$api_server_yaml")
        if [ -z "$value" ]; then
            detail+="--$param 설정이 없습니다.\n"
            recommendation+="2) --$param=<적절한 인증서/키 파일> 설정을 추가하세요.\n"
            is_secure=false
        fi
    done

    # API Server 인증서 관리 검사
    local api_cert_params=(
        "tls-cert-file"
        "tls-private-key-file"
        "client-ca-file"
    )
    
    for param in "${api_cert_params[@]}"; do
        local value=$(grep "\-\-$param" "$api_server_yaml")
        if [ -z "$value" ]; then
            detail+="--$param 설정이 없습니다.\n"
            recommendation+="3) --$param=<적절한 인증서/키 파일> 설정을 추가하세요.\n"
            is_secure=false
        fi
    done

    # 안전한 SSL/TLS 버전 사용 검사
    local tls_cipher_suites=$(grep "\-\-tls-cipher-suites" "$api_server_yaml")
    if [ -z "$tls_cipher_suites" ]; then
        detail+="--tls-cipher-suites 설정이 없습니다.\n"
        recommendation+="4) 안전한 암호화 스위트를 설정하세요. 예시:\n"
        recommendation+="--tls-cipher-suites=TLS_ECDSA_WITH_AED_128_GCM_SHA256,\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "API Server SSL/TLS 적용" "양호" \
            "API Server SSL/TLS가 적절하게 설정되어 있습니다."
    else
        print_result "API Server SSL/TLS 적용" "취약" "$detail" "$recommendation"
    fi
}

# API Server 로그 관리 검사
check_api_logging() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "API Server 로그 관리" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    # 로그 관련 파라미터 검사
    local log_params=(
        "audit-log-path"
        "audit-policy-file"
        "audit-log-maxage"
        "audit-log-maxbackup"
        "audit-log-maxsize"
    )
    
    for param in "${log_params[@]}"; do
        local value=$(grep "\-\-$param" "$api_server_yaml")
        if [ -z "$value" ]; then
            detail+="--$param 설정이 없습니다.\n"
            case "$param" in
                "audit-log-path")
                    recommendation+="1) --audit-log-path=<로그 파일 경로> 설정을 추가하세요.\n"
                    ;;
                "audit-policy-file")
                    recommendation+="2) --audit-policy-file=<정책 파일 경로> 설정을 추가하세요.\n"
                    ;;
                "audit-log-maxage")
                    recommendation+="3) --audit-log-maxage=<일 수> 설정을 추가하세요. (예: 30)\n"
                    ;;
                "audit-log-maxbackup")
                    recommendation+="4) --audit-log-maxbackup=<백업 파일 수> 설정을 추가하세요. (예: 10)\n"
                    ;;
                "audit-log-maxsize")
                    recommendation+="5) --audit-log-maxsize=<크기(MB)> 설정을 추가하세요. (예: 100)\n"
                    ;;
            esac
            is_secure=false
        fi
    done

    if [ "$is_secure" = true ]; then
        print_result "API Server 로그 관리" "양호" \
            "API Server 로그가 적절하게 설정되어 있습니다."
    else
        detail+="\n[설정 설명]\n"
        detail+="- audit-log-path: 감사 로그 파일 저장 경로\n"
        detail+="- audit-policy-file: 감사 정책 설정 파일 경로\n"
        detail+="- audit-log-maxage: 감사 로그 파일 보관 기간(일)\n"
        detail+="- audit-log-maxbackup: 보관할 감사 로그 파일의 최대 개수\n"
        detail+="- audit-log-maxsize: 로그 파일 최대 크기(MB)"
        
        print_result "API Server 로그 관리" "취약" "$detail" "$recommendation"
    fi
}

# Controller 인증 제어 검사
check_controller_auth() {
    local controller_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$controller_yaml" ]; then
        print_result "Controller 인증 제어" "취약" \
            "kube-controller-manager.yaml 파일을 찾을 수 없습니다." \
            "Controller Manager 설정 파일의 위치를 확인하세요."
        return
    fi

    # 서비스 계정 자격증명 설정 검사
    local service_account_cred=$(grep "\-\-use-service-account-credentials" "$controller_yaml")
    if [ -z "$service_account_cred" ]; then
        detail+="--use-service-account-credentials 설정이 없습니다.\n"
        recommendation+="1) --use-service-account-credentials=true 설정을 추가하세요.\n"
        is_secure=false
    elif ! echo "$service_account_cred" | grep -q "=true"; then
        detail+="--use-service-account-credentials가 true로 설정되어 있지 않습니다.\n"
        recommendation+="1) --use-service-account-credentials=true로 설정하세요.\n"
        is_secure=false
    fi

    # 서비스 계정 프라이빗 키 파일 설정 검사
    local private_key_file=$(grep "\-\-service-account-private-key-file" "$controller_yaml")
    if [ -z "$private_key_file" ]; then
        detail+="--service-account-private-key-file 설정이 없습니다.\n"
        recommendation+="2) --service-account-private-key-file=<키 파일 경로> 설정을 추가하세요.\n"
        recommendation+="   (기본값: /etc/kubernetes/pki/sa.key)"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "Controller 인증 제어" "양호" \
            "Controller 인증 제어가 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 개별 서비스 계정 자격증명 사용\n\
- 서비스 계정 프라이빗 키 파일 설정 완료"
    else
        detail+="\n[설정 설명]\n"
        detail+="- use-service-account-credentials: 컨트롤러별 개별 서비스 계정 사용 여부\n"
        detail+="- service-account-private-key-file: 서비스 계정 토큰 생성에 사용되는 프라이빗 키 파일"
        print_result "Controller 인증 제어" "취약" "$detail" "$recommendation"
    fi
}

# Controller Manager SSL/TLS 적용 검사
check_controller_ssl_tls() {
    local controller_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$controller_yaml" ]; then
        print_result "Controller Manager SSL/TLS 적용" "취약" \
            "kube-controller-manager.yaml 파일을 찾을 수 없습니다." \
            "Controller Manager 설정 파일의 위치를 확인하세요."
        return
    fi

    # SSL/TLS 적용을 통한 클라이언트 인증 검사
    local root_ca_file=$(grep "\-\-root-ca-file" "$controller_yaml")
    if [ -z "$root_ca_file" ]; then
        detail+="--root-ca-file 설정이 없습니다.\n"
        recommendation+="1) --root-ca-file=<인증서 파일 경로> 설정을 추가하세요.\n"
        is_secure=false
    fi

    # 인증서 자동 갱신 설정 검사
    local feature_gates=$(grep "\-\-feature-gates" "$controller_yaml")
    if [ -z "$feature_gates" ]; then
        detail+="--feature-gates 설정이 없습니다.\n"
        recommendation+="2) --feature-gates=RotateKubeletServerCertificate=true 설정을 추가하세요.\n"
        is_secure=false
    elif ! echo "$feature_gates" | grep -q "RotateKubeletServerCertificate=true"; then
        detail+="인증서 자동 갱신(RotateKubeletServerCertificate) 기능이 활성화되어 있지 않습니다.\n"
        recommendation+="2) --feature-gates 설정에 RotateKubeletServerCertificate=true를 추가하세요.\n"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "Controller Manager SSL/TLS 적용" "양호" \
            "Controller Manager SSL/TLS가 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 클라이언트 인증을 위한 root CA 파일 설정 완료\n\
- Kubelet 서버 인증서 자동 갱신 기능 활성화"
    else
        detail+="\n[설정 설명]\n"
        detail+="- root-ca-file: 클라이언트 인증에 사용되는 root CA 인증서 파일\n"
        detail+="- feature-gates: Kubelet 서버 인증서 자동 갱신 기능 활성화 여부"
        print_result "Controller Manager SSL/TLS 적용" "취약" "$detail" "$recommendation"
    fi
}

# etcd 암호화 적용 검사
check_etcd_encryption() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "etcd 암호화 적용" "취약" \
            "kube-apiserver.yaml 파일을 찾을 수 없습니다." \
            "API Server 설정 파일의 위치를 확인하세요."
        return
    fi

    # encryption-provider-config 설정 검사
    local encryption_config=$(grep "\-\-encryption-provider-config" "$api_server_yaml")
    if [ -z "$encryption_config" ]; then
        detail+="--encryption-provider-config 설정이 없습니다.\n"
        recommendation+="1) --encryption-provider-config=<설정 파일 경로> 설정을 추가하세요.\n"
        is_secure=false
    else
        # 설정 파일 경로 추출
        local config_path=$(echo "$encryption_config" | grep -o "=.*" | cut -d'=' -f2)
        
        if [ -f "$config_path" ]; then
            # 암호화 설정 파일 내용 검사
            local has_aescbc=$(grep -i "aescbc" "$config_path")
            if [ -z "$has_aescbc" ]; then
                detail+="암호화 설정 파일에서 aescbc 암호화 방식이 설정되어 있지 않습니다.\n"
                is_secure=false
            fi
        else
            detail+="암호화 설정 파일($config_path)을 찾을 수 없습니다.\n"
            is_secure=false
        fi
    fi

    # 실행 중인 프로세스에서 설정 확인
    local running_config=$(ps -ef | grep kube-apiserver | grep "\-\-encryption-provider-config")
    if [ -z "$running_config" ]; then
        detail+="실행 중인 kube-apiserver 프로세스에서 encryption-provider-config 설정을 찾을 수 없습니다.\n"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "etcd 암호화 적용" "양호" \
            "etcd 암호화가 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- encryption-provider-config 설정 완료\n\
- aescbc 이상의 안전한 암호화 방식 사용"
    else
        detail+="\n[설정 설명]\n"
        detail+="- encryption-provider-config: etcd 데이터 암호화 설정 파일 경로\n"
        detail+="- 권장 암호화 방식: aescbc (AES-CBC with PKCS#7 padding)"
        
        if [ -z "$recommendation" ]; then
            recommendation="다음 설정을 적용하세요:\n"
            recommendation+="1) API Server에 암호화 설정 파일 경로 지정\n"
            recommendation+="2) 암호화 설정 파일에 aescbc 방식 설정\n"
            recommendation+="3) API Server 재시작으로 설정 적용"
        fi
        
        print_result "etcd 암호화 적용" "취약" "$detail" "$recommendation"
    fi
}

# etcd SSL/TLS 적용 검사
check_etcd_ssl_tls() {
    local etcd_yaml="/etc/kubernetes/manifests/etcd.yaml"
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    local detail=""
    local recommendation=""
    local is_secure=true
    
    if [ ! -f "$etcd_yaml" ]; then
        print_result "etcd SSL/TLS 적용" "취약" \
            "etcd.yaml 파일을 찾을 수 없습니다." \
            "etcd 설정 파일의 위치를 확인하세요."
        return
    fi

    # SSL/TLS 적용을 통한 클라이언트 인증 검사
    local client_cert_auth=$(grep "\-\-client-cert-auth" "$etcd_yaml")
    if [ -z "$client_cert_auth" ] || ! echo "$client_cert_auth" | grep -q "=true"; then
        detail+="--client-cert-auth가 true로 설정되어 있지 않습니다.\n"
        recommendation+="1) --client-cert-auth=true 설정을 추가하세요.\n"
        is_secure=false
    fi

    # 인증서 관리(etcd peer 및 클라이언트) 검사
    local cert_params=(
        "cert-file"
        "key-file"
        "peer-cert-file"
        "peer-key-file"
    )
    
    for param in "${cert_params[@]}"; do
        local value=$(grep "\-\-$param" "$etcd_yaml")
        if [ -z "$value" ]; then
            detail+="--$param 설정이 없습니다.\n"
            recommendation+="2) --$param=<인증서/키 파일 경로> 설정을 추가하세요.\n"
            is_secure=false
        fi
    done

    # API Server의 etcd 인증서 설정 검사
    if [ -f "$api_server_yaml" ]; then
        local api_cert_params=(
            "etcd-certfile"
            "etcd-keyfile"
            "etcd-cafile"
        )
        
        for param in "${api_cert_params[@]}"; do
            local value=$(grep "\-\-$param" "$api_server_yaml")
            if [ -z "$value" ]; then
                detail+="API Server의 --$param 설정이 없습니다.\n"
                recommendation+="3) API Server에 --$param=<인증서/키 파일 경로> 설정을 추가하세요.\n"
                is_secure=false
            fi
        done
    else
        detail+="kube-apiserver.yaml 파일을 찾을 수 없습니다.\n"
        is_secure=false
    fi

    # 자체 서명 인증서 사용 금지 설정 검사
    local auto_tls=$(grep "\-\-auto-tls" "$etcd_yaml")
    if [ ! -z "$auto_tls" ] && ! echo "$auto_tls" | grep -q "=false"; then
        detail+="--auto-tls가 false로 설정되어 있지 않습니다.\n"
        recommendation+="4) --auto-tls=false 설정을 추가하거나 수정하세요.\n"
        is_secure=false
    fi

    local trusted_ca_file=$(grep "\-\-trusted-ca-file" "$etcd_yaml")
    if [ -z "$trusted_ca_file" ]; then
        detail+="--trusted-ca-file 설정이 없습니다.\n"
        recommendation+="5) --trusted-ca-file=<인증서 파일 경로> 설정을 추가하세요.\n"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "etcd SSL/TLS 적용" "양호" \
            "etcd SSL/TLS가 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 클라이언트 인증 활성화\n\
- etcd peer 및 클라이언트 인증서 설정 완료\n\
- API Server etcd 인증서 설정 완료\n\
- 자체 서명 인증서 사용 제한 설정 완료"
    else
        detail+="\n[설정 설명]\n"
        detail+="- client-cert-auth: 클라이언트 인증서 인증 활성화\n"
        detail+="- cert/key-file: etcd 서버 인증서 및 키 파일\n"
        detail+="- peer-cert/key-file: etcd peer 간 통신용 인증서 및 키 파일\n"
        detail+="- etcd-cert/key/ca-file: API Server의 etcd 접근 인증서\n"
        detail+="- auto-tls: 자체 서명 인증서 사용 여부\n"
        detail+="- trusted-ca-file: 신뢰할 수 있는 CA 인증서 파일"
        print_result "etcd SSL/TLS 적용" "취약" "$detail" "$recommendation"
    fi
}

# 컨테이너 권한 제어 검사
check_container_privileges() {
    if [ "$DEV_MODE" = true ]; then
        print_result "컨테이너 권한 제어" "검사 제외" \
            "[개발 모드] 컨테이너 권한 제어 검사를 건너뜁니다.\n\n\
[검사 대상]\n\
- 네임스페이스별 PSA 정책\n\
- Pod 보안 컨텍스트 설정\n\
- allowPrivilegeEscalation 설정\n\
- runAsNonRoot 설정\n\
- capabilities.drop 설정\n\
- seccompProfile 설정"
        return
    fi

    local detail=""
    local recommendation=""
    local is_secure=true
    
    # 모든 네임스페이스 조회
    local namespaces=$(kubectl get ns -o name 2>/dev/null | cut -d'/' -f2)
    if [ -z "$namespaces" ]; then
        print_result "컨테이너 권한 제어" "검사 불가" \
            "네임스페이스 정보를 가져올 수 없습니다." \
            "kubectl 명령어 실행 권한을 확인하세요."
        return
    fi

    # 네임스페이스별 PSA 정책 검사
    local insecure_ns=0
    for ns in $namespaces; do
        local enforce_policy=$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)
        local warn_policy=$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}' 2>/dev/null)
        
        if [ "$enforce_policy" != "restricted" ] || [ "$warn_policy" != "restricted" ]; then
            detail+="네임스페이스 '$ns'의 PSA 정책이 적절하지 않습니다.\n"
            detail+="- enforce: $enforce_policy\n"
            detail+="- warn: $warn_policy\n"
            insecure_ns=$((insecure_ns + 1))
            is_secure=false
        fi
    done

    if [ $insecure_ns -gt 0 ]; then
        detail+="\n총 $insecure_ns 개의 네임스페이스가 안전하지 않은 PSA 정책을 사용중입니다.\n"
    fi

    # Pod 보안 컨텍스트 설정 검사
    local required_settings=(
        "allowPrivilegeEscalation: false"
        "runAsNonRoot: true"
        "capabilities:\n    drop: [\"ALL\"]"
        "seccompProfile:\n    type: \"RuntimeDefault\""
    )

    # 모든 Pod의 보안 컨텍스트 검사
    local pods=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null)
    if [ ! -z "$pods" ]; then
        local insecure_pods=0
        while IFS= read -r pod_info; do
            local ns=$(echo "$pod_info" | cut -d'/' -f1)
            local pod=$(echo "$pod_info" | cut -d'/' -f2)
            local security_context=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.securityContext}' 2>/dev/null)
            local container_security_contexts=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.containers[*].securityContext}' 2>/dev/null)
            
            if [ -z "$security_context" ] && [ -z "$container_security_contexts" ]; then
                detail+="Pod '$ns/$pod'에 보안 컨텍스트 설정이 없습니다.\n"
                insecure_pods=$((insecure_pods + 1))
                is_secure=false
            fi
        done <<< "$pods"

        if [ $insecure_pods -gt 0 ]; then
            detail+="\n총 $insecure_pods 개의 Pod가 보안 컨텍스트 설정이 미흡합니다.\n"
        fi
    fi

    if [ "$is_secure" = true ]; then
        print_result "컨테이너 권한 제어" "양호" \
            "컨테이너 권한이 적절하게 제어되고 있습니다.\n\n\
[현재 설정]\n\
- 모든 네임스페이스에 PSA 정책 적용\n\
- Pod 보안 컨텍스트 설정 완료"
    else
        detail+="\n[권장 설정]\n"
        detail+="1. 네임스페이스 PSA 정책 설정:\n"
        detail+="   kubectl label --overwrite ns <namespace> \\\n"
        detail+="   pod-security.kubernetes.io/enforce=restricted \\\n"
        detail+="   pod-security.kubernetes.io/warn=restricted\n\n"
        detail+="2. Pod 보안 컨텍스트 필수 설정:\n"
        for setting in "${required_settings[@]}"; do
            detail+="   $setting\n"
        done

        recommendation="다음 조치를 수행하세요:\n"
        recommendation+="1) 모든 네임스페이스에 restricted PSA 정책을 적용하세요.\n"
        recommendation+="2) 모든 Pod에 보안 컨텍스트를 설정하세요.\n"
        recommendation+="3) 권장 보안 설정을 적용하세요:\n"
        recommendation+="   - allowPrivilegeEscalation: false\n"
        recommendation+="   - runAsNonRoot: true\n"
        recommendation+="   - capabilities.drop: [\"ALL\"]\n"
        recommendation+="   - seccompProfile.type: RuntimeDefault"

        print_result "컨테이너 권한 제어" "취약" "$detail" "$recommendation"
    fi
}

# 네임스페이스 공유 금지 검사
check_namespace_isolation() {
    if [ "$DEV_MODE" = true ]; then
        print_result "네임스페이스 공유 금지" "검사 제외" \
            "[개발 모드] 네임스페이스 공유 금지 검사를 건너뜁니다.\n\n\
[검사 대상]\n\
- hostNetwork 설정\n\
- hostPID 설정\n\
- hostIPC 설정"
        return
    fi

    local detail=""
    local recommendation=""
    local is_secure=true
    
    # 모든 Pod의 네임스페이스 설정 검사
    local pods=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null)
    if [ -z "$pods" ]; then
        print_result "네임스페이스 공유 금지" "검사 불가" \
            "Pod 정보를 가져올 수 없습니다." \
            "kubectl 명령어 실행 권한을 확인하세요."
        return
    fi

    local insecure_pods=0
    while IFS= read -r pod_info; do
        local ns=$(echo "$pod_info" | cut -d'/' -f1)
        local pod=$(echo "$pod_info" | cut -d'/' -f2)
        
        # hostNetwork 검사
        local host_network=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.hostNetwork}' 2>/dev/null)
        if [ "$host_network" = "true" ]; then
            detail+="Pod '$ns/$pod'가 hostNetwork를 사용중입니다.\n"
            is_secure=false
            insecure_pods=$((insecure_pods + 1))
        fi
        
        # hostPID 검사
        local host_pid=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.hostPID}' 2>/dev/null)
        if [ "$host_pid" = "true" ]; then
            detail+="Pod '$ns/$pod'가 hostPID를 사용중입니다.\n"
            is_secure=false
            insecure_pods=$((insecure_pods + 1))
        fi
        
        # hostIPC 검사
        local host_ipc=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.hostIPC}' 2>/dev/null)
        if [ "$host_ipc" = "true" ]; then
            detail+="Pod '$ns/$pod'가 hostIPC를 사용중입니다.\n"
            is_secure=false
            insecure_pods=$((insecure_pods + 1))
        fi
    done <<< "$pods"

    if [ $insecure_pods -gt 0 ]; then
        detail+="\n총 $insecure_pods 개의 Pod가 호스트 네임스페이스를 공유하고 있습니다.\n"
    fi

    if [ "$is_secure" = true ]; then
        print_result "네임스페이스 공유 금지" "양호" \
            "모든 Pod가 적절하게 네임스페이스가 격리되어 있습니다.\n\n\
[현재 설정]\n\
- hostNetwork 사용 제한\n\
- hostPID 사용 제한\n\
- hostIPC 사용 제한"
    else
        detail+="\n[설정 설명]\n"
        detail+="- hostNetwork: 노드의 네트워크 네임스페이스 공유\n"
        detail+="- hostPID: 노드의 프로세스 ID 네임스페이스 공유\n"
        detail+="- hostIPC: 노드의 IPC 네임스페이스 공유"

        recommendation="다음 조치를 수행하세요:\n"
        recommendation+="1) Pod 스펙에서 다음 설정을 제거하거나 false로 설정:\n"
        recommendation+="   - hostNetwork: false\n"
        recommendation+="   - hostPID: false\n"
        recommendation+="   - hostIPC: false\n\n"
        recommendation+="2) PSA 정책을 통해 호스트 네임스페이스 사용 제한:\n"
        recommendation+="   kubectl label --overwrite ns <namespace> \\\n"
        recommendation+="   pod-security.kubernetes.io/enforce=restricted"

        print_result "네임스페이스 공유 금지" "취약" "$detail" "$recommendation"
    fi
}

# 환경설정 파일 권한 설정 검사
check_config_file_permissions() {
    if [ "$DEV_MODE" = true ]; then
        print_result "환경설정 파일 권한 설정" "검사 제외" \
            "[개발 모드] 환경설정 파일 권한 설정 검사를 건너뜁니다.\n\n\
[검사 대상 파일]\n\
- /etc/kubernetes/manifests/kube-apiserver.yaml\n\
- /etc/kubernetes/manifests/kube-controller-manager.yaml\n\
- /etc/kubernetes/manifests/kube-scheduler.yaml\n\
- /etc/kubernetes/manifests/etcd.yaml\n\
- /etc/kubernetes/admin.conf\n\
- /etc/kubernetes/scheduler.conf\n\
- /etc/kubernetes/controller-manager.conf"
        return
    fi

    local detail=""
    local recommendation=""
    local is_secure=true
    local manifest_dir="/etc/kubernetes/manifests"
    local kube_dir="/etc/kubernetes"
    
    # 검사할 파일 목록
    local config_files=(
        "$manifest_dir/kube-apiserver.yaml"
        "$manifest_dir/kube-controller-manager.yaml"
        "$manifest_dir/kube-scheduler.yaml"
        "$manifest_dir/etcd.yaml"
        "$kube_dir/admin.conf"
        "$kube_dir/scheduler.conf"
        "$kube_dir/controller-manager.conf"
    )

    local files_exist=false
    local insecure_files=0
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            files_exist=true
            # 파일 권한, 소유자, 그룹 정보 가져오기
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")
            local group=$(stat -c "%G" "$file")
            
            local file_name=$(basename "$file")
            detail+="$file_name 검사 결과:\n"
            detail+="- 현재 권한: $perms\n"
            detail+="- 소유자: $owner\n"
            detail+="- 그룹: $group\n"
            
            # 권한이 644보다 큰지 확인 (8진수로 비교)
            if [ "$perms" -gt "644" ]; then
                detail+="- 권한이 644보다 큽니다.\n"
                recommendation+="1) $file_name의 권한을 644 이하로 변경하세요:\n"
                recommendation+="   chmod 644 $file\n"
                is_secure=false
                insecure_files=$((insecure_files + 1))
            fi
            
            # 소유자와 그룹이 root인지 확인
            if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                detail+="- 소유자 또는 그룹이 root가 아닙니다.\n"
                recommendation+="2) $file_name의 소유자와 그룹을 root로 변경하세요:\n"
                recommendation+="   chown root:root $file\n"
                is_secure=false
                insecure_files=$((insecure_files + 1))
            fi
            
            detail+="\n"
        else
            detail+="$file 파일이 존재하지 않습니다.\n\n"
        fi
    done

    if [ "$files_exist" = false ]; then
        print_result "환경설정 파일 권한 설정" "검사 불가" \
            "검사 대상 파일이 존재하지 않습니다.\n\n\
[검사 대상 파일]\n\
- /etc/kubernetes/manifests/kube-apiserver.yaml\n\
- /etc/kubernetes/manifests/kube-controller-manager.yaml\n\
- /etc/kubernetes/manifests/kube-scheduler.yaml\n\
- /etc/kubernetes/manifests/etcd.yaml\n\
- /etc/kubernetes/admin.conf\n\
- /etc/kubernetes/scheduler.conf\n\
- /etc/kubernetes/controller-manager.conf"
        return
    fi

    if [ "$is_secure" = true ]; then
        print_result "환경설정 파일 권한 설정" "양호" \
            "모든 환경설정 파일의 권한이 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 모든 파일의 소유자와 그룹이 root로 설정됨\n\
- 모든 파일의 권한이 644 이하로 설정됨"
    else
        detail+="\n[권장 설정]\n"
        detail+="- 파일 소유자: root\n"
        detail+="- 파일 그룹: root\n"
        detail+="- 파일 권한: 644 이하\n\n"
        detail+="총 $insecure_files 개의 파일이 부적절한 권한으로 설정되어 있습니다."

        print_result "환경설정 파일 권한 설정" "취약" "$detail" "$recommendation"
    fi
}

# 인증서 파일 권한 설정 검사
check_cert_file_permissions() {
    if [ "$DEV_MODE" = true ]; then
        print_result "인증서 파일 권한 설정" "검사 제외" \
            "[개발 모드] 인증서 파일 권한 설정 검사를 건너뜁니다.\n\n\
[검사 대상 파일]\n\
- /etc/kubernetes/pki/*.crt\n\
- /etc/kubernetes/pki/*.key\n\
- /etc/kubernetes/pki/etcd/*.crt\n\
- /etc/kubernetes/pki/etcd/*.key"
        return
    fi

    local detail=""
    local recommendation=""
    local is_secure=true
    local pki_dir="/etc/kubernetes/pki"
    
    # 검사할 인증서 파일 목록
    local cert_files=(
        "$pki_dir/ca.crt"
        "$pki_dir/ca.key"
        "$pki_dir/apiserver.crt"
        "$pki_dir/apiserver.key"
        "$pki_dir/apiserver-kubelet-client.crt"
        "$pki_dir/apiserver-kubelet-client.key"
        "$pki_dir/front-proxy-ca.crt"
        "$pki_dir/front-proxy-ca.key"
        "$pki_dir/front-proxy-client.crt"
        "$pki_dir/front-proxy-client.key"
        "$pki_dir/etcd/ca.crt"
        "$pki_dir/etcd/ca.key"
        "$pki_dir/etcd/server.crt"
        "$pki_dir/etcd/server.key"
        "$pki_dir/etcd/peer.crt"
        "$pki_dir/etcd/peer.key"
    )

    local files_exist=false
    local insecure_files=0
    for file in "${cert_files[@]}"; do
        if [ -f "$file" ]; then
            files_exist=true
            # 파일 권한, 소유자, 그룹 정보 가져오기
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")
            local group=$(stat -c "%G" "$file")
            local is_key=$(echo "$file" | grep -q "\.key$" && echo true || echo false)
            
            local file_name=$(basename "$file")
            detail+="$file_name 검사 결과:\n"
            detail+="- 현재 권한: $perms\n"
            detail+="- 소유자: $owner\n"
            detail+="- 그룹: $group\n"
            
            # 키 파일은 600, 인증서 파일은 644 권한 체크
            if [ "$is_key" = true ] && [ "$perms" -gt "600" ]; then
                detail+="- 키 파일의 권한이 600보다 큽니다.\n"
                recommendation+="1) $file_name의 권한을 600으로 변경하세요:\n"
                recommendation+="   chmod 600 $file\n"
                is_secure=false
                insecure_files=$((insecure_files + 1))
            elif [ "$is_key" = false ] && [ "$perms" -gt "644" ]; then
                detail+="- 인증서 파일의 권한이 644보다 큽니다.\n"
                recommendation+="1) $file_name의 권한을 644로 변경하세요:\n"
                recommendation+="   chmod 644 $file\n"
                is_secure=false
                insecure_files=$((insecure_files + 1))
            fi
            
            # 소유자와 그룹이 root인지 확인
            if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                detail+="- 소유자 또는 그룹이 root가 아닙니다.\n"
                recommendation+="2) $file_name의 소유자와 그룹을 root로 변경하세요:\n"
                recommendation+="   chown root:root $file\n"
                is_secure=false
                insecure_files=$((insecure_files + 1))
            fi
            
            detail+="\n"
        else
            detail+="$file 파일이 존재하지 않습니다.\n\n"
        fi
    done

    if [ "$files_exist" = false ]; then
        print_result "인증서 파일 권한 설정" "검사 불가" \
            "검사 대상 파일이 존재하지 않습니다.\n\n\
[검사 대상 파일]\n\
- /etc/kubernetes/pki/*.crt\n\
- /etc/kubernetes/pki/*.key\n\
- /etc/kubernetes/pki/etcd/*.crt\n\
- /etc/kubernetes/pki/etcd/*.key"
        return
    fi

    if [ "$is_secure" = true ]; then
        print_result "인증서 파일 권한 설정" "양호" \
            "모든 인증서 파일의 권한이 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 모든 파일의 소유자와 그룹이 root로 설정됨\n\
- 키 파일(.key)의 권한이 600 이하로 설정됨\n\
- 인증서 파일(.crt)의 권한이 644 이하로 설정됨"
    else
        detail+="\n[권장 설정]\n"
        detail+="- 파일 소유자: root\n"
        detail+="- 파일 그룹: root\n"
        detail+="- 파일 권한: 644 이하\n\n"
        detail+="총 $insecure_files 개의 파일이 부적절한 권한으로 설정되어 있습니다."

        print_result "인증서 파일 권한 설정" "취약" "$detail" "$recommendation"
    fi
}

# etcd 데이터 디렉터리 권한 설정 검사
check_etcd_dir_permissions() {
    local detail=""
    local recommendation=""
    local is_secure=true
    local etcd_dir="/var/lib/etcd"
    
    # etcd 전용 계정 목록 (필요한 경우 추가)
    local valid_users=("root" "etcd")
    local valid_groups=("root" "etcd")
    
    if [ -d "$etcd_dir" ]; then
        # 디렉터리 권한, 소유자, 그룹 정보 가져오기
        local perms=$(stat -c "%a" "$etcd_dir")
        local owner=$(stat -c "%U" "$etcd_dir")
        local group=$(stat -c "%G" "$etcd_dir")
        
        detail+="etcd 데이터 디렉터리 검사 결과:\n"
        detail+="- 경로: $etcd_dir\n"
        detail+="- 현재 권한: $perms\n"
        detail+="- 소유자: $owner\n"
        detail+="- 그룹: $group\n"
        
        # 권한이 700보다 큰지 확인
        if [ "$perms" -gt "700" ]; then
            detail+="- 디렉터리 권한이 700보다 큽니다.\n"
            recommendation+="1) etcd 데이터 디렉터리의 권한을 700으로 변경하세요:\n"
            recommendation+="   chmod 700 $etcd_dir\n"
            is_secure=false
        fi
        
        # 소유자가 허용된 계정인지 확인
        local valid_owner=false
        local valid_group=false
        
        for valid_user in "${valid_users[@]}"; do
            if [ "$owner" = "$valid_user" ]; then
                valid_owner=true
                break
            fi
        done
        
        for valid_group_name in "${valid_groups[@]}"; do
            if [ "$group" = "$valid_group_name" ]; then
                valid_group=true
                break
            fi
        done
        
        if [ "$valid_owner" = false ]; then
            detail+="- 소유자가 허용된 계정(${valid_users[*]})이 아닙니다.\n"
            recommendation+="2) etcd 데이터 디렉터리의 소유자를 root 또는 전용 계정으로 변경하세요:\n"
            recommendation+="   chown root $etcd_dir\n"
            is_secure=false
        fi
        
        if [ "$valid_group" = false ]; then
            detail+="- 그룹이 허용된 그룹(${valid_groups[*]})이 아닙니다.\n"
            recommendation+="3) etcd 데이터 디렉터리의 그룹을 root 또는 전용 그룹으로 변경하세요:\n"
            recommendation+="   chgrp root $etcd_dir\n"
            is_secure=false
        fi
        
        # etcd 데이터 파일 검사
        local data_files=$(find "$etcd_dir" -type f 2>/dev/null)
        if [ ! -z "$data_files" ]; then
            detail+="\netcd 데이터 파일 검사 결과:\n"
            local insecure_files=0
            
            while IFS= read -r file; do
                local file_perms=$(stat -c "%a" "$file")
                local file_owner=$(stat -c "%U" "$file")
                local file_group=$(stat -c "%G" "$file")
                local file_name=$(basename "$file")
                
                if [ "$file_perms" -gt "600" ]; then
                    detail+="$file_name:\n"
                    detail+="- 현재 권한: $file_perms (600 초과)\n"
                    detail+="- 소유자: $file_owner\n"
                    detail+="- 그룹: $file_group\n"
                    recommendation+="4) etcd 데이터 파일의 권한을 600 이하로 변경하세요:\n"
                    recommendation+="   chmod 600 $file\n"
                    is_secure=false
                    insecure_files=$((insecure_files + 1))
                fi
                
                local file_valid_owner=false
                local file_valid_group=false
                
                for valid_user in "${valid_users[@]}"; do
                    if [ "$file_owner" = "$valid_user" ]; then
                        file_valid_owner=true
                        break
                    fi
                done
                
                for valid_group_name in "${valid_groups[@]}"; do
                    if [ "$file_group" = "$valid_group_name" ]; then
                        file_valid_group=true
                        break
                    fi
                done
                
                if [ "$file_valid_owner" = false ] || [ "$file_valid_group" = false ]; then
                    if [ "$file_valid_owner" = false ]; then
                        detail+="$file_name:\n"
                        detail+="- 소유자($file_owner)가 허용된 계정이 아닙니다.\n"
                    fi
                    if [ "$file_valid_group" = false ]; then
                        detail+="$file_name:\n"
                        detail+="- 그룹($file_group)이 허용된 그룹이 아닙니다.\n"
                    fi
                    recommendation+="5) etcd 데이터 파일의 소유자와 그룹을 변경하세요:\n"
                    recommendation+="   chown root:root $file\n"
                    is_secure=false
                    insecure_files=$((insecure_files + 1))
                fi
            done <<< "$data_files"
            
            if [ $insecure_files -gt 0 ]; then
                detail+="\n총 $insecure_files 개의 데이터 파일이 부적절한 권한으로 설정되어 있습니다.\n"
            fi
        fi
    else
        detail+="etcd 데이터 디렉터리($etcd_dir)가 존재하지 않습니다.\n"
        is_secure=false
    fi

    if [ "$is_secure" = true ]; then
        print_result "etcd 데이터 디렉터리 권한 설정" "양호" \
            "etcd 데이터 디렉터리의 권한이 적절하게 설정되어 있습니다.\n\n\
[현재 설정]\n\
- 디렉터리 소유자가 root 또는 전용 계정으로 설정됨\n\
- 디렉터리 그룹이 root 또는 전용 그룹으로 설정됨\n\
- 디렉터리 권한이 700 이하로 설정됨\n\
- 모든 데이터 파일의 권한이 600 이하로 설정됨"
    else
        detail+="\n[권장 설정]\n"
        detail+="- 디렉터리 소유자: root 또는 etcd\n"
        detail+="- 디렉터리 그룹: root 또는 etcd\n"
        detail+="- 디렉터리 권한: 700 이하\n"
        detail+="- 데이터 파일 권한: 600 이하\n"

        print_result "etcd 데이터 디렉터리 권한 설정" "취약" "$detail" "$recommendation"
    fi
}

# 최신 보안 패치 적용 검사
check_version_update() {
    local detail=""
    local recommendation=""
    local is_secure=true
    
    # kubectl 버전 정보 가져오기
    local version_info=$(kubectl version 2>/dev/null)
    if [ -z "$version_info" ]; then
        print_result "최신 보안 패치 적용" "검사 불가" \
            "kubectl 버전 정보를 가져올 수 없습니다." \
            "kubectl 명령어 실행 권한을 확인하세요."
        return
    fi

    # 버전 정보 출력
    detail+="[현재 버전 정보]\n"
    detail+="$version_info\n\n"

    # 서버 버전만 추출
    local server_version=$(echo "$version_info" | grep "Server Version" | grep -o "v[0-9]*\.[0-9]*\.[0-9]*")
    
    if [ -z "$server_version" ]; then
        print_result "최신 보안 패치 적용" "검사 불가" \
            "서버 버전 정보를 가져올 수 없습니다." \
            "API 서버 연결 상태를 확인하세요."
        return
    fi

    # 버전 비교 (1.25.0 이상인지 확인)
    if [[ "$server_version" < "v1.25.0" ]]; then
        detail+="[진단 결과]\n"
        detail+="현재 버전($server_version)은 지원이 종료되었거나 곧 종료될 예정입니다.\n"
        recommendation="1) 최신 안정 버전으로 업그레이드하세요.\n"
        recommendation+="2) 업그레이드 전 시스템 영향도 평가 및 테스트를 진행하세요."
        is_secure=false
    else
        detail+="[진단 결과]\n"
        detail+="현재 버전($server_version)은 지원되는 버전입니다.\n"
        detail+="정기적인 보안 패치 적용을 권장합니다."
    fi

    if [ "$is_secure" = true ]; then
        print_result "최신 보안 패치 적용" "양호" "$detail"
    else
        print_result "최신 보안 패치 적용" "취약" "$detail" "$recommendation"
    fi
}

# 메인 함수
main() {
    print_logo
    print_output "${BOLD}[Kubernetes Master 노드 보안 진단 시작]${NC}\n" \
                "[Kubernetes Master 노드 보안 진단 시작]\n"
    
    # API Server Configuration 검사
    print_output "${BLUE}[가. API Server Configuration]${NC}" \
                "[가. API Server Configuration]"
    
    check_anonymous_auth
    check_insecure_auth
    check_service_api_binding
    check_api_authorization
    check_admission_control
    check_api_ssl_tls
    check_api_logging

    # Controller Manager Configuration 검사
    print_output "\n${BLUE}[나. Controller Manager Configuration]${NC}" \
                "\n[나. Controller Manager Configuration]"
    
    check_controller_auth
    check_controller_ssl_tls

    # etcd Configuration 검사
    print_output "\n${BLUE}[다. etcd Configuration]${NC}" \
                "\n[다. etcd Configuration]"
    
    check_etcd_encryption
    check_etcd_ssl_tls

    # PodSecurityAdmission Configuration 검사
    print_output "\n${BLUE}[라. PodSecurityAdmission Configuration]${NC}" \
                "\n[라. PodSecurityAdmission Configuration]"
    
    check_container_privileges
    check_namespace_isolation

    # 파일 권한 설정 검사
    print_output "\n${BLUE}[마. 파일 권한 설정]${NC}" \
                "\n[마. 파일 권한 설정]"
    
    check_config_file_permissions
    check_cert_file_permissions
    check_etcd_dir_permissions

    # 패치 관리 검사
    print_output "\n${BLUE}[바. 패치 관리]${NC}" \
                "\n[바. 패치 관리]"
    
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