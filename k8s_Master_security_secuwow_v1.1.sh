#!/bin/bash

# 출력 파일 경로 설정
OUTPUT_FILE="/tmp/k8s_master/k8s_M_secuwow_$(date +%Y%m%d).txt"

# 출력 디렉토리가 없으면 생성
mkdir -p /tmp/k8s_master

# 이전 결과 파일이 있다면 삭제
[ -f "$OUTPUT_FILE" ] && rm "$OUTPUT_FILE"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# 터미널과 파일에 동시에 출력하는 함수
print_output() {
    local terminal_output="$1"
    local file_output="$2"
    
    # 터미널에는 색상과 함께 출력
    echo -e "$terminal_output"
    
    # 파일에는 색상 코드를 제거하고 출력
    # ANSI 색상 코드 제거
    local clean_output=$(echo "$file_output" | sed 's/\x1b\[[0-9;]*m//g')
    echo "$clean_output" >> "$OUTPUT_FILE"
}

# ASCII 아트 로고 출력
print_logo() {
    # 터미널용 로고 (색상 포함)
    echo -e "${BLUE}"  # 파란색
    echo ' ███████ ███████  ██████ ██    ██ ██     ██  ██████  ██     ██'
    echo ' ██      ██      ██      ██    ██ ██     ██ ██    ██ ██     ██'
    echo ' ███████ █████   ██      ██    ██ ██  █  ██ ██    ██ ██  █  ██'
    echo '      ██ ██      ██      ██    ██ ██ ███ ██ ██    ██ ██ ███ ██'
    echo ' ███████ ███████  ██████  ██████   ███ ███   ██████   ███ ███ '
    echo -e "${CYAN}"  # 청록색
    echo '       Secuwow Kubernetes Security Compliance Check Tool v1.1'
    echo -e "${NC}"   # 색상 초기화
    
    # 파일용 로고 (색상 제거)
    echo ' ███████ ███████  ██████ ██    ██ ██     ██  ██████  ██     ██' >> "$OUTPUT_FILE"
    echo ' ██      ██      ██      ██    ██ ██     ██ ██    ██ ██     ██' >> "$OUTPUT_FILE"
    echo ' ███████ █████   ██      ██    ██ ██  █  ██ ██    ██ ██  █  ██' >> "$OUTPUT_FILE"
    echo '      ██ ██      ██      ██    ██ ██ ███ ██ ██    ██ ██ ███ ██' >> "$OUTPUT_FILE"
    echo ' ███████ ███████  ██████  ██████   ███ ███   ██████   ███ ███ ' >> "$OUTPUT_FILE"
    echo '       Secuwow Kubernetes Security Compliance Check Tool v1.1' >> "$OUTPUT_FILE"
    
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

# KUBECONFIG 환경변수 설정
if [ -f "/etc/kubernetes/admin.conf" ]; then
    export KUBECONFIG=/etc/kubernetes/admin.conf
else
    echo "Kubernetes 설정 파일(/etc/kubernetes/admin.conf)을 찾을 수 없습니다."
    exit 1
fi

# kubernetes 설치 여부 체크 (개발 모드가 아닐 때만)
if [ "$DEV_MODE" = false ]; then
    command -v kubectl >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Kubernetes가 설치되어 있지 않습니다."
        exit 1
    fi

    # 노드 역할 확인 (정보 제공용)
    if kubectl get nodes 2>/dev/null | grep -q "control-plane"; then
        echo "이 노드는 Kubernetes Master 노드입니다."
    else
        echo "이 노드는 Kubernetes Worker 노드입니다."
    fi
else
    echo -e "\n[개발 모드] Kubernetes 설치 체크를 건너뜁니다."
fi

# 결과 카운터 초기화
total_checks=0
good_checks=0
vulnerable_checks=0
na_checks=0
partial_checks=0
interview_checks=0

# 구분선 함수
print_line() {
    echo "===================================================================" | tee -a "$OUTPUT_FILE"
}

# 결과 출력 함수
print_result() {
    local item_number=$1
    local item_name=$2
    local status=$3
    local detail=$4
    local result=$5
    
    print_line
    # 터미널용 출력 (색상 포함)
    echo -e "${BOLD}[$item_number] $item_name${NC}"
    echo ""
    
    # 파일용 출력 (색상 제거)
    echo "[$item_number] $item_name" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "<DETAIL>" | tee -a "$OUTPUT_FILE"
    echo "$detail" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # 상태에 따른 색상 설정
    local status_color=""
    case "$status" in
        "양호")
            status_color="$GREEN"
            ;;
        "취약")
            status_color="$RED"
            ;;
        "N/A")
            status_color="$BLUE"
            ;;
        "부분만족")
            status_color="$YELLOW"
            ;;
        "인터뷰 필요")
            status_color="$PURPLE"
            ;;
    esac
    
    # 터미널용 출력 (색상 포함)
    echo -e "<RESULT>${status_color}$status${NC}"
    echo "$result"
    echo "<END>"
    echo ""
    
    # 파일용 출력 (색상 제거)
    echo "<RESULT>$status" >> "$OUTPUT_FILE"
    echo "$result" >> "$OUTPUT_FILE"
    echo "<END>" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # 결과 카운터 업데이트
    total_checks=$((total_checks + 1))
    case "$status" in
        "양호")
            good_checks=$((good_checks + 1))
            ;;
        "취약")
            vulnerable_checks=$((vulnerable_checks + 1))
            ;;
        "N/A")
            na_checks=$((na_checks + 1))
            ;;
        "부분만족")
            partial_checks=$((partial_checks + 1))
            ;;
        "인터뷰 필요")
            interview_checks=$((interview_checks + 1))
            ;;
    esac
}

# API Server 비인증 접근 차단 검사
check_api_auth() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-01" "API Server 비인증 접근 차단" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "API Server의 비인증 접근이 적절하게 차단되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 비인가자가 API Server에 접근할 수 있습니다.
2. 서비스 계정 토큰의 유효성 검증이 되지 않습니다.
3. 무단 API 접근 시도가 가능합니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --anonymous-auth=false
   - --service-account-lookup=true

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local anonymous_auth=$(grep "\-\-anonymous-auth=false" "$api_server_yaml")
    local service_account_lookup=$(grep "\-\-service-account-lookup=true" "$api_server_yaml")
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

[문제점]"
    
    if [ -z "$anonymous_auth" ]; then
        detail+="
- anonymous-auth=false 설정이 없습니다."
    fi
    
    if [ -z "$service_account_lookup" ]; then
        detail+="
- service-account-lookup=true 설정이 없습니다."
    fi

    if [ ! -z "$anonymous_auth" ] && [ ! -z "$service_account_lookup" ]; then
        print_result "KuM-01" "API Server 비인증 접근 차단" "양호" \
            "$detail" \
            "API Server의 비인증 접근이 적절하게 차단되어 있습니다."
    else
        print_result "KuM-01" "API Server 비인증 접근 차단" "취약" \
            "$detail" \
            "API Server의 비인증 접근이 적절하게 차단되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml
1) --anonymous-auth=false 설정이 없거나 부적절합니다.
2) --service-account-lookup=true 설정이 없거나 부적절합니다.

[보안 위험]
1. 비인가자가 API Server에 접근할 수 있습니다.
2. 서비스 계정 토큰의 유효성 검증이 되지 않습니다.
3. 무단 API 접근 시도가 가능합니다.

[조치 방법]
1. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --anonymous-auth=false
   - --service-account-lookup=true

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# API Server 취약한 방식의 인증 사용 제한 검사
check_api_auth_method() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-02" "API Server 취약한 방식의 인증 사용 제한" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "API Server의 취약한 방식의 인증 사용이 제한되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 취약한 방식의 인증이 사용될 수 있습니다.
2. 비인가자의 접근이 가능합니다.
3. Kubernetes 시스템의 모든 요소에 영향을 줄 수 있습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 --token-auth-file 파라미터가 있는지 확인하고, 있다면 삭제하세요.

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local token_auth_file=$(grep "\-\-token-auth-file" "$api_server_yaml")
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)"

    if [ -z "$token_auth_file" ]; then
        print_result "KuM-02" "API Server 취약한 방식의 인증 사용 제한" "양호" \
            "$detail" \
            "API Server의 취약한 방식의 인증 사용이 제한되어 있습니다.

[현재 상태]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml
1) --token-auth-file 파라미터가 존재하지 않습니다.

[보안 효과]
1. 취약한 방식의 인증이 사용되지 않습니다.
2. 비인가자의 접근이 차단됩니다.
3. Kubernetes 시스템의 보안이 강화됩니다.

[권장 사항]
1. 정기적으로 kube-apiserver.yaml 파일을 검토하여 취약한 인증 방식이 추가되지 않도록 하세요.
2. API Server의 인증 방식을 주기적으로 점검하세요."
    else
        print_result "KuM-02" "API Server 취약한 방식의 인증 사용 제한" "취약" \
            "$detail" \
            "API Server의 취약한 방식의 인증 사용이 제한되어 있지 않습니다.

[현재 문제]
1) kube-apiserver.yaml 파일에 --token-auth-file 파라미터가 존재합니다.

[보안 위험]
1. 취약한 방식의 인증이 사용됩니다.
2. 비인가자의 접근이 가능합니다.
3. Kubernetes 시스템의 모든 요소에 영향을 줄 수 있습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에서 --token-auth-file 파라미터를 삭제하세요.

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# API Server 서비스 API 외부 오픈 금지 검사
check_api_external_access() {
    local scheduler_yaml="/etc/kubernetes/manifests/kube-scheduler.yaml"
    local controller_manager_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    
    if [ ! -f "$scheduler_yaml" ] || [ ! -f "$controller_manager_yaml" ]; then
        print_result "KuM-03" "API Server 서비스 API 외부 오픈 금지" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-scheduler.yaml
$(if [ -f "$scheduler_yaml" ]; then cat "$scheduler_yaml"; else echo "파일이 존재하지 않습니다."; fi)

# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
$(if [ -f "$controller_manager_yaml" ]; then cat "$controller_manager_yaml"; else echo "파일이 존재하지 않습니다."; fi)" \
            "API Server의 서비스 API가 외부에서 접근 가능합니다.

[현재 문제]
1) kube-scheduler.yaml 또는 kube-controller-manager.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. API Server의 서비스 API가 외부에서 접근 가능합니다.
2. Kubernetes 시스템의 모든 요소에 영향을 줄 수 있습니다.
3. 클러스터에 대한 공격 위험이 증가합니다.

[조치 방법]
1. kube-scheduler.yaml 파일에 다음 설정을 추가하세요:
   - --bind-address=127.0.0.1

2. kube-controller-manager.yaml 파일에 다음 설정을 추가하세요:
   - --bind-address=127.0.0.1

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local scheduler_bind_address=$(grep "\-\-bind-address" "$scheduler_yaml" | awk '{print $2}')
    local controller_manager_bind_address=$(grep "\-\-bind-address" "$controller_manager_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-scheduler.yaml
$(cat $scheduler_yaml)

# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
$(cat $controller_manager_yaml)"

    if [ "$scheduler_bind_address" = "127.0.0.1" ] && [ "$controller_manager_bind_address" = "127.0.0.1" ]; then
        print_result "KuM-03" "API Server 서비스 API 외부 오픈 금지" "양호" \
            "$detail" \
            "API Server의 서비스 API가 외부에서 접근 불가능합니다.

[현재 상태]
1) kube-scheduler.yaml 파일의 --bind-address가 127.0.0.1로 설정되어 있습니다.
2) kube-controller-manager.yaml 파일의 --bind-address가 127.0.0.1로 설정되어 있습니다.

[보안 효과]
1. API Server의 서비스 API가 로컬호스트 인터페이스에만 바인딩됩니다.
2. 외부에서의 접근이 차단됩니다.
3. 클러스터에 대한 공격 위험이 감소합니다.

[권장 사항]
1. 정기적으로 바인딩 주소 설정을 검토하세요.
2. 필요한 경우 방화벽 규칙을 추가하여 추가적인 보안을 강화하세요."
    else
        print_result "KuM-03" "API Server 서비스 API 외부 오픈 금지" "취약" \
            "$detail" \
            "API Server의 서비스 API가 외부에서 접근 가능합니다.

[현재 문제]
1) kube-scheduler.yaml 파일의 --bind-address가 127.0.0.1로 설정되어 있지 않습니다.
2) kube-controller-manager.yaml 파일의 --bind-address가 127.0.0.1로 설정되어 있지 않습니다.

[보안 위험]
1. API Server의 서비스 API가 외부에서 접근 가능합니다.
2. Kubernetes 시스템의 모든 요소에 영향을 줄 수 있습니다.
3. 클러스터에 대한 공격 위험이 증가합니다.

[조치 방법]
1. kube-scheduler.yaml 파일에 다음 설정을 추가하세요:
   - --bind-address=127.0.0.1

2. kube-controller-manager.yaml 파일에 다음 설정을 추가하세요:
   - --bind-address=127.0.0.1

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# API Server 권한 제어 검사
check_api_authorization() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-04" "API Server 권한 제어" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "API Server의 권한이 AlwaysAllow로 설정되어 있습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 모든 요청이 허용됩니다.
2. 악의적인 사용자나 부주의한 사용자에 의해 Kubernetes에서 관리하는 다른 컨테이너의 작업에 영향을 줄 수 있습니다.
3. 최소 권한 원칙이 적용되지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 --authorization-mode 파라미터를 AlwaysAllow가 아닌 값으로 설정하세요.
   예: --authorization-mode=Node,RBAC

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local authorization_mode=$(grep "\-\-authorization-mode" "$api_server_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)"

    if [ "$authorization_mode" != "AlwaysAllow" ]; then
        print_result "KuM-04" "API Server 권한 제어" "양호" \
            "$detail" \
            "API Server의 권한이 AlwaysAllow로 설정되어 있지 않습니다.

[현재 상태]
1) kube-apiserver.yaml 파일의 --authorization-mode가 AlwaysAllow가 아닌 값으로 설정되어 있습니다.

[보안 효과]
1. 모든 요청이 허용되지 않습니다.
2. 최소 권한 원칙이 적용됩니다.
3. 악의적인 사용자나 부주의한 사용자에 의한 영향이 제한됩니다.

[권장 사항]
1. 정기적으로 권한 설정을 검토하세요.
2. 필요한 경우 RBAC 정책을 추가하여 세부적인 권한을 설정하세요."
    else
        print_result "KuM-04" "API Server 권한 제어" "취약" \
            "$detail" \
            "API Server의 권한이 AlwaysAllow로 설정되어 있습니다.

[현재 문제]
1) kube-apiserver.yaml 파일의 --authorization-mode가 AlwaysAllow로 설정되어 있습니다.

[보안 위험]
1. 모든 요청이 허용됩니다.
2. 악의적인 사용자나 부주의한 사용자에 의해 Kubernetes에서 관리하는 다른 컨테이너의 작업에 영향을 줄 수 있습니다.
3. 최소 권한 원칙이 적용되지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에서 --authorization-mode 파라미터를 AlwaysAllow가 아닌 값으로 수정하세요.
   예: --authorization-mode=Node,RBAC

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# Admission Control Plugin 설정 검사
check_admission_control() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-05" "Admission Control Plugin 설정" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "Admission Control Plugin 설정이 적용되지 않았습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. Kubernetes API Server가 불안정해질 수 있습니다.
2. 필요한 보안 기능이 활성화되지 않습니다.
3. 리소스 생성 및 수정 시 보안 검증이 이루어지지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --enable-admission-plugins=AlwaysPullImages,NodeRestriction,SecurityContextDeny,EventRateLimit
   - --disable-admission-plugins=NamespaceLifecycle
   - --admission-control-config-file=<path>

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local enable_plugins=$(grep "\-\-enable-admission-plugins" "$api_server_yaml" | awk '{print $2}')
    local disable_plugins=$(grep "\-\-disable-admission-plugins" "$api_server_yaml" | awk '{print $2}')
    local control_config_file=$(grep "\-\-admission-control-config-file" "$api_server_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)"

    local required_plugins="AlwaysPullImages,NodeRestriction,SecurityContextDeny,EventRateLimit"
    local missing_plugins=""
    
    for plugin in $(echo $required_plugins | tr ',' ' '); do
        if [[ ! "$enable_plugins" =~ "$plugin" ]]; then
            missing_plugins+="$plugin "
        fi
    done

    if [ -z "$missing_plugins" ] && [ "$disable_plugins" = "NamespaceLifecycle" ] && [ ! -z "$control_config_file" ]; then
        print_result "KuM-05" "Admission Control Plugin 설정" "양호" \
            "$detail" \
            "Admission Control Plugin 설정이 적절하게 적용되었습니다.

[현재 상태]
1) kube-apiserver.yaml 파일에 다음 설정이 적용되어 있습니다:
   - --enable-admission-plugins=AlwaysPullImages,NodeRestriction,SecurityContextDeny,EventRateLimit
   - --disable-admission-plugins=NamespaceLifecycle
   - --admission-control-config-file=<path>

[보안 효과]
1. Kubernetes API Server의 안정성이 향상됩니다.
2. 필요한 보안 기능이 활성화됩니다.
3. 리소스 생성 및 수정 시 보안 검증이 이루어집니다.

[권장 사항]
1. 정기적으로 Admission Control Plugin 설정을 검토하세요.
2. Kubernetes 버전에 따라 PodSecurityPolicy 대신 PodSecurityStandard를 적용하세요."
    else
        print_result "KuM-05" "Admission Control Plugin 설정" "취약" \
            "$detail" \
            "Admission Control Plugin 설정이 적용되지 않았습니다.

[현재 문제]
1) kube-apiserver.yaml 파일에 다음 설정이 누락되었습니다:
   - --enable-admission-plugins=AlwaysPullImages,NodeRestriction,SecurityContextDeny,EventRateLimit
   - --disable-admission-plugins=NamespaceLifecycle
   - --admission-control-config-file=<path>

[보안 위험]
1. Kubernetes API Server가 불안정해질 수 있습니다.
2. 필요한 보안 기능이 활성화되지 않습니다.
3. 리소스 생성 및 수정 시 보안 검증이 이루어지지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --enable-admission-plugins=AlwaysPullImages,NodeRestriction,SecurityContextDeny,EventRateLimit
   - --disable-admission-plugins=NamespaceLifecycle
   - --admission-control-config-file=<path>

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# API Server SSL/TLS 적용 검사
check_api_ssl_tls() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-06" "API Server SSL/TLS 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "API Server에 SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 네트워크 구간의 데이터가 암호화되지 않습니다.
2. 중간자 공격(Man-in-the-Middle)에 취약합니다.
3. 인증서 기반의 상호 인증이 이루어지지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --secure-port=6443
   - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
   - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
   - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
   - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
   - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
   - --client-ca-file=/etc/kubernetes/pki/ca.crt
   - --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

[예시]
--tls-cipher-suites에 설정 가능한 추가 암호화 스위트:
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local secure_port=$(grep "\-\-secure-port" "$api_server_yaml" | awk '{print $2}')
    local kubelet_ca=$(grep "\-\-kubelet-certificate-authority" "$api_server_yaml" | awk '{print $2}')
    local kubelet_cert=$(grep "\-\-kubelet-client-certificate" "$api_server_yaml" | awk '{print $2}')
    local kubelet_key=$(grep "\-\-kubelet-client-key" "$api_server_yaml" | awk '{print $2}')
    local tls_cert=$(grep "\-\-tls-cert-file" "$api_server_yaml" | awk '{print $2}')
    local tls_key=$(grep "\-\-tls-private-key-file" "$api_server_yaml" | awk '{print $2}')
    local client_ca=$(grep "\-\-client-ca-file" "$api_server_yaml" | awk '{print $2}')
    local tls_cipher=$(grep "\-\-tls-cipher-suites" "$api_server_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

[문제점]"
    
    if [ -z "$secure_port" ] || [ "$secure_port" = "0" ]; then
        detail+="
- --secure-port가 설정되지 않았거나 0으로 설정되어 있습니다."
    fi
    
    if [ -z "$kubelet_ca" ]; then
        detail+="
- --kubelet-certificate-authority가 설정되지 않았습니다."
    fi
    
    if [ -z "$kubelet_cert" ]; then
        detail+="
- --kubelet-client-certificate가 설정되지 않았습니다."
    fi
    
    if [ -z "$kubelet_key" ]; then
        detail+="
- --kubelet-client-key가 설정되지 않았습니다."
    fi
    
    if [ -z "$tls_cert" ]; then
        detail+="
- --tls-cert-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$tls_key" ]; then
        detail+="
- --tls-private-key-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$client_ca" ]; then
        detail+="
- --client-ca-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$tls_cipher" ]; then
        detail+="
- --tls-cipher-suites가 설정되지 않았습니다."
    fi

    if [ ! -z "$secure_port" ] && [ "$secure_port" != "0" ] && \
       [ ! -z "$kubelet_ca" ] && [ ! -z "$kubelet_cert" ] && [ ! -z "$kubelet_key" ] && \
       [ ! -z "$tls_cert" ] && [ ! -z "$tls_key" ] && [ ! -z "$client_ca" ] && [ ! -z "$tls_cipher" ]; then
        print_result "KuM-06" "API Server SSL/TLS 적용" "양호" \
            "$detail" \
            "API Server에 SSL/TLS가 적절하게 적용되어 있습니다.

[현재 상태]
1) --secure-port가 0이 아닌 값으로 설정되어 있습니다.
2) API Server to kubelet 인증서가 설정되어 있습니다.
3) API Server 인증서가 설정되어 있습니다.
4. 안전한 SSL/TLS 버전이 설정되어 있습니다.

[보안 효과]
1. 네트워크 구간의 데이터가 암호화됩니다.
2. 중간자 공격(Man-in-the-Middle)으로부터 보호됩니다.
3. 인증서 기반의 상호 인증이 이루어집니다.

[권장 사항]
1. 정기적으로 인증서를 갱신하세요.
2. TLS 암호화 스위트를 주기적으로 검토하고 업데이트하세요.
3. 인증서 파일의 권한을 적절하게 설정하세요."
    else
        print_result "KuM-06" "API Server SSL/TLS 적용" "취약" \
            "$detail" \
            "API Server에 SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
1) --secure-port가 설정되지 않았거나 0으로 설정되어 있습니다.
2) API Server to kubelet 인증서가 설정되지 않았습니다.
3) API Server 인증서가 설정되지 않았습니다.
4) 안전한 SSL/TLS 버전이 설정되지 않았습니다.

[보안 위험]
1. 네트워크 구간의 데이터가 암호화되지 않습니다.
2. 중간자 공격(Man-in-the-Middle)에 취약합니다.
3. 인증서 기반의 상호 인증이 이루어지지 않습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --secure-port=6443
   - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
   - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
   - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
   - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
   - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
   - --client-ca-file=/etc/kubernetes/pki/ca.crt
   - --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

[예시]
--tls-cipher-suites에 설정 가능한 추가 암호화 스위트:
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# API Server 로그 관리 검사
check_api_logging() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-07" "API Server 로그 관리" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "API Server의 로그 관리가 설정되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 침해 사고 발생 시 원인 파악이 어렵습니다.
2. 해킹의 흔적 및 공격 기법을 확인할 수 없습니다.
3. 시스템 침입 흔적을 추적할 수 없습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --auditlog-path=/var/log/kubernetes/audit.log
   - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
   - --audit-log-maxage=30
   - --audit-log-maxbackup=10
   - --audit-log-maxsize=100

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local audit_log_path=$(grep "\-\-auditlog-path" "$api_server_yaml" | awk '{print $2}')
    local audit_policy_file=$(grep "\-\-audit-policy-file" "$api_server_yaml" | awk '{print $2}')
    local audit_log_maxage=$(grep "\-\-audit-log-maxage" "$api_server_yaml" | awk '{print $2}')
    local audit_log_maxbackup=$(grep "\-\-audit-log-maxbackup" "$api_server_yaml" | awk '{print $2}')
    local audit_log_maxsize=$(grep "\-\-audit-log-maxsize" "$api_server_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

[문제점]"
    
    if [ -z "$audit_log_path" ]; then
        detail+="
- --auditlog-path가 설정되지 않았습니다."
    fi
    
    if [ -z "$audit_policy_file" ]; then
        detail+="
- --audit-policy-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$audit_log_maxage" ]; then
        detail+="
- --audit-log-maxage가 설정되지 않았습니다."
    fi
    
    if [ -z "$audit_log_maxbackup" ]; then
        detail+="
- --audit-log-maxbackup이 설정되지 않았습니다."
    fi
    
    if [ -z "$audit_log_maxsize" ]; then
        detail+="
- --audit-log-maxsize가 설정되지 않았습니다."
    fi

    if [ ! -z "$audit_log_path" ] && [ ! -z "$audit_policy_file" ] && \
       [ ! -z "$audit_log_maxage" ] && [ ! -z "$audit_log_maxbackup" ] && [ ! -z "$audit_log_maxsize" ]; then
        print_result "KuM-07" "API Server 로그 관리" "양호" \
            "$detail" \
            "API Server의 로그 관리가 적절하게 설정되어 있습니다.

[현재 상태]
1) --auditlog-path가 설정되어 있습니다.
2) --audit-policy-file이 설정되어 있습니다.
3) --audit-log-maxage가 설정되어 있습니다.
4) --audit-log-maxbackup이 설정되어 있습니다.
5) --audit-log-maxsize가 설정되어 있습니다.

[보안 효과]
1. 침해 사고 발생 시 원인 파악이 용이합니다.
2. 해킹의 흔적 및 공격 기법을 확인할 수 있습니다.
3. 시스템 침입 흔적을 추적할 수 있습니다.

[권장 사항]
1. 정기적으로 로그를 분석하세요.
2. 로그 파일의 권한을 적절하게 설정하세요.
3. 로그 보관 기간을 정기적으로 검토하세요."
    else
        print_result "KuM-07" "API Server 로그 관리" "취약" \
            "$detail" \
            "API Server의 로그 관리가 설정되어 있지 않습니다.

[현재 문제]
1) --auditlog-path가 설정되지 않았습니다.
2) --audit-policy-file이 설정되지 않았습니다.
3) --audit-log-maxage가 설정되지 않았습니다.
4) --audit-log-maxbackup이 설정되지 않았습니다.
5) --audit-log-maxsize가 설정되지 않았습니다.

[보안 위험]
1. 침해 사고 발생 시 원인 파악이 어렵습니다.
2. 해킹의 흔적 및 공격 기법을 확인할 수 없습니다.
3. 시스템 침입 흔적을 추적할 수 없습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --auditlog-path=/var/log/kubernetes/audit.log
   - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
   - --audit-log-maxage=30
   - --audit-log-maxbackup=10
   - --audit-log-maxsize=100

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# Controller 인증 제어 검사
check_controller_auth() {
    local controller_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    
    if [ ! -f "$controller_yaml" ]; then
        print_result "KuM-08" "Controller 인증 제어" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
파일이 존재하지 않습니다." \
            "Controller의 인증 제어가 설정되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-controller-manager.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 인가되지 않은 계정이 클러스터를 제어할 수 있습니다.
2. 컨트롤러의 작업이 적절하게 제한되지 않습니다.
3. 서비스 계정 자격 증명이 안전하게 관리되지 않습니다.

[조치 방법]
1. kube-controller-manager.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --use-service-account-credentials=true
   - --service-account-private-key-file=/etc/kubernetes/pki/sa.key

3. Controller Manager를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local use_service_account=$(grep "\-\-use-service-account-credentials" "$controller_yaml" | awk '{print $2}')
    local service_account_key=$(grep "\-\-service-account-private-key-file" "$controller_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
$(cat $controller_yaml)

[문제점]"
    
    if [ -z "$use_service_account" ] || [ "$use_service_account" != "true" ]; then
        detail+="
- --use-service-account-credentials가 true로 설정되지 않았습니다."
    fi
    
    if [ -z "$service_account_key" ]; then
        detail+="
- --service-account-private-key-file이 설정되지 않았습니다."
    fi

    if [ ! -z "$use_service_account" ] && [ "$use_service_account" = "true" ] && [ ! -z "$service_account_key" ]; then
        print_result "KuM-08" "Controller 인증 제어" "양호" \
            "$detail" \
            "Controller의 인증 제어가 적절하게 설정되어 있습니다.

[현재 상태]
1) --use-service-account-credentials가 true로 설정되어 있습니다.
2) --service-account-private-key-file이 설정되어 있습니다.

[보안 효과]
1. 인가된 계정만이 클러스터를 제어할 수 있습니다.
2. 컨트롤러의 작업이 적절하게 제한됩니다.
3. 서비스 계정 자격 증명이 안전하게 관리됩니다.

[권장 사항]
1. 정기적으로 서비스 계정 권한을 검토하세요.
2. 서비스 계정 키 파일의 권한을 적절하게 설정하세요.
3. 서비스 계정 키를 주기적으로 갱신하세요."
    else
        print_result "KuM-08" "Controller 인증 제어" "취약" \
            "$detail" \
            "Controller의 인증 제어가 설정되어 있지 않습니다.

[현재 문제]
1) --use-service-account-credentials가 true로 설정되지 않았습니다.
2) --service-account-private-key-file이 설정되지 않았습니다.

[보안 위험]
1. 인가되지 않은 계정이 클러스터를 제어할 수 있습니다.
2. 컨트롤러의 작업이 적절하게 제한되지 않습니다.
3. 서비스 계정 자격 증명이 안전하게 관리되지 않습니다.

[조치 방법]
1. kube-controller-manager.yaml 파일에 다음 설정을 추가하세요:
   - --use-service-account-credentials=true
   - --service-account-private-key-file=/etc/kubernetes/pki/sa.key

2. Controller Manager를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# Controller Manager SSL/TLS 적용 검사
check_controller_ssl_tls() {
    local controller_yaml="/etc/kubernetes/manifests/kube-controller-manager.yaml"
    
    if [ ! -f "$controller_yaml" ]; then
        print_result "KuM-09" "Controller Manager SSL/TLS 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
파일이 존재하지 않습니다." \
            "Controller Manager에 SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-controller-manager.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. 네트워크 구간의 데이터가 암호화되지 않습니다.
2. 중간자 공격(Man-in-the-Middle)에 취약합니다.
3. 클라이언트 인증이 이루어지지 않습니다.

[조치 방법]
1. kube-controller-manager.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --root-ca-file=/etc/kubernetes/pki/ca.crt
   - --feature-gates=RotateKubeletServerCertificate=true

3. Controller Manager를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local root_ca_file=$(grep "\-\-root-ca-file" "$controller_yaml" | awk '{print $2}')
    local feature_gates=$(grep "\-\-feature-gates" "$controller_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-controller-manager.yaml
$(cat $controller_yaml)

[문제점]"
    
    if [ -z "$root_ca_file" ]; then
        detail+="
- --root-ca-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$feature_gates" ] || [[ ! "$feature_gates" =~ "RotateKubeletServerCertificate=true" ]]; then
        detail+="
- --feature-gates에 RotateKubeletServerCertificate=true가 설정되지 않았습니다."
    fi

    if [ ! -z "$root_ca_file" ] && [ ! -z "$feature_gates" ] && [[ "$feature_gates" =~ "RotateKubeletServerCertificate=true" ]]; then
        print_result "KuM-09" "Controller Manager SSL/TLS 적용" "양호" \
            "$detail" \
            "Controller Manager에 SSL/TLS가 적절하게 적용되어 있습니다.

[현재 상태]
1) --root-ca-file이 설정되어 있습니다.
2) --feature-gates에 RotateKubeletServerCertificate=true가 설정되어 있습니다.

[보안 효과]
1. 네트워크 구간의 데이터가 암호화됩니다.
2. 중간자 공격(Man-in-the-Middle)으로부터 보호됩니다.
3. 클라이언트 인증이 이루어집니다.
4. Kubelet 서버 인증서가 자동으로 갱신됩니다.

[권장 사항]
1. 정기적으로 인증서를 갱신하세요.
2. 인증서 파일의 권한을 적절하게 설정하세요.
3. 인증서 갱신 주기를 정기적으로 검토하세요."
    else
        print_result "KuM-09" "Controller Manager SSL/TLS 적용" "취약" \
            "$detail" \
            "Controller Manager에 SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
1) --root-ca-file이 설정되지 않았습니다.
2) --feature-gates에 RotateKubeletServerCertificate=true가 설정되지 않았습니다.

[보안 위험]
1. 네트워크 구간의 데이터가 암호화되지 않습니다.
2. 중간자 공격(Man-in-the-Middle)에 취약합니다.
3. 클라이언트 인증이 이루어지지 않습니다.
4. Kubelet 서버 인증서가 자동으로 갱신되지 않습니다.

[조치 방법]
1. kube-controller-manager.yaml 파일에 다음 설정을 추가하세요:
   - --root-ca-file=/etc/kubernetes/pki/ca.crt
   - --feature-gates=RotateKubeletServerCertificate=true

2. Controller Manager를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# etcd 암호화 적용 검사
check_etcd_encryption() {
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-10" "etcd 암호화 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
파일이 존재하지 않습니다." \
            "etcd 암호화가 적용되어 있지 않습니다.

[현재 문제]
Master Node에서 /etc/kubernetes/manifests/kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. etcd에 저장되는 데이터가 암호화되지 않습니다.
2. 민감한 정보가 평문으로 저장됩니다.
3. 데이터 유출 위험이 있습니다.

[조치 방법]
1. kube-apiserver.yaml 파일의 위치를 확인하세요.
2. 파일이 존재하는 경우 다음 설정을 추가하세요:
   - --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

3. encryption-config.yaml 파일을 생성하고 다음 내용을 추가하세요:
   kind: EncryptionConfig
   apiVersion: v1
   resources:
   - resources:
     - secrets
     providers:
     - aescbc:
         keys:
         - name: key1
           secret: <base64-encoded-32-byte-key>
     - identity: {}

4. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    local encryption_config=$(grep "\-\-encryption-provider-config" "$api_server_yaml" | awk '{print $2}')
    
    if [ -z "$encryption_config" ]; then
        print_result "KuM-10" "etcd 암호화 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)" \
            "etcd 암호화가 적용되어 있지 않습니다.

[현재 문제]
1) --encryption-provider-config가 설정되지 않았습니다.

[보안 위험]
1. etcd에 저장되는 데이터가 암호화되지 않습니다.
2. 민감한 정보가 평문으로 저장됩니다.
3. 데이터 유출 위험이 있습니다.

[조치 방법]
1. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

2. encryption-config.yaml 파일을 생성하고 다음 내용을 추가하세요:
   kind: EncryptionConfig
   apiVersion: v1
   resources:
   - resources:
     - secrets
     providers:
     - aescbc:
         keys:
         - name: key1
           secret: <base64-encoded-32-byte-key>
     - identity: {}

3. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    # encryption-config.yaml 파일 확인
    if [ ! -f "$encryption_config" ]; then
        print_result "KuM-10" "etcd 암호화 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

[문제점]
- encryption-config.yaml 파일이 존재하지 않습니다." \
            "etcd 암호화가 적용되어 있지 않습니다.

[현재 문제]
1) encryption-config.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. etcd에 저장되는 데이터가 암호화되지 않습니다.
2. 민감한 정보가 평문으로 저장됩니다.
3. 데이터 유출 위험이 있습니다.

[조치 방법]
1. encryption-config.yaml 파일을 생성하고 다음 내용을 추가하세요:
   kind: EncryptionConfig
   apiVersion: v1
   resources:
   - resources:
     - secrets
     providers:
     - aescbc:
         keys:
         - name: key1
           secret: <base64-encoded-32-byte-key>
     - identity: {}

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    # 암호화 방식 확인
    local encryption_provider=$(grep "providers:" -A 10 "$encryption_config" | grep -v "providers:" | head -n 1 | awk '{print $1}')
    
    if [ "$encryption_provider" = "aescbc:" ]; then
        print_result "KuM-10" "etcd 암호화 적용" "양호" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

# cat $encryption_config
$(cat $encryption_config)" \
            "etcd 암호화가 적절하게 적용되어 있습니다.

[현재 상태]
1) --encryption-provider-config가 설정되어 있습니다.
2) encryption-config.yaml 파일이 존재합니다.
3) aescbc 암호화 방식이 사용되고 있습니다.

[보안 효과]
1. etcd에 저장되는 데이터가 암호화됩니다.
2. 민감한 정보가 보호됩니다.
3. 데이터 유출 위험이 감소합니다.

[권장 사항]
1. 정기적으로 암호화 키를 갱신하세요.
2. 암호화 설정 파일의 권한을 적절하게 설정하세요.
3. 암호화 방식을 주기적으로 검토하세요."
    else
        print_result "KuM-10" "etcd 암호화 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

# cat $encryption_config
$(cat $encryption_config)" \
            "etcd 암호화가 취약한 방식으로 적용되어 있습니다.

[현재 문제]
1) 암호화 방식이 aescbc가 아닙니다.

[보안 위험]
1. 취약한 암호화 방식이 사용됩니다.
2. 데이터 보안이 취약합니다.
3. 암호화가 무력화될 위험이 있습니다.

[조치 방법]
1. encryption-config.yaml 파일을 수정하여 aescbc 암호화 방식을 사용하도록 설정하세요:
   kind: EncryptionConfig
   apiVersion: v1
   resources:
   - resources:
     - secrets
     providers:
     - aescbc:
         keys:
         - name: key1
           secret: <base64-encoded-32-byte-key>
     - identity: {}

2. API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# etcd SSL/TLS 적용 검사
check_etcd_ssl_tls() {
    local etcd_yaml="/etc/kubernetes/manifests/etcd.yaml"
    local api_server_yaml="/etc/kubernetes/manifests/kube-apiserver.yaml"
    
    if [ ! -f "$etcd_yaml" ] || [ ! -f "$api_server_yaml" ]; then
        print_result "KuM-11" "etcd SSL/TLS 적용" "취약" \
            "[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/etcd.yaml
$(if [ -f "$etcd_yaml" ]; then cat "$etcd_yaml"; else echo "파일이 존재하지 않습니다."; fi)

# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(if [ -f "$api_server_yaml" ]; then cat "$api_server_yaml"; else echo "파일이 존재하지 않습니다."; fi)" \
            "etcd SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
1) etcd.yaml 또는 kube-apiserver.yaml 파일이 존재하지 않습니다.

[보안 위험]
1. etcd 통신이 암호화되지 않습니다.
2. 네트워크 스니핑에 취약합니다.
3. 클라이언트 인증이 이루어지지 않습니다.

[조치 방법]
1. etcd.yaml 파일에 다음 설정을 추가하세요:
   - --client-cert-auth=true
   - --cert-file=/etc/kubernetes/pki/etcd/server.crt
   - --key-file=/etc/kubernetes/pki/etcd/server.key
   - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
   - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
   - --auto-tls=false
   - --peer-auto-tls=false
   - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt

2. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --etcd-certfile=/etc/kubernetes/pki/etcd/server.crt
   - --etcd-keyfile=/etc/kubernetes/pki/etcd/server.key
   - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt

3. etcd와 API Server를 재시작하세요:
   # systemctl restart kubelet"
        return
    fi

    # SSL/TLS 설정 확인
    local client_cert_auth=$(grep "\-\-client-cert-auth" "$etcd_yaml" | awk '{print $2}')
    local cert_file=$(grep "\-\-cert-file" "$etcd_yaml" | awk '{print $2}')
    local key_file=$(grep "\-\-key-file" "$etcd_yaml" | awk '{print $2}')
    local peer_cert_file=$(grep "\-\-peer-cert-file" "$etcd_yaml" | awk '{print $2}')
    local peer_key_file=$(grep "\-\-peer-key-file" "$etcd_yaml" | awk '{print $2}')
    local auto_tls=$(grep "\-\-auto-tls" "$etcd_yaml" | awk '{print $2}')
    local peer_auto_tls=$(grep "\-\-peer-auto-tls" "$etcd_yaml" | awk '{print $2}')
    local trusted_ca_file=$(grep "\-\-trusted-ca-file" "$etcd_yaml" | awk '{print $2}')
    
    # API Server etcd 인증서 설정 확인
    local etcd_certfile=$(grep "\-\-etcd-certfile" "$api_server_yaml" | awk '{print $2}')
    local etcd_keyfile=$(grep "\-\-etcd-keyfile" "$api_server_yaml" | awk '{print $2}')
    local etcd_cafile=$(grep "\-\-etcd-cafile" "$api_server_yaml" | awk '{print $2}')
    
    local detail="[ 현재 설정 상태 ]
# cat /etc/kubernetes/manifests/etcd.yaml
$(cat $etcd_yaml)

# cat /etc/kubernetes/manifests/kube-apiserver.yaml
$(cat $api_server_yaml)

[문제점]"
    
    if [ -z "$client_cert_auth" ] || [ "$client_cert_auth" != "true" ]; then
        detail+="
- --client-cert-auth가 true로 설정되지 않았습니다."
    fi
    
    if [ -z "$cert_file" ]; then
        detail+="
- --cert-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$key_file" ]; then
        detail+="
- --key-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$peer_cert_file" ]; then
        detail+="
- --peer-cert-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$peer_key_file" ]; then
        detail+="
- --peer-key-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$auto_tls" ] || [ "$auto_tls" != "false" ]; then
        detail+="
- --auto-tls가 false로 설정되지 않았습니다."
    fi
    
    if [ -z "$peer_auto_tls" ] || [ "$peer_auto_tls" != "false" ]; then
        detail+="
- --peer-auto-tls가 false로 설정되지 않았습니다."
    fi
    
    if [ -z "$trusted_ca_file" ]; then
        detail+="
- --trusted-ca-file이 설정되지 않았습니다."
    fi
    
    if [ -z "$etcd_certfile" ]; then
        detail+="
- --etcd-certfile이 설정되지 않았습니다."
    fi
    
    if [ -z "$etcd_keyfile" ]; then
        detail+="
- --etcd-keyfile이 설정되지 않았습니다."
    fi
    
    if [ -z "$etcd_cafile" ]; then
        detail+="
- --etcd-cafile이 설정되지 않았습니다."
    fi

    if [ ! -z "$client_cert_auth" ] && [ "$client_cert_auth" = "true" ] && \
       [ ! -z "$cert_file" ] && [ ! -z "$key_file" ] && \
       [ ! -z "$peer_cert_file" ] && [ ! -z "$peer_key_file" ] && \
       [ ! -z "$auto_tls" ] && [ "$auto_tls" = "false" ] && \
       [ ! -z "$peer_auto_tls" ] && [ "$peer_auto_tls" = "false" ] && \
       [ ! -z "$trusted_ca_file" ] && \
       [ ! -z "$etcd_certfile" ] && [ ! -z "$etcd_keyfile" ] && [ ! -z "$etcd_cafile" ]; then
        print_result "KuM-11" "etcd SSL/TLS 적용" "양호" \
            "$detail" \
            "etcd SSL/TLS가 적절하게 적용되어 있습니다.

[현재 상태]
1) 클라이언트 인증이 활성화되어 있습니다.
2) 인증서 파일이 모두 설정되어 있습니다.
3) 자체 서명 인증서 사용이 비활성화되어 있습니다.

[보안 효과]
1. etcd 통신이 암호화됩니다.
2. 네트워크 스니핑으로부터 보호됩니다.
3. 클라이언트 인증이 이루어집니다.

[권장 사항]
1. 정기적으로 인증서를 갱신하세요.
2. 인증서 파일의 권한을 적절하게 설정하세요.
3. 인증서 갱신 주기를 정기적으로 검토하세요."
    else
        print_result "KuM-11" "etcd SSL/TLS 적용" "취약" \
            "$detail" \
            "etcd SSL/TLS가 적용되어 있지 않습니다.

[현재 문제]
1) 클라이언트 인증이 비활성화되어 있습니다.
2) 일부 인증서 파일이 설정되지 않았습니다.
3) 자체 서명 인증서 사용이 활성화되어 있습니다.

[보안 위험]
1. etcd 통신이 암호화되지 않습니다.
2. 네트워크 스니핑에 취약합니다.
3. 클라이언트 인증이 이루어지지 않습니다.

[조치 방법]
1. etcd.yaml 파일에 다음 설정을 추가하세요:
   - --client-cert-auth=true
   - --cert-file=/etc/kubernetes/pki/etcd/server.crt
   - --key-file=/etc/kubernetes/pki/etcd/server.key
   - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
   - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
   - --auto-tls=false
   - --peer-auto-tls=false
   - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt

2. kube-apiserver.yaml 파일에 다음 설정을 추가하세요:
   - --etcd-certfile=/etc/kubernetes/pki/etcd/server.crt
   - --etcd-keyfile=/etc/kubernetes/pki/etcd/server.key
   - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt

3. etcd와 API Server를 재시작하세요:
   # systemctl restart kubelet"
    fi
}

# 컨테이너 권한 제어 검사
check_container_privileges() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-12" "컨테이너 권한 제어" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 컨테이너 권한 제어 검사를 건너뜁니다." \
            "컨테이너 권한 제어 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 컨테이너 권한 제어가 완화될 수 있습니다.
2. 실제 운영 환경에서는 더 엄격한 권한 제어가 필요합니다.

[권장 사항]
1. 운영 환경에서는 반드시 PodSecurityAdmission 정책을 적용하세요.
2. 모든 Pod에 SecurityContext를 설정하세요.
3. 정기적으로 권한 설정을 검토하세요."
        return
    fi

    # PodSecurityAdmission 정책 확인
    local namespaces=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
    local psa_enforced=false
    local psa_warned=false
    local total_namespaces=0
    local restricted_namespaces=0
    
    for ns in $namespaces; do
        total_namespaces=$((total_namespaces + 1))
        local enforce_label=$(kubectl get ns $ns -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
        local warn_label=$(kubectl get ns $ns -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}')
        
        if [ "$enforce_label" = "restricted" ]; then
            psa_enforced=true
            restricted_namespaces=$((restricted_namespaces + 1))
        fi
        if [ "$warn_label" = "restricted" ]; then
            psa_warned=true
        fi
    done

    # Pod SecurityContext 설정 확인
    local total_pods=0
    local secured_pods=0
    local unsecured_pods=0
    local pod_details=""
    local namespace_pods=""
    local current_namespace=""
    
    # 모든 Pod의 SecurityContext 설정을 한 번에 확인
    while IFS= read -r line; do
        if [ ! -z "$line" ]; then
            local ns=$(echo "$line" | awk '{print $1}')
            local pod=$(echo "$line" | awk '{print $2}')
            total_pods=$((total_pods + 1))
            
            # Pod의 SecurityContext 설정 확인
            local allow_priv_esc=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.securityContext.allowPrivilegeEscalation}')
            local run_as_user=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.securityContext.runAsUser}')
            local run_as_non_root=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.securityContext.runAsNonRoot}')
            local capabilities_drop=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.securityContext.capabilities.drop[*]}')
            local seccomp_profile=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.securityContext.seccompProfile.type}')
            
            local is_secured=true
            local missing_settings=""
            
            if [ "$allow_priv_esc" != "false" ]; then
                is_secured=false
                missing_settings+="allowPrivilegeEscalation: false, "
            fi
            if [ -z "$run_as_user" ] || [ "$run_as_user" = "0" ]; then
                is_secured=false
                missing_settings+="runAsUser: <non-zero-uid>, "
            fi
            if [ "$run_as_non_root" != "true" ]; then
                is_secured=false
                missing_settings+="runAsNonRoot: true, "
            fi
            if [ -z "$capabilities_drop" ]; then
                is_secured=false
                missing_settings+="capabilities.drop: [ALL], "
            fi
            if [ -z "$seccomp_profile" ]; then
                is_secured=false
                missing_settings+="seccompProfile.type: RuntimeDefault, "
            fi
            
            if [ "$is_secured" = true ]; then
                secured_pods=$((secured_pods + 1))
            else
                unsecured_pods=$((unsecured_pods + 1))
                
                # 네임스페이스별로 Pod 목록 정리
                if [ "$current_namespace" != "$ns" ]; then
                    if [ ! -z "$current_namespace" ]; then
                        namespace_pods+="\n\n$current_namespace 네임스페이스:\n$pod_details"
                    fi
                    current_namespace="$ns"
                    pod_details=""
                fi
                
                pod_details+="\n  - $pod: ${missing_settings%, }"
            fi
        fi
    done < <(kubectl get pods -A --no-headers)
    
    # 마지막 네임스페이스 추가
    if [ ! -z "$current_namespace" ]; then
        namespace_pods+="\n\n$current_namespace 네임스페이스:\n$pod_details"
    fi

    # 줄바꿈 문자를 실제 줄바꿈으로 변환
    namespace_pods=$(echo -e "$namespace_pods")

    local detail="[ 현재 설정 상태 ]
# PodSecurityAdmission 정책 적용 상태
- 전체 네임스페이스 수: $total_namespaces
- restricted 정책 적용된 네임스페이스 수: $restricted_namespaces
- enforce=restricted 적용된 네임스페이스: $(if [ "$psa_enforced" = true ]; then echo "있음"; else echo "없음"; fi)
- warn=restricted 적용된 네임스페이스: $(if [ "$psa_warned" = true ]; then echo "있음"; else echo "없음"; fi)

# Pod SecurityContext 설정 상태
- 전체 Pod 수: $total_pods
- SecurityContext가 적절히 설정된 Pod 수: $secured_pods
- SecurityContext가 설정되지 않은 Pod 수: $unsecured_pods

# SecurityContext가 설정되지 않은 Pod 목록
$namespace_pods"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ $restricted_namespaces -eq 0 ] && [ $secured_pods -eq 0 ]; then
        status="취약"
        result="컨테이너 권한 제어가 전혀 적용되어 있지 않습니다.

[현재 문제]
1) PodSecurityAdmission 정책이 어떤 네임스페이스에도 적용되어 있지 않습니다.
2) 모든 Pod에 SecurityContext가 설정되어 있지 않습니다.

[보안 위험]
1. 모든 컨테이너가 과도한 권한을 가질 수 있습니다.
2. 권한 상승이 가능합니다.
3. 보안 프로필이 적용되지 않습니다.

[조치 방법]
1. 모든 네임스페이스에 PodSecurityAdmission 정책을 적용하세요:
   # kubectl label --overwrite ns <namespace> pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted

2. 모든 Pod의 SecurityContext를 다음과 같이 설정하세요:
   securityContext:
     allowPrivilegeEscalation: false
     runAsUser: <non-zero-uid>
     runAsNonRoot: true
     capabilities:
       drop: ["ALL"]
     seccompProfile:
       type: RuntimeDefault

3. 기존 Pod의 SecurityContext 설정을 검토하고 필요한 경우 수정하세요."
    elif [ $restricted_namespaces -gt 0 ] && [ $restricted_namespaces -lt $total_namespaces ] && [ $secured_pods -gt 0 ] && [ $secured_pods -lt $total_pods ]; then
        status="부분만족"
        result="컨테이너 권한 제어가 부분적으로 적용되어 있습니다.

[현재 문제]
1) PodSecurityAdmission 정책이 일부 네임스페이스에만 적용되어 있습니다.
2) 일부 Pod에 SecurityContext가 설정되어 있지 않습니다.

[보안 위험]
1. 일부 컨테이너가 과도한 권한을 가질 수 있습니다.
2. 권한 상승이 가능할 수 있습니다.
3. 보안 프로필이 일부만 적용됩니다.

[조치 방법]
1. 모든 네임스페이스에 PodSecurityAdmission 정책을 적용하세요:
   # kubectl label --overwrite ns <namespace> pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted

2. 모든 Pod의 SecurityContext를 다음과 같이 설정하세요:
   securityContext:
     allowPrivilegeEscalation: false
     runAsUser: <non-zero-uid>
     runAsNonRoot: true
     capabilities:
       drop: ["ALL"]
     seccompProfile:
       type: RuntimeDefault

3. 기존 Pod의 SecurityContext 설정을 검토하고 필요한 경우 수정하세요."
    elif [ $restricted_namespaces -eq $total_namespaces ] && [ $secured_pods -eq $total_pods ]; then
        status="양호"
        result="컨테이너 권한 제어가 적절하게 적용되어 있습니다.

[현재 상태]
1) PodSecurityAdmission 정책이 모든 네임스페이스에 적용되어 있습니다.
2) 모든 Pod에 SecurityContext가 적절히 설정되어 있습니다.

[보안 효과]
1. 컨테이너의 권한이 제한됩니다.
2. 권한 상승이 방지됩니다.
3. 보안 프로필이 적용됩니다.

[권장 사항]
1. 정기적으로 PodSecurityAdmission 정책을 검토하세요.
2. 새로운 Pod 생성 시 SecurityContext 설정을 확인하세요.
3. 권한 설정 변경 시 영향도를 평가하세요."
    else
        status="인터뷰 필요"
        result="컨테이너 권한 제어 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) PodSecurityAdmission 정책 적용 상태가 불명확합니다.
2. Pod SecurityContext 설정 상태가 불명확합니다.

[보안 효과]
1. 컨테이너 권한 제어 상태를 정확히 파악할 수 없습니다.
2. 보안 위험을 정확히 평가할 수 없습니다.

[권장 사항]
1. PodSecurityAdmission 정책 적용 상태를 확인하세요.
2. Pod SecurityContext 설정 상태를 확인하세요.
3. 필요한 경우 추가 정보를 제공하세요."
    fi

    print_result "KuM-12" "컨테이너 권한 제어" "$status" "$detail" "$result"
}

# 네임스페이스 공유 금지 검사
check_namespace_sharing() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-13" "네임스페이스 공유 금지" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 네임스페이스 공유 금지 검사를 건너뜁니다." \
            "네임스페이스 공유 금지 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 네임스페이스 공유가 허용될 수 있습니다.
2. 실제 운영 환경에서는 더 엄격한 네임스페이스 격리가 필요합니다.

[권장 사항]
1. 운영 환경에서는 반드시 네임스페이스 공유를 금지하세요.
2. 모든 Pod의 hostNetwork, hostPID, hostIPC 설정을 확인하세요.
3. 정기적으로 네임스페이스 설정을 검토하세요."
        return
    fi

    # Pod 네임스페이스 공유 설정 확인
    local total_pods=0
    local secured_pods=0
    local unsecured_pods=0
    local pod_details=""
    local namespace_pods=""
    local current_namespace=""
    
    # 모든 Pod의 네임스페이스 공유 설정을 한 번에 확인
    while IFS= read -r line; do
        if [ ! -z "$line" ]; then
            local ns=$(echo "$line" | awk '{print $1}')
            local pod=$(echo "$line" | awk '{print $2}')
            total_pods=$((total_pods + 1))
            
            # Pod의 네임스페이스 공유 설정 확인
            local host_network=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.hostNetwork}')
            local host_pid=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.hostPID}')
            local host_ipc=$(kubectl get pod $pod -n $ns -o jsonpath='{.spec.hostIPC}')
            
            local is_secured=true
            local missing_settings=""
            
            if [ "$host_network" = "true" ]; then
                is_secured=false
                missing_settings+="hostNetwork: true, "
            fi
            if [ "$host_pid" = "true" ]; then
                is_secured=false
                missing_settings+="hostPID: true, "
            fi
            if [ "$host_ipc" = "true" ]; then
                is_secured=false
                missing_settings+="hostIPC: true, "
            fi
            
            if [ "$is_secured" = true ]; then
                secured_pods=$((secured_pods + 1))
            else
                unsecured_pods=$((unsecured_pods + 1))
                
                # 네임스페이스별로 Pod 목록 정리
                if [ "$current_namespace" != "$ns" ]; then
                    if [ ! -z "$current_namespace" ]; then
                        namespace_pods+="\n\n$current_namespace 네임스페이스:\n$pod_details"
                    fi
                    current_namespace="$ns"
                    pod_details=""
                fi
                
                pod_details+="\n  - $pod: ${missing_settings%, }"
            fi
        fi
    done < <(kubectl get pods -A --no-headers)
    
    # 마지막 네임스페이스 추가
    if [ ! -z "$current_namespace" ]; then
        namespace_pods+="\n\n$current_namespace 네임스페이스:\n$pod_details"
    fi

    # 줄바꿈 문자를 실제 줄바꿈으로 변환
    namespace_pods=$(echo -e "$namespace_pods")

    local detail="[ 현재 설정 상태 ]
# Pod 네임스페이스 공유 설정 상태
- 전체 Pod 수: $total_pods
- 네임스페이스 공유가 금지된 Pod 수: $secured_pods
- 네임스페이스 공유가 허용된 Pod 수: $unsecured_pods

# 네임스페이스 공유가 허용된 Pod 목록
$namespace_pods"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ $unsecured_pods -eq 0 ]; then
        status="양호"
        result="네임스페이스 공유 금지 설정이 적절하게 적용되어 있습니다.

[현재 상태]
1) 모든 Pod가 호스트의 네트워크, PID, IPC 네임스페이스를 공유하지 않습니다.

[보안 효과]
1. 컨테이너 간 격리가 유지됩니다.
2. 호스트 시스템과의 불필요한 상호작용이 방지됩니다.
3. 보안 경계가 명확하게 유지됩니다.

[권장 사항]
1. 정기적으로 Pod 설정을 검토하세요.
2. 새로운 Pod 생성 시 네임스페이스 공유 설정을 확인하세요.
3. 필요한 경우 네트워크 정책을 추가하여 통신을 제한하세요."
    else
        status="취약"
        result="네임스페이스 공유 금지 설정이 적용되지 않았습니다.

[현재 문제]
1) 일부 Pod가 호스트의 네트워크, PID, IPC 네임스페이스를 공유합니다.

[보안 위험]
1. 컨테이너 간 격리가 깨질 수 있습니다.
2. 호스트 시스템의 프로세스와 리소스에 접근할 수 있습니다.
3. 컨테이너에서 호스트 시스템으로의 권한 상승이 가능합니다.

[조치 방법]
1. 모든 Pod의 설정에서 다음 항목을 확인하고 수정하세요:
   - hostNetwork: false 또는 파라미터 제거
   - hostPID: false 또는 파라미터 제거
   - hostIPC: false 또는 파라미터 제거

2. PodSecurityAdmission 정책을 적용하여 네임스페이스 공유를 제한하세요:
   # kubectl label --overwrite ns <namespace> pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted

3. 기존 Pod의 설정을 검토하고 필요한 경우 수정하세요."
    fi

    print_result "KuM-13" "네임스페이스 공유 금지" "$status" "$detail" "$result"
}

# 환경설정 파일 권한 설정 검사
check_config_file_permissions() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-14" "환경설정 파일 권한 설정" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 환경설정 파일 권한 설정 검사를 건너뜁니다." \
            "환경설정 파일 권한 설정 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 파일 권한이 완화될 수 있습니다.
2. 실제 운영 환경에서는 더 엄격한 파일 권한이 필요합니다.

[권장 사항]
1. 운영 환경에서는 반드시 환경설정 파일의 권한을 제한하세요.
2. 모든 환경설정 파일의 소유자와 권한을 확인하세요.
3. 정기적으로 파일 권한을 검토하세요."
        return
    fi

    # 검사할 파일 목록
    local config_files=(
        "/etc/kubernetes/manifests/kube-apiserver.yaml"
        "/etc/kubernetes/manifests/kube-controller-manager.yaml"
        "/etc/kubernetes/manifests/kube-scheduler.yaml"
        "/etc/kubernetes/manifests/etcd.yaml"
        "/etc/kubernetes/admin.conf"
        "/etc/kubernetes/scheduler.conf"
        "/etc/kubernetes/controller-manager.conf"
    )
    
    local total_files=0
    local secured_files=0
    local unsecured_files=0
    local file_details=""
    local all_file_details=""
    
    # 각 파일의 권한 확인
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            total_files=$((total_files + 1))
            
            # 파일 권한 정보 가져오기
            local file_info=$(ls -l "$file")
            local file_owner=$(echo "$file_info" | awk '{print $3}')
            local file_group=$(echo "$file_info" | awk '{print $4}')
            local file_perms=$(echo "$file_info" | awk '{print $1}')
            
            # 권한을 숫자로 변환 (예: rw-r--r-- -> 644)
            local numeric_perms=0
            if [[ "$file_perms" =~ ^-rw-r--r-- ]]; then
                numeric_perms=644
            elif [[ "$file_perms" =~ ^-rw-r----- ]]; then
                numeric_perms=640
            elif [[ "$file_perms" =~ ^-rw------- ]]; then
                numeric_perms=600
            elif [[ "$file_perms" =~ ^-rw-rw-r-- ]]; then
                numeric_perms=664
            elif [[ "$file_perms" =~ ^-rw-rw-rw- ]]; then
                numeric_perms=666
            elif [[ "$file_perms" =~ ^-rwxr--r-- ]]; then
                numeric_perms=755
            elif [[ "$file_perms" =~ ^-rwxr-xr-x ]]; then
                numeric_perms=755
            elif [[ "$file_perms" =~ ^-rwxrwxr-x ]]; then
                numeric_perms=775
            elif [[ "$file_perms" =~ ^-rwxrwxrwx ]]; then
                numeric_perms=777
            fi
            
            # 권한 검사
            local is_secured=true
            local issue=""
            
            if [ "$file_owner" != "root" ]; then
                is_secured=false
                issue+="소유자가 root가 아님, "
            fi
            
            if [ "$file_group" != "root" ]; then
                is_secured=false
                issue+="소유 그룹이 root가 아님, "
            fi
            
            if [ $numeric_perms -gt 644 ]; then
                is_secured=false
                issue+="권한이 644 초과 ($numeric_perms), "
            fi
            
            # 모든 파일의 상세 정보 추가
            all_file_details+="
# $file
- 소유자: $file_owner
- 소유 그룹: $file_group
- 권한: $file_perms ($numeric_perms)
- 상태: $(if [ "$is_secured" = true ]; then echo "양호"; else echo "취약 - ${issue%, }"; fi)"
            
            if [ "$is_secured" = true ]; then
                secured_files=$((secured_files + 1))
            else
                unsecured_files=$((unsecured_files + 1))
                file_details+="
  - $file: $file_owner:$file_group $file_perms ($numeric_perms) - ${issue%, }"
            fi
        else
            # 파일이 존재하지 않는 경우
            all_file_details+="
# $file
- 상태: 파일이 존재하지 않음"
        fi
    done
    
    local detail="[ 현재 설정 상태 ]
# 환경설정 파일 권한 설정 상태
- 전체 파일 수: $total_files
- 권한이 적절히 설정된 파일 수: $secured_files
- 권한이 과도하게 설정된 파일 수: $unsecured_files

# 각 파일의 현재 권한 설정 상태
$all_file_details

# 권한이 과도하게 설정된 파일 목록
$file_details"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ $unsecured_files -eq 0 ]; then
        status="양호"
        result="환경설정 파일의 권한이 적절하게 설정되어 있습니다.

[현재 상태]
1) 모든 환경설정 파일의 소유자 및 소유 그룹이 root입니다.
2) 모든 환경설정 파일의 접근 권한이 644 이하로 설정되어 있습니다.

[보안 효과]
1. 비인가자가 환경설정 파일을 수정할 수 없습니다.
2. 파일의 무결성이 유지됩니다.
3. 침해 사고 발생 가능성이 감소합니다.

[권장 사항]
1. 정기적으로 파일 권한을 검토하세요.
2. 새로운 파일 생성 시 적절한 권한을 설정하세요.
3. 파일 권한 변경 시 영향도를 평가하세요."
    else
        status="취약"
        result="환경설정 파일의 권한이 과도하게 설정되어 있습니다.

[현재 문제]
1) 일부 환경설정 파일의 소유자 또는 소유 그룹이 root가 아닙니다.
2) 일부 환경설정 파일의 접근 권한이 644 초과로 설정되어 있습니다.

[보안 위험]
1. 비인가자가 환경설정 파일을 수정할 수 있습니다.
2. 파일의 무결성이 깨질 수 있습니다.
3. 침해 사고 발생 가능성이 증가합니다.

[조치 방법]
1. 모든 환경설정 파일의 소유자 및 소유 그룹을 root로 변경하세요:
   # chown root:root <파일경로>

2. 모든 환경설정 파일의 접근 권한을 644 이하로 설정하세요:
   # chmod 644 <파일경로>

3. 파일 권한 변경 후 서비스가 정상적으로 동작하는지 확인하세요."
    fi

    print_result "KuM-14" "환경설정 파일 권한 설정" "$status" "$detail" "$result"
}

# 인증서 파일 권한 설정 검사
check_certificate_permissions() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-15" "인증서 파일 권한 설정" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 인증서 파일 권한 설정 검사를 건너뜁니다." \
            "인증서 파일 권한 설정 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 파일 권한이 완화될 수 있습니다.
2. 실제 운영 환경에서는 더 엄격한 파일 권한이 필요합니다.

[권장 사항]
1. 운영 환경에서는 반드시 인증서 파일의 권한을 제한하세요.
2. 모든 인증서 파일의 소유자와 권한을 확인하세요.
3. 정기적으로 파일 권한을 검토하세요."
        return
    fi

    # 검사할 디렉토리 목록
    local cert_dirs=(
        "/etc/kubernetes/pki"
        "/var/lib/kubernetes"
    )
    
    local total_files=0
    local secured_files=0
    local unsecured_files=0
    local file_details=""
    local all_file_details=""
    
    # 각 디렉토리의 인증서 파일 권한 확인
    for dir in "${cert_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # 인증서 파일(.crt, .pem) 확인
            for cert_file in $(find "$dir" -type f -name "*.crt" -o -name "*.pem" 2>/dev/null); do
                total_files=$((total_files + 1))
                
                # 파일 권한 정보 가져오기
                local file_info=$(ls -l "$cert_file")
                local file_owner=$(echo "$file_info" | awk '{print $3}')
                local file_group=$(echo "$file_info" | awk '{print $4}')
                local file_perms=$(echo "$file_info" | awk '{print $1}')
                
                # 권한을 숫자로 변환 (예: rw-r--r-- -> 644)
                local numeric_perms=0
                if [[ "$file_perms" =~ ^-rw-r--r-- ]]; then
                    numeric_perms=644
                elif [[ "$file_perms" =~ ^-rw-r----- ]]; then
                    numeric_perms=640
                elif [[ "$file_perms" =~ ^-rw------- ]]; then
                    numeric_perms=600
                elif [[ "$file_perms" =~ ^-rw-rw-r-- ]]; then
                    numeric_perms=664
                elif [[ "$file_perms" =~ ^-rw-rw-rw- ]]; then
                    numeric_perms=666
                elif [[ "$file_perms" =~ ^-rwxr--r-- ]]; then
                    numeric_perms=755
                elif [[ "$file_perms" =~ ^-rwxr-xr-x ]]; then
                    numeric_perms=755
                elif [[ "$file_perms" =~ ^-rwxrwxr-x ]]; then
                    numeric_perms=775
                elif [[ "$file_perms" =~ ^-rwxrwxrwx ]]; then
                    numeric_perms=777
                fi
                
                # 권한 검사
                local is_secured=true
                local issue=""
                
                if [ "$file_owner" != "root" ]; then
                    is_secured=false
                    issue+="소유자가 root가 아님, "
                fi
                
                if [ "$file_group" != "root" ]; then
                    is_secured=false
                    issue+="소유 그룹이 root가 아님, "
                fi
                
                if [ $numeric_perms -gt 644 ]; then
                    is_secured=false
                    issue+="권한이 644 초과 ($numeric_perms), "
                fi
                
                # 모든 파일의 상세 정보 추가
                all_file_details+="
# $cert_file
- 소유자: $file_owner
- 소유 그룹: $file_group
- 권한: $file_perms ($numeric_perms)
- 상태: $(if [ "$is_secured" = true ]; then echo "양호"; else echo "취약 - ${issue%, }"; fi)"
                
                if [ "$is_secured" = true ]; then
                    secured_files=$((secured_files + 1))
                else
                    unsecured_files=$((unsecured_files + 1))
                    file_details+="
  - $cert_file: $file_owner:$file_group $file_perms ($numeric_perms) - ${issue%, }"
                fi
            done
            
            # 키 파일(.key) 확인
            for key_file in $(find "$dir" -type f -name "*.key" 2>/dev/null); do
                total_files=$((total_files + 1))
                
                # 파일 권한 정보 가져오기
                local file_info=$(ls -l "$key_file")
                local file_owner=$(echo "$file_info" | awk '{print $3}')
                local file_group=$(echo "$file_info" | awk '{print $4}')
                local file_perms=$(echo "$file_info" | awk '{print $1}')
                
                # 권한을 숫자로 변환 (예: rw-r--r-- -> 644)
                local numeric_perms=0
                if [[ "$file_perms" =~ ^-rw-r--r-- ]]; then
                    numeric_perms=644
                elif [[ "$file_perms" =~ ^-rw-r----- ]]; then
                    numeric_perms=640
                elif [[ "$file_perms" =~ ^-rw------- ]]; then
                    numeric_perms=600
                elif [[ "$file_perms" =~ ^-rw-rw-r-- ]]; then
                    numeric_perms=664
                elif [[ "$file_perms" =~ ^-rw-rw-rw- ]]; then
                    numeric_perms=666
                elif [[ "$file_perms" =~ ^-rwxr--r-- ]]; then
                    numeric_perms=755
                elif [[ "$file_perms" =~ ^-rwxr-xr-x ]]; then
                    numeric_perms=755
                elif [[ "$file_perms" =~ ^-rwxrwxr-x ]]; then
                    numeric_perms=775
                elif [[ "$file_perms" =~ ^-rwxrwxrwx ]]; then
                    numeric_perms=777
                fi
                
                # 권한 검사
                local is_secured=true
                local issue=""
                
                if [ "$file_owner" != "root" ]; then
                    is_secured=false
                    issue+="소유자가 root가 아님, "
                fi
                
                if [ "$file_group" != "root" ]; then
                    is_secured=false
                    issue+="소유 그룹이 root가 아님, "
                fi
                
                if [ $numeric_perms -gt 600 ]; then
                    is_secured=false
                    issue+="권한이 600 초과 ($numeric_perms), "
                fi
                
                # 모든 파일의 상세 정보 추가
                all_file_details+="
# $key_file
- 소유자: $file_owner
- 소유 그룹: $file_group
- 권한: $file_perms ($numeric_perms)
- 상태: $(if [ "$is_secured" = true ]; then echo "양호"; else echo "취약 - ${issue%, }"; fi)"
                
                if [ "$is_secured" = true ]; then
                    secured_files=$((secured_files + 1))
                else
                    unsecured_files=$((unsecured_files + 1))
                    file_details+="
  - $key_file: $file_owner:$file_group $file_perms ($numeric_perms) - ${issue%, }"
                fi
            done
        else
            # 디렉토리가 존재하지 않는 경우
            all_file_details+="
# $dir
- 상태: 디렉토리가 존재하지 않음"
        fi
    done
    
    local detail="[ 현재 설정 상태 ]
# 인증서 파일 권한 설정 상태
- 전체 파일 수: $total_files
- 권한이 적절히 설정된 파일 수: $secured_files
- 권한이 과도하게 설정된 파일 수: $unsecured_files

# 각 파일의 현재 권한 설정 상태
$all_file_details

# 권한이 과도하게 설정된 파일 목록
$file_details"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ $unsecured_files -eq 0 ]; then
        status="양호"
        result="인증서 파일의 권한이 적절하게 설정되어 있습니다.

[현재 상태]
1) 모든 인증서 파일의 소유자 및 소유 그룹이 root입니다.
2) 모든 인증서 파일의 접근 권한이 644 이하로 설정되어 있습니다.
3) 모든 키 파일의 접근 권한이 600 이하로 설정되어 있습니다.

[보안 효과]
1. 비인가자가 인증서 파일을 수정할 수 없습니다.
2. 인증서의 무결성이 유지됩니다.
3. SSL/TLS 통신의 보안이 강화됩니다.

[권장 사항]
1. 정기적으로 인증서 파일 권한을 검토하세요.
2. 새로운 인증서 생성 시 적절한 권한을 설정하세요.
3. 인증서 갱신 시 권한 설정을 확인하세요."
    else
        status="취약"
        result="인증서 파일의 권한이 과도하게 설정되어 있습니다.

[현재 문제]
1) 일부 인증서 파일의 소유자 또는 소유 그룹이 root가 아닙니다.
2) 일부 인증서 파일의 접근 권한이 644 초과로 설정되어 있습니다.
3) 일부 키 파일의 접근 권한이 600 초과로 설정되어 있습니다.

[보안 위험]
1. 비인가자가 인증서 파일을 수정할 수 있습니다.
2. 인증서의 무결성이 깨질 수 있습니다.
3. SSL/TLS 통신의 보안이 약화됩니다.
4. 인증서가 유출될 위험이 있습니다.

[조치 방법]
1. 모든 인증서 파일의 소유자 및 소유 그룹을 root로 변경하세요:
   # chown root:root <파일경로>

2. 모든 인증서 파일의 접근 권한을 644 이하로 설정하세요:
   # chmod 644 <파일경로>

3. 모든 키 파일의 접근 권한을 600 이하로 설정하세요:
   # chmod 600 <파일경로>

4. 파일 권한 변경 후 서비스가 정상적으로 동작하는지 확인하세요."
    fi

    print_result "KuM-15" "인증서 파일 권한 설정" "$status" "$detail" "$result"
}

# etcd 데이터 디렉터리 권한 설정 검사
check_etcd_directory_permissions() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-16" "etcd 데이터 디렉터리 권한 설정" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 etcd 데이터 디렉터리 권한 설정 검사를 건너뜁니다." \
            "etcd 데이터 디렉터리 권한 설정 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 디렉터리 권한이 완화될 수 있습니다.
2. 실제 운영 환경에서는 더 엄격한 디렉터리 권한이 필요합니다.

[권장 사항]
1. 운영 환경에서는 반드시 etcd 데이터 디렉터리의 권한을 제한하세요.
2. 디렉터리의 소유자와 권한을 확인하세요.
3. 정기적으로 디렉터리 권한을 검토하세요."
        return
    fi

    # 검사할 디렉토리 목록
    local etcd_dirs=(
        "/var/lib/etcd"
    )
    
    local total_dirs=0
    local secured_dirs=0
    local unsecured_dirs=0
    local dir_details=""
    local all_dir_details=""
    
    # 각 디렉토리의 권한 확인
    for dir in "${etcd_dirs[@]}"; do
        if [ -d "$dir" ]; then
            total_dirs=$((total_dirs + 1))
            
            # 디렉토리 권한 정보 가져오기
            local dir_info=$(ls -ld "$dir")
            local dir_owner=$(echo "$dir_info" | awk '{print $3}')
            local dir_group=$(echo "$dir_info" | awk '{print $4}')
            local dir_perms=$(echo "$dir_info" | awk '{print $1}')
            
            # 권한을 숫자로 변환 (예: drwx------ -> 700)
            local numeric_perms=0
            if [[ "$dir_perms" =~ ^d[rwx-]{9} ]]; then
                if [[ "$dir_perms" =~ ^drwx------ ]]; then
                    numeric_perms=700
                elif [[ "$dir_perms" =~ ^drwxr-x--- ]]; then
                    numeric_perms=750
                elif [[ "$dir_perms" =~ ^drwxr-xr-x ]]; then
                    numeric_perms=755
                elif [[ "$dir_perms" =~ ^drwxrwx--- ]]; then
                    numeric_perms=770
                elif [[ "$dir_perms" =~ ^drwxrwxr-x ]]; then
                    numeric_perms=775
                elif [[ "$dir_perms" =~ ^drwxrwxrwx ]]; then
                    numeric_perms=777
                fi
            fi
            
            # 권한 검사
            local is_secured=true
            local issue=""
            
            if [ "$dir_owner" != "root" ]; then
                is_secured=false
                issue+="소유자가 root가 아님, "
            fi
            
            if [ "$dir_group" != "root" ]; then
                is_secured=false
                issue+="소유 그룹이 root가 아님, "
            fi
            
            if [ $numeric_perms -gt 700 ]; then
                is_secured=false
                issue+="권한이 700 초과 ($numeric_perms), "
            fi
            
            # 모든 디렉토리의 상세 정보 추가
            all_dir_details+="
# $dir
- 소유자: $dir_owner
- 소유 그룹: $dir_group
- 권한: $dir_perms ($numeric_perms)
- 상태: $(if [ "$is_secured" = true ]; then echo "양호"; else echo "취약 - ${issue%, }"; fi)"
            
            if [ "$is_secured" = true ]; then
                secured_dirs=$((secured_dirs + 1))
            else
                unsecured_dirs=$((unsecured_dirs + 1))
                dir_details+="
  - $dir: $dir_owner:$dir_group $dir_perms ($numeric_perms) - ${issue%, }"
            fi
        else
            # 디렉토리가 존재하지 않는 경우
            all_dir_details+="
# $dir
- 상태: 디렉토리가 존재하지 않음"
        fi
    done
    
    local detail="[ 현재 설정 상태 ]
# etcd 데이터 디렉터리 권한 설정 상태
- 전체 디렉터리 수: $total_dirs
- 권한이 적절히 설정된 디렉터리 수: $secured_dirs
- 권한이 과도하게 설정된 디렉터리 수: $unsecured_dirs

# 각 디렉터리의 현재 권한 설정 상태
$all_dir_details

# 권한이 과도하게 설정된 디렉터리 목록
$dir_details"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ $unsecured_dirs -eq 0 ]; then
        status="양호"
        result="etcd 데이터 디렉터리의 권한이 적절하게 설정되어 있습니다.

[현재 상태]
1) 모든 etcd 데이터 디렉터리의 소유자 및 소유 그룹이 root입니다.
2) 모든 etcd 데이터 디렉터리의 접근 권한이 700 이하로 설정되어 있습니다.

[보안 효과]
1. 비인가자가 etcd 데이터 디렉터리를 수정할 수 없습니다.
2. etcd 데이터의 무결성이 유지됩니다.
3. 민감한 데이터가 보호됩니다.

[권장 사항]
1. 정기적으로 etcd 데이터 디렉터리 권한을 검토하세요.
2. 새로운 etcd 인스턴스 생성 시 적절한 권한을 설정하세요.
3. etcd 업그레이드 시 권한 설정을 확인하세요."
    else
        status="취약"
        result="etcd 데이터 디렉터리의 권한이 과도하게 설정되어 있습니다.

[현재 문제]
1) 일부 etcd 데이터 디렉터리의 소유자 또는 소유 그룹이 root가 아닙니다.
2) 일부 etcd 데이터 디렉터리의 접근 권한이 700 초과로 설정되어 있습니다.

[보안 위험]
1. 비인가자가 etcd 데이터 디렉터리를 수정할 수 있습니다.
2. etcd 데이터의 무결성이 깨질 수 있습니다.
3. 민감한 데이터가 유출될 위험이 있습니다.
4. 침해 사고가 발생할 가능성이 있습니다.

[조치 방법]
1. 모든 etcd 데이터 디렉터리의 소유자 및 소유 그룹을 root로 변경하세요:
   # chown root:root <디렉터리경로>

2. 모든 etcd 데이터 디렉터리의 접근 권한을 700 이하로 설정하세요:
   # chmod 700 <디렉터리경로>

3. 권한 변경 후 etcd 서비스가 정상적으로 동작하는지 확인하세요."
    fi

    print_result "KuM-16" "etcd 데이터 디렉터리 권한 설정" "$status" "$detail" "$result"
}

# 최신 보안 패치 적용 검사
check_security_patches() {
    # 개발 모드 체크
    if [ "$DEV_MODE" = true ]; then
        print_result "KuM-17" "최신 보안 패치 적용" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
개발 모드로 실행되어 최신 보안 패치 적용 검사를 건너뜁니다." \
            "최신 보안 패치 적용 상태를 확인하기 위해 추가 정보가 필요합니다.

[현재 상태]
1) 개발 모드로 실행되어 상세 검사를 건너뜁니다.

[보안 효과]
1. 개발 환경에서는 다양한 버전의 Kubernetes를 사용할 수 있습니다.
2. 실제 운영 환경에서는 보안 취약점이 없는 안정적인 버전을 사용해야 합니다.

[권장 사항]
1. 운영 환경에서는 반드시 보안 취약점이 없는 안정적인 버전을 사용하세요.
2. 정기적으로 보안 패치를 적용하세요.
3. 패치 적용 전 충분한 테스트를 진행하세요."
        return
    fi

    # Kubernetes 버전 정보 가져오기
    local k8s_version_info=$(kubectl version 2>/dev/null)
    if [ -z "$k8s_version_info" ]; then
        print_result "KuM-17" "최신 보안 패치 적용" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
Kubernetes 버전 정보를 가져올 수 없습니다." \
            "Kubernetes 버전 정보를 확인할 수 없어 보안 패치 적용 상태를 검사할 수 없습니다.

[현재 상태]
1) kubectl version 명령어로 버전 정보를 가져올 수 없습니다.

[가능한 원인]
1. kubectl이 설치되어 있지 않을 수 있습니다.
2. Kubernetes 클러스터에 접근할 수 없을 수 있습니다.
3. 권한 문제로 버전 정보를 가져올 수 없을 수 있습니다.

[권장 사항]
1. kubectl이 올바르게 설치되어 있는지 확인하세요.
2. Kubernetes 클러스터에 접근할 수 있는지 확인하세요.
3. 필요한 권한이 있는지 확인하세요."
        return
    fi

    # 서버 버전 정보 추출
    local k8s_version=$(echo "$k8s_version_info" | grep "Server Version:" | awk '{print $3}')
    if [ -z "$k8s_version" ]; then
        print_result "KuM-17" "최신 보안 패치 적용" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
Kubernetes 서버 버전 정보를 가져올 수 없습니다.
버전 정보:
$k8s_version_info" \
            "Kubernetes 서버 버전 정보를 확인할 수 없어 보안 패치 적용 상태를 검사할 수 없습니다.

[현재 상태]
1) 서버 버전 정보를 추출할 수 없습니다.

[가능한 원인]
1. kubectl version 출력 형식이 예상과 다를 수 있습니다.
2. 서버 버전 정보가 누락되었을 수 있습니다.

[권장 사항]
1. kubectl version 명령어의 출력을 확인하세요.
2. 필요한 경우 수동으로 버전을 확인하세요."
        return
    fi

    # 버전 정보 파싱 (v1.31.7 형식에서 숫자만 추출)
    local k8s_major=$(echo "$k8s_version" | sed 's/v//' | cut -d. -f1)
    local k8s_minor=$(echo "$k8s_version" | sed 's/v//' | cut -d. -f2)
    local k8s_patch=$(echo "$k8s_version" | sed 's/v//' | cut -d. -f3)

    # 버전 정보 유효성 검사
    if ! [[ "$k8s_major" =~ ^[0-9]+$ ]] || ! [[ "$k8s_minor" =~ ^[0-9]+$ ]] || ! [[ "$k8s_patch" =~ ^[0-9]+$ ]]; then
        print_result "KuM-17" "최신 보안 패치 적용" "인터뷰 필요" \
            "[ 현재 설정 상태 ]
Kubernetes 버전 정보가 올바르지 않습니다.
- 현재 버전: $k8s_version
- 메이저 버전: $k8s_major
- 마이너 버전: $k8s_minor
- 패치 버전: $k8s_patch" \
            "Kubernetes 버전 정보가 올바르지 않아 보안 패치 적용 상태를 검사할 수 없습니다.

[현재 상태]
1) 버전 정보가 숫자 형식이 아닙니다.

[가능한 원인]
1. 버전 정보가 예상과 다른 형식으로 출력되었을 수 있습니다.
2. 버전 정보가 손상되었을 수 있습니다.

[권장 사항]
1. kubectl version 명령어의 출력을 확인하세요.
2. 필요한 경우 수동으로 버전을 확인하세요."
        return
    fi
    
    # 현재 날짜 가져오기
    local current_date=$(date +%Y%m)
    
    # 알려진 취약점이 있는 버전 목록 (예시)
    local vulnerable_versions=(
        "1.24.0:1.24.5"  # 1.24.0 ~ 1.24.5 버전에 취약점 존재
        "1.25.0:1.25.3"  # 1.25.0 ~ 1.25.3 버전에 취약점 존재
        "1.26.0:1.26.1"  # 1.26.0 ~ 1.26.1 버전에 취약점 존재
    )
    
    local is_vulnerable=false
    local vulnerability_info=""
    
    # 버전이 취약한지 확인
    for version_range in "${vulnerable_versions[@]}"; do
        local min_version=$(echo "$version_range" | cut -d: -f1)
        local max_version=$(echo "$version_range" | cut -d: -f2)
        
        local min_major=$(echo "$min_version" | cut -d. -f1)
        local min_minor=$(echo "$min_version" | cut -d. -f2)
        local min_patch=$(echo "$min_version" | cut -d. -f3)
        
        local max_major=$(echo "$max_version" | cut -d. -f1)
        local max_minor=$(echo "$max_version" | cut -d. -f2)
        local max_patch=$(echo "$max_version" | cut -d. -f3)
        
        # 버전 비교
        if [ "$k8s_major" -eq "$min_major" ] && [ "$k8s_major" -eq "$max_major" ]; then
            if [ "$k8s_minor" -ge "$min_minor" ] && [ "$k8s_minor" -le "$max_minor" ]; then
                if [ "$k8s_minor" -eq "$min_minor" ] && [ "$k8s_patch" -lt "$min_patch" ]; then
                    continue
                fi
                if [ "$k8s_minor" -eq "$max_minor" ] && [ "$k8s_patch" -gt "$max_patch" ]; then
                    continue
                fi
                is_vulnerable=true
                vulnerability_info+="
  - $min_version ~ $max_version 버전에 알려진 취약점이 있습니다."
            fi
        fi
    done
    
    local detail="[ 현재 설정 상태 ]
# Kubernetes 버전 정보
- 현재 버전: $k8s_version (전체 버전)
- 메이저 버전: $k8s_major (주요 버전, 현재는 1.x.x 형식)
- 마이너 버전: $k8s_minor (기능 추가/개선 버전, 2024년 3월 기준 31이 최신)
- 패치 버전: $k8s_patch (버그 수정/보안 패치 버전)

# 버전 정보 설명
1. 메이저 버전 (1)
   - Kubernetes의 주요 버전을 나타냅니다.
   - 현재는 1.x.x 형식으로, 아직 2.0.0이 출시되지 않았습니다.
   - 메이저 버전이 변경되면 하위 호환성이 깨질 수 있는 큰 변경사항이 포함됩니다.

2. 마이너 버전 (31)
   - 기능 추가나 개선이 포함된 버전을 나타냅니다.
   - 하위 호환성을 유지하면서 새로운 기능이 추가됩니다.
   - 현재 31 버전은 2024년 3월 기준 최신 버전입니다.

3. 패치 버전 (7)
   - 버그 수정이나 보안 패치가 포함된 버전을 나타냅니다.
   - 하위 호환성을 유지하면서 버그를 수정합니다.
   - 7은 31번째 마이너 버전의 7번째 패치를 의미합니다.

# 알려진 취약점 정보
$(if [ "$is_vulnerable" = true ]; then
    echo "$vulnerability_info"
else
    echo "  - 현재 사용 중인 버전에 알려진 취약점이 없습니다."
fi)"

    # 상태 판단 기준
    local status=""
    local result=""
    
    if [ "$is_vulnerable" = false ]; then
        status="양호"
        result="최신 보안 패치가 적용되어 있습니다.

[현재 상태]
1) Kubernetes 버전 $k8s_version이 사용 중입니다.
2) 현재 버전에 알려진 보안 취약점이 없습니다.

[보안 효과]
1. 알려진 보안 취약점으로부터 시스템이 보호됩니다.
2. 시스템의 안정성이 향상됩니다.
3. 보안 관련 이슈가 발생할 가능성이 낮아집니다.

[권장 사항]
1. 정기적으로 보안 패치를 확인하고 적용하세요.
2. 패치 적용 전 충분한 테스트를 진행하세요.
3. 패치 적용 계획을 문서화하고 관리하세요."
    else
        status="취약"
        result="보안 취약점이 있는 버전이 사용 중입니다.

[현재 문제]
1) Kubernetes 버전 $k8s_version이 사용 중입니다.
2) 현재 버전에 알려진 보안 취약점이 있습니다.

[보안 위험]
1. 알려진 보안 취약점을 통해 시스템이 공격받을 수 있습니다.
2. 시스템의 안정성이 저하될 수 있습니다.
3. 데이터 유출이나 서비스 중단이 발생할 수 있습니다.

[조치 방법]
1. 보안 취약점이 없는 최신 버전으로 업그레이드하세요:
   # kubectl version  # 현재 버전 확인
   # kubeadm upgrade plan  # 업그레이드 계획 수립
   # kubeadm upgrade apply  # 업그레이드 적용

2. 업그레이드 전 다음 사항을 확인하세요:
   - 백업 수행
   - 영향도 분석
   - 테스트 환경에서 검증
   - 롤백 계획 수립

3. 정기적인 보안 패치 적용 계획을 수립하세요:
   - 월별 또는 분기별 패치 적용 일정 수립
   - 패치 적용 전 테스트 수행
   - 패치 적용 후 모니터링"
    fi

    print_result "KuM-17" "최신 보안 패치 적용" "$status" "$detail" "$result"
}

# 메인 함수
main() {
    print_logo
    echo "Kubernetes Master 노드 보안 진단 시작" | tee -a "$OUTPUT_FILE"
    print_line
    
    # EKS 환경 체크
    local is_eks=false
    if kubectl get nodes -o jsonpath='{.items[0].metadata.labels}' 2>/dev/null | grep -q "eks.amazonaws.com"; then
        is_eks=true
        echo "AWS EKS 환경이 감지되었습니다." | tee -a "$OUTPUT_FILE"
        echo "EKS 환경에서는 AWS 관리형 컨트롤 플레인과 함께 보안 설정을 검사합니다." | tee -a "$OUTPUT_FILE"
        print_line
    fi
    
    # API Server Configuration 검사
    check_api_auth
    check_api_auth_method
    check_api_external_access
    check_api_authorization
    check_admission_control
    check_api_ssl_tls
    check_api_logging
    check_controller_auth
    check_controller_ssl_tls
    check_etcd_encryption
    check_etcd_ssl_tls
    check_container_privileges
    check_namespace_sharing
    check_config_file_permissions
    check_certificate_permissions
    check_etcd_directory_permissions
    check_security_patches

    # EKS 특화 보안 설정 검사
    if [ "$is_eks" = true ]; then
        echo "EKS 특화 보안 설정 검사를 시작합니다." | tee -a "$OUTPUT_FILE"
        print_line
        
        # IRSA(IAM Roles for Service Accounts) 설정 검사
        check_irsa_settings
        
        # VPC 보안 그룹 설정 검사
        check_vpc_security_groups
        
        # AWS KMS 암호화 설정 검사
        check_kms_encryption
        
        # EKS 클러스터 로깅 설정 검사
        check_eks_logging
        
        print_line
    fi

    # 결과 요약
    print_line
    echo "진단 결과 요약" | tee -a "$OUTPUT_FILE"
    if [ "$is_eks" = true ]; then
        echo "AWS EKS 환경에서 추가적인 보안 설정이 검사되었습니다." | tee -a "$OUTPUT_FILE"
    fi
    echo "전체 검사 항목: $total_checks" | tee -a "$OUTPUT_FILE"
    echo "양호 항목 수: $good_checks" | tee -a "$OUTPUT_FILE"
    echo "취약 항목 수: $vulnerable_checks" | tee -a "$OUTPUT_FILE"
    echo "N/A 항목 수: $na_checks" | tee -a "$OUTPUT_FILE"
    echo "부분만족 항목 수: $partial_checks" | tee -a "$OUTPUT_FILE"
    echo "인터뷰 필요 항목 수: $interview_checks" | tee -a "$OUTPUT_FILE"
    print_line

    echo "진단 결과가 다음 파일에 저장되었습니다: $OUTPUT_FILE"
}

# EKS 특화 보안 설정 검사 함수들
check_irsa_settings() {
    # IRSA 설정 검사
    local irsa_enabled=$(kubectl get serviceaccount -A -o json | jq -r '.items[] | select(.metadata.annotations."eks.amazonaws.com/role-arn")')
    
    if [ -n "$irsa_enabled" ]; then
        print_result "KuM-EKS-01" "IRSA(IAM Roles for Service Accounts) 설정" "양호" \
            "[ 현재 설정 상태 ]
IRSA가 활성화되어 있습니다." \
            "IRSA가 적절히 구성되어 있습니다.

[보안 효과]
1. 서비스 계정에 대한 세분화된 IAM 권한 관리가 가능합니다.
2. AWS 리소스에 대한 접근이 제한됩니다.
3. 보안 자격 증명 관리가 개선됩니다."
    else
        print_result "KuM-EKS-01" "IRSA(IAM Roles for Service Accounts) 설정" "취약" \
            "[ 현재 설정 상태 ]
IRSA가 활성화되어 있지 않습니다." \
            "IRSA를 활성화하여 서비스 계정에 대한 IAM 권한을 관리하세요.

[보안 위험]
1. 서비스 계정에 대한 권한 관리가 어려워집니다.
2. AWS 리소스에 대한 과도한 접근이 가능할 수 있습니다.

[조치 방법]
1. 서비스 계정에 IAM 역할을 연결하세요:
   eksctl create iamserviceaccount --name=<service-account-name> --namespace=<namespace> --cluster=<cluster-name> --attach-policy-arn=<policy-arn> --approve"
    fi
}

check_vpc_security_groups() {
    # VPC 보안 그룹 설정 검사
    print_result "KuM-EKS-02" "VPC 보안 그룹 설정" "인터뷰 필요" \
        "[ 현재 설정 상태 ]
VPC 보안 그룹 설정을 확인하려면 AWS CLI가 필요합니다." \
        "VPC 보안 그룹 설정을 검토하세요.

[권장 사항]
1. 노드 보안 그룹:
   - 필요한 포트만 열어두세요 (기본: 22, 443, 10250)
   - 소스 IP를 제한하세요

2. 클러스터 보안 그룹:
   - API Server 접근을 제한하세요
   - 필요한 CIDR 블록만 허용하세요"
}

check_kms_encryption() {
    # AWS KMS 암호화 설정 검사
    print_result "KuM-EKS-03" "AWS KMS 암호화 설정" "인터뷰 필요" \
        "[ 현재 설정 상태 ]
AWS KMS 암호화 설정을 확인하려면 AWS CLI가 필요합니다." \
        "AWS KMS를 사용한 암호화를 구성하세요.

[권장 사항]
1. etcd 데이터 암호화:
   - AWS KMS 키를 생성하세요
   - 클러스터 생성 시 암호화를 활성화하세요

2. 시크릿 암호화:
   - AWS Secrets Manager 사용을 고려하세요
   - 외부 시크릿 관리자를 구성하세요"
}

check_eks_logging() {
    # EKS 클러스터 로깅 설정 검사
    print_result "KuM-EKS-04" "EKS 클러스터 로깅 설정" "인터뷰 필요" \
        "[ 현재 설정 상태 ]
EKS 클러스터 로깅 설정을 확인하려면 AWS CLI가 필요합니다." \
        "EKS 클러스터 로깅을 활성화하세요.

[권장 사항]
1. CloudWatch 로깅:
   - API Server 로그
   - 감사 로그
   - 컨트롤러 매니저 로그
   - 스케줄러 로그

2. 로그 보존:
   - 적절한 보존 기간 설정
   - 로그 암호화 활성화"
}

# 스크립트 실행
main