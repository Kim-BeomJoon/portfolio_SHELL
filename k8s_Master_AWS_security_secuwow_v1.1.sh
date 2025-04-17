#!/bin/bash

# AWS EKS 보안 진단 스크립트
# 작성일: 2025-04-17
# 버전: 1.1

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 결과 파일 설정
OUTPUT_FILE="/tmp/k8s_master/k8s_M_AWS_secuwow_$(date +%Y%m%d).txt"

# 개발 모드 설정 (true/false)
DEV_MODE=false

# AWS CLI 설치 여부 확인
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        echo "AWS CLI가 설치되어 있지 않습니다."
        echo "설치 방법: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi
}

# AWS 자격 증명 확인
check_aws_credentials() {
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "AWS 자격 증명이 설정되어 있지 않거나 유효하지 않습니다."
        echo "AWS CLI 구성 방법: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html"
        exit 1
    fi
}

# EKS 클러스터 확인
check_eks_cluster() {
    if ! aws eks list-clusters &> /dev/null; then
        echo "EKS 클러스터에 접근할 수 없습니다."
        exit 1
    fi
}

# kubectl 설치 여부 확인
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo "kubectl이 설치되어 있지 않습니다."
        echo "설치 방법: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi
}

# 구분선 출력 함수
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

    echo -e "\n[항목 $item_number] $item_name" | tee -a "$OUTPUT_FILE"
    echo -e "상태: $status" | tee -a "$OUTPUT_FILE"
    echo -e "상세:\n$detail" | tee -a "$OUTPUT_FILE"
    echo -e "결과:\n$result" | tee -a "$OUTPUT_FILE"
    print_line
}

# IRSA(IAM Roles for Service Accounts) 설정 검사
check_irsa_settings() {
    local irsa_enabled=$(kubectl get serviceaccount -A -o json | jq -r '.items[] | select(.metadata.annotations."eks.amazonaws.com/role-arn")')
    
    if [ -n "$irsa_enabled" ]; then
        print_result "EKS-01" "IRSA(IAM Roles for Service Accounts) 설정" "양호" \
            "[ 현재 설정 상태 ]
IRSA가 활성화되어 있습니다." \
            "IRSA가 적절히 구성되어 있습니다.

[보안 효과]
1. 서비스 계정에 대한 세분화된 IAM 권한 관리가 가능합니다.
2. AWS 리소스에 대한 접근이 제한됩니다.
3. 보안 자격 증명 관리가 개선됩니다."
    else
        print_result "EKS-01" "IRSA(IAM Roles for Service Accounts) 설정" "취약" \
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

# VPC 보안 그룹 설정 검사
check_vpc_security_groups() {
    local cluster_name=$(aws eks list-clusters --query 'clusters[0]' --output text)
    local vpc_id=$(aws eks describe-cluster --name $cluster_name --query 'cluster.resourcesVpcConfig.vpcId' --output text)
    
    # 노드 그룹 보안 그룹 검사
    local node_sg=$(aws eks describe-cluster --name $cluster_name --query 'cluster.resourcesVpcConfig.securityGroupIds[0]' --output text)
    local node_sg_rules=$(aws ec2 describe-security-groups --group-ids $node_sg --query 'SecurityGroups[0].IpPermissions' --output json)
    
    # API 서버 보안 그룹 검사
    local api_sg=$(aws eks describe-cluster --name $cluster_name --query 'cluster.resourcesVpcConfig.securityGroupIds[1]' --output text)
    local api_sg_rules=$(aws ec2 describe-security-groups --group-ids $api_sg --query 'SecurityGroups[0].IpPermissions' --output json)
    
    print_result "EKS-02" "VPC 보안 그룹 설정" "검사 완료" \
        "[ 현재 설정 상태 ]
VPC ID: $vpc_id
노드 보안 그룹: $node_sg
API 서버 보안 그룹: $api_sg" \
        "보안 그룹 설정을 검토하세요.

[권장 사항]
1. 노드 보안 그룹:
   - 필요한 포트만 열어두세요 (기본: 22, 443, 10250)
   - 소스 IP를 제한하세요

2. API 서버 보안 그룹:
   - API Server 접근을 제한하세요
   - 필요한 CIDR 블록만 허용하세요"
}

# AWS KMS 암호화 설정 검사
check_kms_encryption() {
    local cluster_name=$(aws eks list-clusters --query 'clusters[0]' --output text)
    local encryption_config=$(aws eks describe-cluster --name $cluster_name --query 'cluster.encryptionConfig' --output json)
    
    if [ "$encryption_config" != "null" ]; then
        print_result "EKS-03" "AWS KMS 암호화 설정" "양호" \
            "[ 현재 설정 상태 ]
암호화가 활성화되어 있습니다." \
            "KMS 암호화가 적절히 구성되어 있습니다.

[보안 효과]
1. etcd 데이터가 암호화되어 있습니다.
2. 시크릿 데이터가 안전하게 보호됩니다."
    else
        print_result "EKS-03" "AWS KMS 암호화 설정" "취약" \
            "[ 현재 설정 상태 ]
암호화가 활성화되어 있지 않습니다." \
            "KMS 암호화를 활성화하세요.

[보안 위험]
1. etcd 데이터가 암호화되지 않습니다.
2. 시크릿 데이터가 노출될 수 있습니다.

[조치 방법]
1. KMS 키를 생성하세요:
   aws kms create-key --description 'EKS encryption key'

2. 클러스터에 암호화를 활성화하세요:
   eksctl create cluster --name <cluster-name> --region <region> --encrypt-secrets"
    fi
}

# EKS 클러스터 로깅 설정 검사
check_eks_logging() {
    local cluster_name=$(aws eks list-clusters --query 'clusters[0]' --output text)
    local logging_config=$(aws eks describe-cluster --name $cluster_name --query 'cluster.logging.clusterLogging' --output json)
    
    if [ "$logging_config" != "null" ]; then
        print_result "EKS-04" "EKS 클러스터 로깅 설정" "양호" \
            "[ 현재 설정 상태 ]
클러스터 로깅이 활성화되어 있습니다." \
            "클러스터 로깅이 적절히 구성되어 있습니다.

[보안 효과]
1. API Server 로그가 기록됩니다.
2. 감사 로그가 유지됩니다.
3. 컨트롤러 매니저 로그가 보존됩니다."
    else
        print_result "EKS-04" "EKS 클러스터 로깅 설정" "취약" \
            "[ 현재 설정 상태 ]
클러스터 로깅이 활성화되어 있지 않습니다." \
            "클러스터 로깅을 활성화하세요.

[보안 위험]
1. 보안 관련 이벤트 추적이 어렵습니다.
2. 문제 발생 시 원인 파악이 어려워집니다.

[조치 방법]
1. CloudWatch 로깅을 활성화하세요:
   aws eks update-cluster-config --name <cluster-name> --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'"
    fi
}

# 노드 그룹 보안 설정 검사
check_node_group_security() {
    local cluster_name=$(aws eks list-clusters --query 'clusters[0]' --output text)
    local node_groups=$(aws eks list-nodegroups --cluster-name $cluster_name --query 'nodegroups[]' --output text)
    
    print_result "EKS-05" "노드 그룹 보안 설정" "검사 완료" \
        "[ 현재 설정 상태 ]
노드 그룹: $node_groups" \
        "노드 그룹 보안 설정을 검토하세요.

[권장 사항]
1. 최신 Amazon EKS 최적화 AMI 사용
2. 자동 보안 패치 활성화
3. 필요한 경우 노드 그룹별 IAM 역할 구성"
}

# 메인 함수
main() {
    echo "AWS EKS 보안 진단 시작" | tee -a "$OUTPUT_FILE"
    print_line
    
    # 필수 도구 확인
    check_aws_cli
    check_aws_credentials
    check_eks_cluster
    check_kubectl
    
    # 보안 설정 검사
    check_irsa_settings
    check_vpc_security_groups
    check_kms_encryption
    check_eks_logging
    check_node_group_security
    
    # 결과 요약
    print_line
    echo "진단 결과가 다음 파일에 저장되었습니다: $OUTPUT_FILE"
}

# 스크립트 실행
main 