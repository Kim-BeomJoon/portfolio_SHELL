# 🛡️ Linux Server Security Assessment Script

![LED TEAM Logo](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/LEDTEAM_%EB%A1%9C%EA%B3%A0.jpg)

## 📋 프로젝트 개요

이 프로젝트는 LED TEAM이 개발한 Rocky Linux 서버의 보안 취약점을 자동으로 진단하고 분석하는 스크립트입니다. 총 72개의 보안 점검 항목을 통해 시스템의 보안 상태를 종합적으로 평가합니다.

## ✨ 주요 기능

- **계정 관리 점검**: 패스워드 정책, 계정 권한, 접근 제어 등
- **파일 시스템 보안**: 주요 설정 파일 권한, 소유자 점검
- **서비스 보안**: 불필요한 서비스 비활성화 상태 점검
- **네트워크 보안**: SSH, FTP, SNMP 등 주요 서비스 설정 검사
- **실시간 진행 상황**: 프로그레스 바를 통한 진단 진행률 표시
- **상세한 결과 리포트**: 취약점 발견 시 구체적인 조치 방안 제시

## 🖼️ 결과 스크린샷

![Result Screenshot 1](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start.png)
![Result Screenshot 2](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start1.png)
![Result Screenshot 3](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start2.png)
![Result Screenshot 4](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start4.png)

## 🚀 실행 방법

```bash
# 스크립트 실행 권한 부여
chmod +x Shell_Check.sh

# 스크립트 실행 (root 권한 필요)
sudo ./Shell_Check.sh
```

## 📊 진단 항목 분류

### 1. 계정 관리 (U-01 ~ U-54)
- 패스워드 정책
- 계정 권한 설정
- 로그인 제한

### 2. 파일 및 디렉토리 관리 (U-05 ~ U-59)
- 주요 설정 파일 권한
- 디렉토리 접근 제어
- 불필요한 파일 점검

### 3. 서비스 관리 (U-19 ~ U-41)
- 불필요한 서비스 비활성화
- 보안 설정 점검
- 접근 제어 설정

### 4. 보안 패치 및 로그 관리 (U-42 ~ U-72)
- 시스템 패치 상태
- 로그 설정
- 보안 정책 준수 여부

## 🛠️ 기술 스택

- Shell Script (Bash)
- Linux System Commands
- Security Compliance Tools

## 📈 성능 및 결과

- 평균 진단 소요 시간: 2-3분
- 메모리 사용량: 최소화 설계
- 시스템 부하: 낮음

## 🔒 보안 취약점 진단 기준

본 스크립트는 다음과 같은 보안 가이드라인을 기반으로 제작되었습니다:
- 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세 가이드
- CIS (Center for Internet Security) Benchmarks
- Linux Security Hardening Guidelines

## 👥 기여자

- **개발자: LED TEAM (김범준, 윤광혁, 안정훈, 허준범)**

### 김범준
- U44, 45, 52, 53, 10, 11, 18, 55, 72, U61 ~ 68, 69

### 윤광혁
- U2, 48, 49, 06, 07, 14, 15, 58, 59, U19 ~ 26

### 안정훈
- U3, 47, 50, 05, 08, 13, 16, 57, 42, U27 ~ 34, 71

### 허준범
- U4, 46, 51, 54, 09, 12, 17, 56, 43, U35 ~ 60, 70


## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---

