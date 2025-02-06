
# 🛡️ Security Assessment & Incident Response Scripts

![LED TEAM Logo](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/LEDTEAM_%EB%A1%9C%EA%B3%A0.jpg)

이 저장소는 두 가지 주요 보안 스크립트를 포함하고 있습니다:
1. Linux 서버 보안 진단 스크립트
2. Windows 침해사고 대응 아티팩트 수집 스크립트

# 📋 Part 1: Linux Server Security Assessment Script

## 프로젝트 개요
이 프로젝트는 LED TEAM이 개발한 Rocky Linux 서버의 보안 취약점을 자동으로 진단하고 분석하는 스크립트입니다. 총 72개의 보안 점검 항목을 통해 시스템의 보안 상태를 종합적으로 평가합니다.

- **팀명**: LED TEAM
- **수행기간**: 2024년 10월 28일 ~ 2024년 11월 29일
- **개발자**: 김범준(팀장), 윤광혁, 안정훈, 허준범

## ✨ 주요 기능
- **계정 관리 점검**: 패스워드 정책, 계정 권한, 접근 제어 등
- **파일 시스템 보안**: 주요 설정 파일 권한, 소유자 점검
- **서비스 보안**: 불필요한 서비스 비활성화 상태 점검
- **네트워크 보안**: SSH, FTP, SNMP 등 주요 서비스 설정 검사
- **실시간 진행 상황**: 프로그레스 바를 통한 진단 진행률 표시
- **상세한 결과 리포트**: 취약점 발견 시 구체적인 조치 방안 제시

## 🖼️ Linux 스크립트 결과 스크린샷
![Result Screenshot 1](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start.png)
![Result Screenshot 2](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start1.png)
![Result Screenshot 3](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start2.png)
![Result Screenshot 4](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/start4.png)

## 🚀 Linux 스크립트 실행 방법
```bash
# 스크립트 실행 권한 부여
chmod +x Shell_Check.sh

# 스크립트 실행 (root 권한 필요)
sudo ./Shell_Check.sh
```

## 📊 Linux 진단 항목 분류
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

# 📋 Part 2: Windows Incident Response Artifact Collection Script

## 프로젝트 개요
- **팀명**: LED TEAM
- **수행기간**: 2024년 11월 5일 ~ 2024년 11월 6일
- **개발자**: 김범준(팀장), 안정훈, 윤광혁

## ✨ 주요 기능
- **프로세스 정보 수집**: 실행 중인 프로세스 및 관련 정보 수집
- **이벤트 로그 분석**: 시스템, 보안, 애플리케이션 로그 수집
- **파일 시스템 분석**: MFT 정보 및 Prefetch 파일 분석
- **브라우저 히스토리**: 웹 브라우저 사용 기록 수집
- **시스템 지속성 분석**: 시작 프로그램 및 레지스트리 분석

## 🖼️ Windows 스크립트 결과 스크린샷
![Windows Check 1](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/win_check.png)
![Windows Check 2](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/windows_check1.png)
![Windows Check 3](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/win_check3.png)
![Windows Check 4](https://github.com/Kim-BeomJoon/portfolio_SHELL/blob/main/win_check2.png)

## 🚀 Windows 스크립트 실행 방법
```powershell
# 관리자 권한으로 PowerShell 실행
.\Artifact_Collection.ps1
```

## 📊 Windows 수집 항목 분류
### 1. 프로세스 정보
- 실행 중인 프로세스 목록
- 프로세스 세부 정보
- 네트워크 연결 정보

### 2. 시스템 로그
- 이벤트 로그 (시스템/보안/애플리케이션)
- 사용자 계정 활동 기록
- 시스템 변경 사항

### 3. 파일 시스템 분석
- MFT 정보 수집
- Prefetch 파일 분석
- 최근 접근 파일 목록

### 4. 브라우저 및 시스템 아티팩트
- 브라우저 히스토리
- 시작 프로그램 목록
- 레지스트리 분석 결과

## 🛠️ 기술 스택
### Linux 스크립트
- Shell Script (Bash)
- Linux System Commands
- Security Compliance Tools

### Windows 스크립트
- PowerShell
- Windows Management Instrumentation (WMI)
- Windows Event Log API
- Registry Management Tools

## 👥 기여자 역할 분담
### Linux 스크립트 개발
#### 김범준
- U44, 45, 52, 53, 10, 11, 18, 55, 72, U61 ~ 68, 69

#### 윤광혁
- U2, 48, 49, 06, 07, 14, 15, 58, 59, U19 ~ 26

#### 안정훈
- U3, 47, 50, 05, 08, 13, 16, 57, 42, U27 ~ 34, 71

#### 허준범
- U4, 46, 51, 54, 09, 12, 17, 56, 43, U35 ~ 60, 70

### Windows 스크립트 개발
각 팀원이 개별적으로 아티팩트 수집 스크립트를 개발한 후 통합했습니다.

#### 김범준
- 프로세스 정보 수집 스크립트 개발
  - 실행 중인 프로세스 목록 수집
  - 프로세스 세부 정보 분석
  - 네트워크 연결 정보 수집

#### 안정훈
- 이벤트 로그 및 파일 시스템 분석 스크립트 개발
  - 시스템/보안/애플리케이션 로그 수집
  - MFT 정보 수집
  - Prefetch 파일 분석

#### 윤광혁
- 브라우저 및 시스템 아티팩트 수집 스크립트 개발
  - 브라우저 히스토리 수집
  - 시작 프로그램 목록 분석
  - 레지스트리 정보 수집

## 📝 라이선스
이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.
````
