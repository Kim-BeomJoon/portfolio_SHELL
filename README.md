

# 🛡️ Linux Server Security Assessment Script

![Security Assessment Banner](https://your-banner-image-url.png)

## 📋 프로젝트 개요

이 프로젝트는 Rocky Linux 서버의 보안 취약점을 자동으로 진단하고 분석하는 스크립트입니다. 총 72개의 보안 점검 항목을 통해 시스템의 보안 상태를 종합적으로 평가합니다.

## ✨ 주요 기능

- **계정 관리 점검**: 패스워드 정책, 계정 권한, 접근 제어 등
- **파일 시스템 보안**: 주요 설정 파일 권한, 소유자 점검
- **서비스 보안**: 불필요한 서비스 비활성화 상태 점검
- **네트워크 보안**: SSH, FTP, SNMP 등 주요 서비스 설정 검사
- **실시간 진행 상황**: 프로그레스 바를 통한 진단 진행률 표시
- **상세한 결과 리포트**: 취약점 발견 시 구체적인 조치 방안 제시

## 🖼️ 스크린샷

### 진단 프로세스
![Diagnosis Process](https://your-process-image-url.png)

### 결과 리포트
![Result Report](https://your-report-image-url.png)

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

- 개발자: [Your Name]
- 이메일: [Your Email]
- GitHub: [Your GitHub Profile]

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---
⭐ 이 프로젝트가 도움이 되었다면 GitHub 스타를 눌러주세요!

이런 형식으로 작성해보았습니다. 실제 사용하실 때는:
1. 실제 스크린샷 이미지를 추가
2. 개인 정보 및 연락처 업데이트
3. 실제 성능 측정 결과 반영
4. 프로젝트 특성에 맞게 내용 수정
이 필요합니다.

또한 배너나 스크린샷 이미지는 프로젝트의 전문성을 보여줄 수 있는 고품질 이미지를 사용하시면 좋을 것 같습니다.

