@echo off
setlocal enabledelayedexpansion

:: UTF-8 설정
chcp 65001 > nul

:: 관리자 권한 체크
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo 관리자 권한으로 실행해주세요!
    pause
    exit /b
)

:: 현재 시간을 폴더명으로 사용
set "timestamp=%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%"
set "timestamp=%timestamp: =0%"

:: 기본 디렉토리 생성
set "COLLECT_DIR=%~dp0\collected_%timestamp%"
mkdir "%COLLECT_DIR%" 2>nul

echo ================================================
echo           Windows Artifact Collector
echo ================================================
echo 수집 시작 시간: %date% %time%
echo 저장 경로: %COLLECT_DIR%
echo ================================================

:: 1. 프로세스 정보 수집
echo [+] 프로세스 정보 수집 중...
tasklist /v > "%COLLECT_DIR%\1_프로세스목록.txt"
wmic process get Caption,CommandLine,ProcessId,ParentProcessId /format:list > "%COLLECT_DIR%\2_프로세스상세정보.txt"
echo    완료!

:: 2. 이벤트 로그 수집
echo [+] 이벤트 로그 수집 중...
wevtutil qe System /c:100 /f:text > "%COLLECT_DIR%\3_시스템이벤트.txt"
wevtutil qe Security /c:100 /f:text > "%COLLECT_DIR%\4_보안이벤트.txt"
wevtutil qe Application /c:100 /f:text > "%COLLECT_DIR%\5_응용프로그램이벤트.txt"
echo    완료!

:: 3. 브라우저 정보
echo [+] 브라우저 정보 수집 중...
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\" /s /b > "%COLLECT_DIR%\6_크롬브라우저정보.txt"
dir "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\" /s /b > "%COLLECT_DIR%\7_엣지브라우저정보.txt"
echo    완료!

:: 4. 레지스트리 정보
echo [+] 레지스트리 정보 수집 중...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%COLLECT_DIR%\8_시스템시작프로그램.txt"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%COLLECT_DIR%\9_사용자시작프로그램.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" > "%COLLECT_DIR%\10_설치프로그램목록.txt"
echo    완료!

:: 5. 네트워크 정보
echo [+] 네트워크 정보 수집 중...
netstat -ano > "%COLLECT_DIR%\11_네트워크연결.txt"
ipconfig /all > "%COLLECT_DIR%\12_네트워크설정.txt"
arp -a > "%COLLECT_DIR%\13_ARP캐시.txt"
netstat -rn > "%COLLECT_DIR%\14_라우팅테이블.txt"
echo    완료!

:: 6. 시스템 정보
echo [+] 시스템 정보 수집 중...
systeminfo > "%COLLECT_DIR%\15_시스템정보.txt"
net user > "%COLLECT_DIR%\16_사용자계정.txt"
net localgroup administrators > "%COLLECT_DIR%\17_관리자그룹.txt"
schtasks /query /fo list > "%COLLECT_DIR%\18_예약작업.txt"
dir /s /b "C:\Users" > "%COLLECT_DIR%\19_사용자파일목록.txt"
echo    완료!

:: 7. 보안 정보
echo [+] 보안 정보 수집 중...
net share > "%COLLECT_DIR%\20_공유폴더.txt"
net session > "%COLLECT_DIR%\21_세션정보.txt"
netsh firewall show config > "%COLLECT_DIR%\22_방화벽설정.txt"
echo    완료!

:: 8. 서비스 정보
echo [+] 서비스 정보 수집 중...
sc query > "%COLLECT_DIR%\23_서비스목록.txt"
net start > "%COLLECT_DIR%\24_실행중서비스.txt"
echo    완료!

echo ================================================
echo 수집 완료!
echo 수집된 파일 위치: %COLLECT_DIR%
echo ================================================

:: 결과 요약 생성
echo ================================================ > "%COLLECT_DIR%\0_수집결과요약.txt"
echo           Artifact 수집 결과 요약                >> "%COLLECT_DIR%\0_수집결과요약.txt"
echo ================================================ >> "%COLLECT_DIR%\0_수집결과요약.txt"
echo 수집 시간: %date% %time%                         >> "%COLLECT_DIR%\0_수집결과요약.txt"
echo 컴퓨터 이름: %computername%                      >> "%COLLECT_DIR%\0_수집결과요약.txt"
echo 사용자 이름: %username%                          >> "%COLLECT_DIR%\0_수집결과요약.txt"
echo ================================================ >> "%COLLECT_DIR%\0_수집결과요약.txt"

pause