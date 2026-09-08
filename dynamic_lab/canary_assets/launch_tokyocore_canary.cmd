@echo off
setlocal
set "SAMPLE=386fbb57ba83864ee57a9e8a271c6dc215dc20bb1521ee85ad414f0dc67babdc.exe"
if not exist "%USERPROFILE%\Documents" mkdir "%USERPROFILE%\Documents"
if not exist "C:\Users\Public\Documents" mkdir "C:\Users\Public\Documents"
copy /y "%~dp0TOKYOCORE_CANARY.txt" "%USERPROFILE%\Documents\TOKYOCORE_CANARY.txt" >nul
copy /y "%~dp0TOKYOCORE_CANARY.txt" "C:\Users\Public\Documents\TOKYOCORE_PUBLIC_CANARY.txt" >nul
start "" "%~dp0%SAMPLE%"
exit /b 0
