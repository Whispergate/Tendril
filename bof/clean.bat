@echo off
if exist "%~dp0build" (
    rd /s /q "%~dp0build"
    echo [+] Build directory cleaned
) else (
    echo [*] Nothing to clean
)
