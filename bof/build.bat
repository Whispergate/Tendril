@echo off
setlocal enabledelayedexpansion
:: Tendril BOF - unified build

set "OUTDIR=%~dp0build"
set "INCDIR=%~dp0include"
set "SRC=%~dp0tendril.c"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set "CC="
set "CC32="
where x86_64-w64-mingw32-gcc >nul 2>&1 && set "CC=x86_64-w64-mingw32-gcc"
where i686-w64-mingw32-gcc >nul 2>&1 && set "CC32=i686-w64-mingw32-gcc"

if not defined CC (
    for %%P in (
        "C:\msys64\mingw64\bin"
        "C:\msys64\ucrt64\bin"
    ) do (
        if exist "%%~P\x86_64-w64-mingw32-gcc.exe" set "CC=%%~P\x86_64-w64-mingw32-gcc.exe"
    )
)
if not defined CC32 (
    for %%P in ("C:\msys64\mingw32\bin") do (
        if exist "%%~P\i686-w64-mingw32-gcc.exe" set "CC32=%%~P\i686-w64-mingw32-gcc.exe"
    )
)

if not defined CC (
    echo [-] x86_64-w64-mingw32-gcc not found
    exit /b 1
)

echo [*] Building tendril.x64.o
"%CC%" -c -I"%INCDIR%" -Wall -Os -o "%OUTDIR%\tendril.x64.o" "%SRC%"
if errorlevel 1 ( echo [-] x64 build FAILED & exit /b 1 )

if defined CC32 (
    echo [*] Building tendril.x86.o
    "%CC32%" -c -I"%INCDIR%" -Wall -Os -o "%OUTDIR%\tendril.x86.o" "%SRC%"
    if errorlevel 1 echo [!] x86 build FAILED
)

echo [+] Tendril BOF built in %OUTDIR%
exit /b 0
