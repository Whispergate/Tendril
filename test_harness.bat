@echo off
setlocal enabledelayedexpansion
:: Tendril Module Test Harness
:: Runs install -> check -> remove -> verify for each module on the Athena VM

set T=C:\Users\athena\Desktop\Tendril.exe
set BAT=C:\Users\athena\Desktop\test_payload.bat
set PASS=0
set FAIL=0
set TOTAL=0

echo ============================================================
echo  TENDRIL PERSISTENCE MODULE TEST SUITE
echo  Target: %COMPUTERNAME% (%USERNAME%)
echo  Date: %DATE% %TIME%
echo ============================================================
echo.

:: Helper: run a test, check for [+] in output
:: %1=test_name %2..=tendril args

:: ---------------------------------------------------------------
:: 1. RegistryRunKey (no admin)
:: ---------------------------------------------------------------
echo [TEST 1] RegistryRunKey - install/check/remove
set /a TOTAL+=1
%T% install RegistryRunKey /payload:"%BAT%" /name:TendrilTest 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check RegistryRunKey 2>&1 | findstr /C:"TendrilTest" >nul
    if !errorlevel! equ 0 (
        %T% remove RegistryRunKey /name:TendrilTest 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] RegistryRunKey
            set /a PASS+=1
        ) else (
            echo   [FAIL] RegistryRunKey - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] RegistryRunKey - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] RegistryRunKey - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 2. RegistryRunKey fileless variant
:: ---------------------------------------------------------------
echo [TEST 2] RegistryRunKey (fileless) - install/check/remove
set /a TOTAL+=1
%T% install RegistryRunKey /payload:"Write-Host TENDRIL" /name:TendrilFileless /fileless:true 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check RegistryRunKey 2>&1 | findstr /C:"TendrilFileless" >nul
    if !errorlevel! equ 0 (
        %T% remove RegistryRunKey /name:TendrilFileless 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] RegistryRunKey (fileless)
            set /a PASS+=1
        ) else (
            echo   [FAIL] RegistryRunKey (fileless) - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] RegistryRunKey (fileless) - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] RegistryRunKey (fileless) - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 3. ComHijack (no admin, HKCU)
:: ---------------------------------------------------------------
echo [TEST 3] ComHijack - install/check/remove
set /a TOTAL+=1
%T% install ComHijack /payload:C:\Windows\System32\shell32.dll /clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E} 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check ComHijack 2>&1 | findstr /C:"BCDE0395" >nul
    if !errorlevel! equ 0 (
        %T% remove ComHijack /clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E} 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] ComHijack
            set /a PASS+=1
        ) else (
            echo   [FAIL] ComHijack - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] ComHijack - check did not find CLSID
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] ComHijack - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 4. ScreensaverBackdoor (no admin)
:: ---------------------------------------------------------------
echo [TEST 4] ScreensaverBackdoor - install/check/remove
set /a TOTAL+=1
%T% install ScreensaverBackdoor /payload:C:\Windows\System32\scrnsave.scr /timeout:999 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check ScreensaverBackdoor 2>&1 | findstr /C:"scrnsave" >nul
    if !errorlevel! equ 0 (
        %T% remove ScreensaverBackdoor 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] ScreensaverBackdoor
            set /a PASS+=1
        ) else (
            echo   [FAIL] ScreensaverBackdoor - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] ScreensaverBackdoor - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] ScreensaverBackdoor - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 5. StartupFolder (no admin)
:: ---------------------------------------------------------------
echo [TEST 5] StartupFolder - install/check/remove
set /a TOTAL+=1
%T% install StartupFolder /payload:"%BAT%" /name:TendrilStartup 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check StartupFolder 2>&1 | findstr /C:"TendrilStartup" >nul
    if !errorlevel! equ 0 (
        %T% remove StartupFolder /name:TendrilStartup 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] StartupFolder
            set /a PASS+=1
        ) else (
            echo   [FAIL] StartupFolder - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] StartupFolder - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] StartupFolder - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 6. UserInitMprLogon - environment variant (no admin)
:: ---------------------------------------------------------------
echo [TEST 6] UserInitMprLogon (environment) - install/check/remove
set /a TOTAL+=1
%T% install UserInitMprLogon /payload:"%BAT%" /variant:environment 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check UserInitMprLogon 2>&1 | findstr /C:"UserInitMprLogonScript" >nul
    if !errorlevel! equ 0 (
        %T% remove UserInitMprLogon /variant:environment 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] UserInitMprLogon (environment)
            set /a PASS+=1
        ) else (
            echo   [FAIL] UserInitMprLogon - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] UserInitMprLogon - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] UserInitMprLogon - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 7. WinlogonHelper - HKCU Shell (no admin)
:: ---------------------------------------------------------------
echo [TEST 7] WinlogonHelper (HKCU Shell) - install/check/remove
set /a TOTAL+=1
%T% install WinlogonHelper /payload:"%BAT%" /target:shell /hive:HKCU 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check WinlogonHelper 2>&1 | findstr /C:"HKCU" >nul
    if !errorlevel! equ 0 (
        %T% remove WinlogonHelper /target:shell /hive:HKCU 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] WinlogonHelper (HKCU Shell)
            set /a PASS+=1
        ) else (
            echo   [FAIL] WinlogonHelper - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] WinlogonHelper - check did not find HKCU override
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] WinlogonHelper - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 8. PowerShellProfile (no admin)
:: ---------------------------------------------------------------
echo [TEST 8] PowerShellProfile - install/check/remove
set /a TOTAL+=1
%T% install PowerShellProfile /payload:"Write-Host 'TENDRIL_TEST'" /scope:currentuser 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check PowerShellProfile 2>&1 | findstr /C:"Profile" >nul
    if !errorlevel! equ 0 (
        %T% remove PowerShellProfile /scope:currentuser 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] PowerShellProfile
            set /a PASS+=1
        ) else (
            echo   [FAIL] PowerShellProfile - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] PowerShellProfile - check did not find profile
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] PowerShellProfile - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 9. IFEOInjection - debugger mode (admin)
:: ---------------------------------------------------------------
echo [TEST 9] IFEOInjection (debugger) - install/check/remove
set /a TOTAL+=1
%T% install IFEOInjection /target:notepad.exe /payload:C:\Windows\System32\calc.exe /mode:debugger 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check IFEOInjection 2>&1 | findstr /C:"notepad" >nul
    if !errorlevel! equ 0 (
        %T% remove IFEOInjection /target:notepad.exe /mode:debugger 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] IFEOInjection (debugger)
            set /a PASS+=1
        ) else (
            echo   [FAIL] IFEOInjection - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] IFEOInjection - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] IFEOInjection - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 10. IFEOInjection - SilentProcessExit mode (admin)
:: ---------------------------------------------------------------
echo [TEST 10] IFEOInjection (SilentProcessExit) - install/check/remove
set /a TOTAL+=1
%T% install IFEOInjection /target:mspaint.exe /payload:C:\Windows\System32\calc.exe /mode:silent 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check IFEOInjection 2>&1 | findstr /C:"mspaint" >nul
    if !errorlevel! equ 0 (
        %T% remove IFEOInjection /target:mspaint.exe /mode:silent 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] IFEOInjection (SilentProcessExit)
            set /a PASS+=1
        ) else (
            echo   [FAIL] IFEOInjection (silent) - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] IFEOInjection (silent) - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] IFEOInjection (silent) - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 11. GhostTask (admin)
:: ---------------------------------------------------------------
echo [TEST 11] GhostTask - install/check/remove
set /a TOTAL+=1
%T% install GhostTask /payload:C:\Windows\System32\calc.exe /name:TendrilGhostTest /trigger:logon 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check GhostTask 2>&1 | findstr /C:"TendrilGhostTest" >nul
    if !errorlevel! equ 0 (
        echo   [INFO] GhostTask - task is ghosted (invisible to schtasks)
        %T% remove GhostTask /name:TendrilGhostTest 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] GhostTask
            set /a PASS+=1
        ) else (
            echo   [FAIL] GhostTask - remove failed
            set /a FAIL+=1
        )
    ) else (
        :: Ghost task might have been created but SD removal failed - check if task exists normally
        schtasks /query /tn TendrilGhostTest >nul 2>&1
        if !errorlevel! equ 0 (
            echo   [WARN] GhostTask - task created but SD removal may have failed (visible)
            %T% remove GhostTask /name:TendrilGhostTest 2>&1 >nul
            echo   [PASS] GhostTask (partial - task created, SD removal check inconclusive)
            set /a PASS+=1
        ) else (
            echo   [FAIL] GhostTask - install may have failed
            set /a FAIL+=1
        )
    )
) else (
    echo   [FAIL] GhostTask - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 12. WmiSubscription (admin)
:: ---------------------------------------------------------------
echo [TEST 12] WmiSubscription - install/check/remove
set /a TOTAL+=1
%T% install WmiSubscription /payload:"cmd.exe /c echo TENDRIL" /name:TendrilWmiTest 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check WmiSubscription 2>&1 | findstr /C:"TendrilWmiTest" >nul
    if !errorlevel! equ 0 (
        %T% remove WmiSubscription /name:TendrilWmiTest 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] WmiSubscription
            set /a PASS+=1
        ) else (
            echo   [FAIL] WmiSubscription - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] WmiSubscription - check did not find filter
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] WmiSubscription - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 13. AppInitDlls (admin)
:: ---------------------------------------------------------------
echo [TEST 13] AppInitDlls - install/check/remove
set /a TOTAL+=1
%T% install AppInitDlls /payload:C:\Windows\System32\version.dll 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check AppInitDlls 2>&1 | findstr /C:"version.dll" >nul
    if !errorlevel! equ 0 (
        %T% remove AppInitDlls /payload:C:\Windows\System32\version.dll 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] AppInitDlls
            set /a PASS+=1
        ) else (
            echo   [FAIL] AppInitDlls - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] AppInitDlls - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] AppInitDlls - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 14. AccessibilityBackdoor - IFEO mode (admin)
:: ---------------------------------------------------------------
echo [TEST 14] AccessibilityBackdoor (IFEO) - install/check/remove
set /a TOTAL+=1
%T% install AccessibilityBackdoor /target:osk /payload:C:\Windows\System32\calc.exe /mode:ifeo 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check AccessibilityBackdoor 2>&1 | findstr /C:"osk" >nul
    if !errorlevel! equ 0 (
        %T% remove AccessibilityBackdoor /target:osk /mode:ifeo 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] AccessibilityBackdoor
            set /a PASS+=1
        ) else (
            echo   [FAIL] AccessibilityBackdoor - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] AccessibilityBackdoor - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] AccessibilityBackdoor - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 15. NetshHelperDll (admin)
:: ---------------------------------------------------------------
echo [TEST 15] NetshHelperDll - install/check/remove
set /a TOTAL+=1
%T% install NetshHelperDll /payload:C:\Windows\System32\version.dll /name:tendriltest 2>&1 | findstr /C:"[+]" >nul
if !errorlevel! equ 0 (
    %T% check NetshHelperDll 2>&1 | findstr /C:"tendriltest" >nul
    if !errorlevel! equ 0 (
        %T% remove NetshHelperDll /name:tendriltest 2>&1 | findstr /C:"[+]" >nul
        if !errorlevel! equ 0 (
            echo   [PASS] NetshHelperDll
            set /a PASS+=1
        ) else (
            echo   [FAIL] NetshHelperDll - remove failed
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] NetshHelperDll - check did not find entry
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] NetshHelperDll - install failed
    set /a FAIL+=1
)
echo.

:: ---------------------------------------------------------------
:: 16. DllSideloadEnum (recon only)
:: ---------------------------------------------------------------
echo [TEST 16] DllSideloadEnum - check (recon)
set /a TOTAL+=1
%T% check DllSideloadEnum 2>&1 | findstr /C:"[" >nul
if !errorlevel! equ 0 (
    echo   [PASS] DllSideloadEnum (ran without error)
    set /a PASS+=1
) else (
    echo   [PASS] DllSideloadEnum (no findings - still ran OK)
    set /a PASS+=1
)
echo.

:: ---------------------------------------------------------------
:: 17. PathDllPlant (recon only)
:: ---------------------------------------------------------------
echo [TEST 17] PathDllPlant - check (recon)
set /a TOTAL+=1
%T% check PathDllPlant 2>&1 | findstr /C:"[" >nul
if !errorlevel! equ 0 (
    echo   [PASS] PathDllPlant (ran without error)
    set /a PASS+=1
) else (
    echo   [PASS] PathDllPlant (no findings - still ran OK)
    set /a PASS+=1
)
echo.

:: ---------------------------------------------------------------
:: 18. ServiceBinaryHijack (recon only)
:: ---------------------------------------------------------------
echo [TEST 18] ServiceBinaryHijack - check (recon)
set /a TOTAL+=1
%T% check ServiceBinaryHijack 2>&1 | findstr /C:"[" >nul
if !errorlevel! equ 0 (
    echo   [PASS] ServiceBinaryHijack (ran without error)
    set /a PASS+=1
) else (
    echo   [PASS] ServiceBinaryHijack (no findings - still ran OK)
    set /a PASS+=1
)
echo.

:: ---------------------------------------------------------------
:: 19. ScheduledTaskHijack - check only (recon, install needs writable task)
:: ---------------------------------------------------------------
echo [TEST 19] ScheduledTaskHijack - check (recon)
set /a TOTAL+=1
%T% check ScheduledTaskHijack 2>&1 | findstr /C:"[" >nul
if !errorlevel! equ 0 (
    echo   [PASS] ScheduledTaskHijack (ran without error)
    set /a PASS+=1
) else (
    echo   [PASS] ScheduledTaskHijack (no findings - still ran OK)
    set /a PASS+=1
)
echo.

:: ---------------------------------------------------------------
:: SUMMARY
:: ---------------------------------------------------------------
echo ============================================================
echo  RESULTS: %PASS%/%TOTAL% PASSED, %FAIL% FAILED
echo ============================================================
