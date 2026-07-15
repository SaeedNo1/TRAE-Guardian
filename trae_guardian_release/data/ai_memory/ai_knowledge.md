# AI Knowledge Base - Process Guardian

This file contains offline behavioral indicators and attack patterns for the
daemon's AI analyst. It intentionally does NOT name specific commercial
software as "rogue" to avoid legal/reputation issues. Use this database for
offline behavior matching; use `web_search` for current public reputation of
specific products.

## How to use this knowledge base

1. **Behavior-first analysis**: match what a process *does* against the
   patterns below, not just its name or signer.
2. **Microsoft/Windows signed components** are normally trusted unless there is
   evidence of tampering.
3. **Third-party signed or unsigned processes** that match aggressive patterns
   below should be rated by behavior.
4. **If the user asks "is X software good/bad"**: use `web_search(X)` to get
   current reputation, then combine it with the behavioral patterns here.
5. **If the machine is offline**: rely on the behavior patterns here.

## Universal suspicious behavior patterns

### System modification without consent
- Writing to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  or `RunOnce` without clear installer context.
- Creating Windows Services under `HKLM\SYSTEM\CurrentControlSet\Services`.
- Creating Scheduled Tasks in `C:\Windows\System32\Tasks`.
- Modifying browser default settings (homepage, search provider, new tab).
- Modifying MBR/VBR, boot configuration, or Secure Boot variables.

### Silent / unwanted additional installation
- One installer drops executables, services, or scheduled tasks that the user
  did not explicitly agree to.
- New unrelated products from the same vendor appear after an update.
- Background downloads of additional payloads without user interaction.

### Anti-removal and self-defense
- Protects its own files with ACLs, symlinks, or by restarting immediately after
  termination.
- Leaves services/drivers/registry keys after uninstallation.
- Displays fake warnings to discourage uninstallation.

### Anti-competitor behavior
- Blocks, disables, or uninstalls other security software.
- Prevents competing products from installing or running.
- Modifies firewall/antivirus exclusions to exclude itself only.

### Browser monetization / hijacking
- Changes homepage, default search engine, or new-tab page.
- Installs extensions/toolbars without clear consent.
- Locks browser settings so the user cannot revert them.

### Mass registry / file system mutation
- Hundreds of registry writes across unrelated keys in a short time.
- Writes random-named files across many directories.
- Repeatedly enumerates and modifies many unrelated file paths.

### Persistence abuse
- Multiple persistence mechanisms for a single executable.
- Random or misleading names in Run keys / services / tasks.
- WMI event subscriptions (`ROOT\subscription`) from normal user software.

### Privilege abuse
- Unsigned process running as SYSTEM.
- User-level process touching `HKEY_LOCAL_MACHINE\SYSTEM` or protected kernel
  objects.
- Obtaining SeDebugPrivilege, SeLoadDriverPrivilege, or other sensitive tokens
  without justification.

## Code-injection and tampering indicators

- Unsigned DLL loaded into a Microsoft-signed or system-critical process.
- Reflective DLL loading (PE loaded from memory rather than disk).
- Process hollowing: legitimate process created then image replaced in memory.
- Inline hooks or IAT/EAT modifications in other processes.
- APC injection, thread hijacking, or SetWindowsHookEx across processes.
- Modifying code sections of system DLLs or security software.

## Malware family behavioral indicators

### Ransomware
- Mass file encryption with extension changes.
- Deletion of shadow copies (`vssadmin delete shadows`).
- Ransom notes such as `README*.txt`, `HOW_TO_DECRYPT*`, `*.readme`.
- Disabling backup services and Volume Shadow Copy service.

### Banking / info-stealing trojans
- Web injection into browser processes.
- Credential theft from browsers, mail clients, or cryptocurrency wallets.
- Screenshot capture and keylogging behavior.
- Data exfiltration to Telegram, Discord, Pastebin, or VPS.
- Office macros spawning PowerShell or downloading payloads.

### Remote Access Trojans (RAT)
- Hidden remote desktop, webcam capture, or microphone access.
- Reverse connections to dynamic DNS or recently registered domains.
- Persistence via multiple mechanisms to survive cleanup.

### Cryptominers
- High sustained CPU/GPU usage from an unexpected process.
- Connections to known mining pools.
- Often dropped by other malware or bundled with cracked software.

### Rootkits / bootkits
- Hidden processes or services invisible to normal task managers.
- Kernel-level hooks, driver loading without clear hardware purpose.
- MBR/VBR modifications.

### Wipers
- Destroys files or partition tables without ransom demand.
- Often targets critical infrastructure or specific geographies.

### Supply-chain attacks
- Legitimate vendor signature but malicious payload.
- Backdoored update mechanisms or compromised build pipelines.
- Match known IoCs before treating a signed vendor as malicious.

## Common persistence locations

| Mechanism | Typical registry / path |
|---|---|
| Run keys | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `HKCU` counterpart |
| RunOnce | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services` |
| Scheduled Tasks | `C:\Windows\System32\Tasks` |
| WMI subscriptions | `ROOT\subscription` classes |
| Winlogon | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` |
| Active Setup | `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components` |
| Boot execute | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` |
| Office add-ins | Word/Excel startup folders |
| Browser extensions | Chrome/Edge/Firefox extension directories |

## Network indicators of compromise

| Indicator | Why it matters |
|---|---|
| Connections to dynamic DNS or recently registered domains | Common C2 pattern. |
| Connections to Tor exit nodes or onion services | Anonymization used by attackers. |
| High-volume DNS queries to random-looking domains | Domain Generation Algorithm (DGA). |
| Connections to cryptocurrency mining pools | Cryptominer infection. |
| SMB/RDP brute-force traffic | Lateral movement or ransomware precursor. |
| Outbound connections from `lsass.exe`, `winlogon.exe`, or `csrss.exe` | These system processes normally do not initiate external connections. |
| Large unexpected uploads to file-sharing or cloud storage | Data exfiltration. |

## Normal Windows components that should rarely be flagged

| Process | Normal purpose |
|---|---|
| `svchost.exe` | Generic service host. |
| `services.exe` | Service Control Manager. |
| `lsass.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe` | Critical system processes. |
| `explorer.exe` | Windows shell. |
| `dwm.exe` | Desktop Window Manager. |
| `taskhostw.exe` | Task host. |
| `ctfmon.exe`, `TextInputHost.exe` | Text services / IME. |
| `sihost.exe` | Shell infrastructure host. |
| `dllhost.exe` | COM surrogate. |
| `runtimebroker.exe` | Universal app permissions. |
| `SearchIndexer.exe` | Windows search indexing. |
| `MsMpEng.exe`, `MpDefenderCoreService.exe` | Windows Defender. |
| `smartscreen.exe` | Windows SmartScreen. |

## Notes for the AI analyst

- **Do not publicly label a specific vendor as malware** unless the behavior is
  unambiguously malicious and you have evidence. Use neutral language like
  "exhibits aggressive behavior" or "matches PUP patterns".
- **Reputation data belongs on the web**: when the user asks about a named
  product, call `web_search(product name)` to gather current public opinion.
- **Offline safety**: this file is designed to work without internet. Match
  behaviors described here even when `web_search` is unavailable.
- **Own-process protection**: `trae_guardian*.exe` is the user's security tool.
  Never flag it as malicious.
