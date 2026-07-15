# Virus Signature Database (Unsigned Malware)

This database is queried when the suspect process has **NO valid digital signature**.
Matching is behavior-first and keyword-based. When multiple high-confidence
indicators below match the observed behavior, the process should be treated as
CONFIRMED malware and the daemon will auto-clean its directory WITHOUT user
authorization.

Search strategy for the AI analyst:
- Extract keywords from the daemon log lines (process name, path, registry
  keys touched, files written, network destinations, command line).
- Search this file for each keyword. Each hit raises the confidence score.
- **High match** (>=3 distinct indicators from the same family) => CONFIRMED,
  return `cleanup` containing the process's own directory. The daemon will
  terminate the process, add it to the repeated-kill list, and recursively
  delete its install directory without asking the user.
- **Medium match** (1-2 indicators) => HIGH with `needsApproval=true`; do NOT
  auto-clean. Request `search_logs` for more context or `web_search` for
  reputation before escalating.
- **No match** => LOW; do not clean.

---

## 1. Ransomware (keyword: ransomware, encrypt, shadow, vssadmin, decrypt, bitcoin, wallet)

Behavioral indicators:
- Mass file reads followed by writes with a new extension (e.g., `.locked`,
  `.enc`, `.crypt`, `.crypted`, `.locked`, `.readme`, `.pay`, `.onion`).
- Calls `vssadmin delete shadows /all /quiet` or `wbadmin delete catalog`.
- Disables the Volume Shadow Copy service, backup services, or repair tools.
- Drops a ransom note named `README*.txt`, `HOW_TO_DECRYPT*`, `!!!READ!!!*`,
  `YOUR_FILES_ARE_ENCRYPTED*`, `RESTORE_FILES*` in many directories.
- Connects to a Tor hidden service or known ransom payment portal.
- Writes a Bitcoin/ransom wallet address to disk or to the ransom note.
- Enumerates network shares and attempts encryption on remote hosts.
- Sets the desktop wallpaper to a ransom message.
- Clears Windows Event Logs to hide the encryption trail.

High-confidence file/path indicators:
- Presence of `*how_to_decrypt*`, `*restore_files*`, `*your_files*` notes.
- Execution from `%AppData%`, `%LocalAppData%\Temp`, or `%ProgramData%` with
  a random-looking executable name.
- Command line containing `vssadmin`, `wbadmin`, `bcdedit /set recoveryenabled`,
  or `cipher /w`.

Action guidance: HIGH confidence after >=3 indicators. Auto-clean the entire
executable directory; the process is destructive and must not survive.

---

## 2. Info-stealers / Credential thieves (keyword: stealer, credential, wallet, cookie, login, password, keylog, exfiltrate, discord, telegram, browser)

Behavioral indicators:
- Reads files matching `Login Data`, `Cookies`, `Web Data`, `Local State`
  inside Chrome/Edge/Firefox/Opera user profile directories.
- Reads cryptocurrency wallet files (`wallet.dat`, `keystore`, `seed`, `.wallet`).
- Reads saved passwords from browser password stores or Windows Credential
  Manager (`%AppData%\Microsoft\Credentials`, `Vault`).
- Reads Discord/Telegram session tokens from `%AppData%\discord\Local Storage`
  or `%AppData%\Telegram Desktop`.
- Captures keystrokes via `SetWindowsHookEx`, low-level keyboard hook, or
  raw input. Writes captured input to a log file.
- Captures screenshots via `BitBlt` + `CreateCompatibleBitmap` and stores
  them in a temp folder before exfiltration.
- Uploads collected data to Telegram Bot API, Discord webhook, Pastebin,
  `tmpfiles.org`, `file.io`, `transfer.sh`, or a hardcoded VPS.
- Execution chain: Office macro -> PowerShell -> encoded payload -> stealer.
- Parent process is `WINWORD.EXE`/`EXCEL.EXE` and child is an unsigned
  executable dropped in `%Temp%`.

High-confidence file/path indicators:
- Reads from `%LocalAppData%\Google\Chrome\User Data\*\Login Data`.
- Writes a staging archive (`*.zip`, `*.rar`, `*.7z`) in `%Temp%` before upload.
- Outbound HTTPS POST with a large body (>50 KB) to a non-CDN domain.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 3. Remote Access Trojans (RAT) (keyword: rat, remote, backdoor, reverse, shell, vnc, webcam, microphone, capture)

Behavioral indicators:
- Opens a persistent reverse TCP/HTTPS connection to a dynamic DNS host
  (e.g., `*.ddns.net`, `*.noip.com`, `*.duckdns.org`) or recently
  registered domain.
- Listens on a high port and accepts inbound connections (bind shell).
- Accesses webcam via `avicap32`/DirectShow or microphone via `waveIn*` APIs.
- Spawns `cmd.exe`/`powershell.exe` as a child and pipes stdin/stdout over
  the network socket.
- Supports a command grammar: `!screenshot`, `!webcam`, `!keylog`, `!download`,
  `!upload`, `!exec`, `!persist`, `!kill`.
- Writes captured data to a hidden folder (`%AppData%\Microsoft\Network\...`).
- Creates registry Run/RunOnce key with a random name to survive reboot.
- Modifies the host firewall or adds a Windows Defender exclusion for itself.
- Persists via WMI event subscription in `ROOT\subscription` (`__EventFilter`,
  `CommandLineEventConsumer`).
- Parents to `explorer.exe` but launches `vbscript`/`mshta`/`powershell`
  children.

High-confidence file/path indicators:
- Executable lives in `%AppData%\Microsoft\` with a system-looking but
  misspelled name (e.g., `svchost.exe` outside `System32`).
- Outbound connection on non-standard ports (4444, 5555, 1234, 8080, 8443,
  9001, 1337).
- Inbound listener on a high port (>49152) bound to `0.0.0.0`.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory
and remove persistence keys.

---

## 4. Cryptominers (keyword: miner, mining, pool, xmrig, stratum, cryptonight, randomx, monero, nicehash)

Behavioral indicators:
- Sustained high CPU/GPU usage from a process that has no clear interactive UI.
- Outbound connections to ports 3333, 4444, 5555, 7777, 14444, 45700.
- DNS lookups for `*pool*`, `*mine*`, `*xmr*`, `*monero*`, `*ethash*`,
  `*nicehash*`, `*nanopool*`, `*f2pool*`, `*antpool*`.
- Reads a `config.json` containing `stratum+tcp://`, `stratum+ssl://`, a
  wallet address, or a worker name.
- Process spawns `cmd.exe` to set CPU affinity or kill competing miners.
- Bundled with a "free" software installer; spawns as a scheduled task
  configured to launch every minute.
- Modifies its own process priority to below normal to evade detection.

High-confidence file/path indicators:
- Executable path contains `xmrig`, `cpuminer`, `ccminer`, `ethminer`,
  `tsm`, `teamredminer`, `lolminer`, `nbminer`, `PhoenixMiner`.
- Drops a `start.bat` that launches the miner with `--background` or
  `--donate-level 0`.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 5. Rootkits / Bootkits (keyword: rootkit, bootkit, mbr, vbr, boot, driver, kernel, hook, stealth, hide)

Behavioral indicators:
- Writes raw bytes to `\\.\PhysicalDrive0` (or `\\.\C:`) to modify the
  Master Boot Record (MBR) or Volume Boot Record (VBR).
- Loads a kernel-mode driver (`NtLoadDriver`, `ZwLoadDriver`) that has no
  corresponding hardware purpose.
- Hooks system service dispatch table (SSDT), interrupts, or IRP handlers.
- Hides processes, files, registry keys, or network ports from enumeration
  APIs (`NtQuerySystemInformation`, `NtQueryDirectoryFile`).
- Disables PatchGuard or modifies kernel code sections.
- Intercepts IRP_MJ_DIRECTORY_CONTROL to filter file listings.
- Installs a filter driver that hides its own files.
- Boots from a UEFI payload (LoJax-style) by writing to the SPI flash.

High-confidence file/path indicators:
- Writes to `\\.\PhysicalDrive0` sectors 0-16.
- Drops a `.sys` file to `%SystemRoot%\system32\drivers\` and loads it.
- Registry key `HKLM\SYSTEM\CurrentControlSet\Services\<random>` with type=1
  (kernel driver) and signed by an unknown or self-signed cert.

Action guidance: HIGH confidence after >=1 indicator (bootkits are always
malicious). Auto-clean directory, remove the dropped driver, mark the affected
disk for MBR repair on next boot.

---

## 6. Wipers / Destructive malware (keyword: wiper, destroy, delete, format, partition, overwrite, mbr)

Behavioral indicators:
- Opens `\\.\PhysicalDrive0` with `GENERIC_WRITE` and overwrites sectors.
- Calls `DeleteFileW` in a loop across the entire user profile, Program
  Files, or `C:\Windows`.
- Overwrites files with `0x00`, `0xFF`, or random bytes (not encrypted).
- Calls `FormatEx` or `DeviceIoControl(IOCTL_DISK_FORMAT_TRACKS)`.
- Modifies the partition table (GPT/MBR) to remove active partitions.
- Writes a destructive payload in `BootExecute` under
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`.
- Calls `StopService` + `DeleteService` on critical services (`EventLog`,
  `Schedule`, `WinDefend`).
- Issues `shutdown /r /t 0` after destruction to trigger a non-bootable
  state.

High-confidence file/path indicators:
- Writes to `\\.\PhysicalDrive0` outside of a partition manager tool.
- Mass file deletion across unrelated directories within 30 seconds.
- Drops a destructive payload in `C:\Windows\Temp\` with a random name.

Action guidance: HIGH confidence after >=1 indicator. Auto-clean directory
and immediately request a reboot for MBR/partition repair.

---

## 7. Botnets / DDoS clients (keyword: botnet, ddos, flood, syn, udp, amplification, irc, command, c2, slave, zombie)

Behavioral indicators:
- Maintains a persistent connection to an IRC server on port 6667/6697 and
  joins a channel to await commands.
- Sends many outbound UDP/TCP packets to a single target IP (SYN flood,
  UDP flood, HTTP flood).
- Issues DNS queries with very long random subdomains (DNS amplification).
- Parses a command set: `!ddos`, `!stop`, `!download`, `!update`, `!visit`,
  `!udpflood`, `!synflood`, `!httpflood`.
- Spreads via SMB (port 445) by brute-forcing credentials or exploiting
  EternalBlue (MS17-010).
- Updates itself by downloading a new binary from a C2 URL and replacing
  its own image.
- Persists via a Windows Service with a misleading name (e.g., `Windows
  Update Service`, `Network Helper`).

High-confidence file/path indicators:
- Multiple outbound connections to the same target port (445, 80, 443, 53)
  with small packets at high frequency.
- Listens on a hidden port and accepts remote shell-like commands.
- Binary stored in `C:\ProgramData\` or `%Public%` with a misleading name.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 8. Network worms / Lateral movement (keyword: worm, smb, eternalblue, ms17-010, bluekeep, rdp, wmi, psexec, lateral, spread)

Behavioral indicators:
- Sends many SMB requests to internal IPs (port 445) attempting to exploit
  MS17-010 or brute-force credentials.
- Spawns `cmd.exe` or `powershell.exe` via WMI (`Win32_Process::Create`)
  on remote hosts.
- Copies itself to `\\<host>\ADMIN$` or `\\<host>\C$\Windows\Temp\`.
- Uses `schtasks /create /s <remote>` to install itself on remote hosts.
- Scans port 3389 (RDP) or 445 (SMB) on the local /24 subnet.
- Exploits BlueKeep (CVE-2019-0708) or PrintNightmare (CVE-2021-34527) for
  remote code execution.
- Drops itself to `\\<host>\IPC$` and triggers `schtasks /run` remotely.

High-confidence file/path indicators:
- Outbound SMB connections to >10 internal IPs within a minute.
- Copies itself to ADMIN$ shares on multiple hosts.
- Drops a `.dll` to `\\<host>\C$\Windows\System32\spool\drivers\x64\3\`
  (PrintNightmare pattern).

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 9. Fileless / LOLBins abuse (keyword: fileless, powershell, mshta, rundll32, regsvr32, certutil, bitsadmin, wscript, cscript, msiexec, lolbin)

Behavioral indicators:
- `powershell.exe` launched with `-ExecutionPolicy Bypass`, `-EncodedCommand`
  (Base64), `-WindowStyle Hidden`, or `Invoke-Expression` downloading from
  the internet.
- `mshta.exe` runs a remote `*.hta` URL: `mshta http://...`.
- `rundll32.exe` loads a DLL from `%Temp%`, `%AppData%`, or a remote WebDAV
  share (`\\host@port\path`).
- `certutil.exe -decode` or `-urlcache` used to download a payload.
- `bitsadmin.exe /transfer` used to fetch a payload.
- `regsvr32.exe /s /u /i:http://... scrobj.dll` (Squiblydoo).
- `wmic.exe process call create` used to launch a child off-path.
- `msiexec.exe /i http://... /quiet` installs a remote MSI.
- WMI permanent event subscription (`__EventFilter` + `CommandLineEventConsumer`)
  created by a user-level process.
- Powershell writing a script block to a registry value (e.g.,
  `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` containing a Base64
  payload) to avoid file-on-disk detection.

High-confidence file/path indicators:
- Parent is `explorer.exe` but the command line of `powershell.exe`/`cmd.exe`
  contains `-enc`, `-EncodedCommand`, `IEX(`, `DownloadString`, `Invoke-Expression`.
- Process launched from `cmd.exe` with a command line that contains `http://`,
  `https://`, `ftp://` combined with `-hidden` or `-bypass`.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean the dropped
payload directory and remove the registry-stored payload.

---

## 10. Droppers / Downloaders (keyword: dropper, downloader, payload, stage, install, fetch, bot)

Behavioral indicators:
- The first-stage executable is small (<100 KB) and its only behavior is to
  download and execute a second-stage binary.
- Downloads an executable from a URL ending in `.exe`, `.dll`, `.scr`,
  `.com` and saves it to `%Temp%` or `%AppData%`.
- Uses `URLDownloadToFile`, `WinHttpDownloadFile`, or `WebClient.DownloadFile`.
- Uses `CreateProcessW` to launch the downloaded payload.
- Writes a `.bat`/`.vbs`/`.ps1` bootstrap that launches the payload.
- The downloaded payload has a random name like `bf4a9c.exe`.
- The dropper itself runs from `%Temp%`, `%ProgramData%`, or a user
  profile root — never from `Program Files`.

High-confidence file/path indicators:
- Dropped file in `%Temp%\<random>\<random>.exe`.
- Uses `WinHttpOpen` with a non-standard User-Agent string.
- Process running from a path containing `temp` or `appdata`.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean the dropper
directory AND the dropped payload directory.

---

## 11. Banking trojans (keyword: banking, banker, webinject, cashier, atm, swift, redirect)

Behavioral indicators:
- Web injects into `chrome.exe`, `firefox.exe`, `msedge.exe`, `iexplore.exe`
  via DLL injection or hooking `WinHttpSendRequest`/`InternetWriteFile`.
- Hooks `NtQueryDirectoryFile` or `NtEnumerateKey` to hide its own files.
- Modifies the `hosts` file (`%SystemRoot%\System32\drivers\etc\hosts`) to
  redirect banking domains.
- Stages stolen credentials in `%AppData%\<random>\` and uploads via HTTPS.
- Issues VNC-style screenshots when the user browses a banking URL.
- Captures clipboard content when clipboard data resembles an account
  number or IBAN.
- Reads `cookies.sqlite` from Firefox and `Login Data` from Chrome.

High-confidence file/path indicators:
- Drops a DLL named `*.dll` into `%AppData%` and injects into browser
  processes.
- Modifies `hosts` file (which is normally empty) with bank domain entries.
- Connects to a C2 domain resolving to a recent registration.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 12. Adware / Click fraud bots (keyword: adware, click, fraud, impression, ad, redirect, popup)

Behavioral indicators:
- Silently opens browser windows to ad URLs without user input.
- Sends simulated click events to ad networks via `WinHttpSendRequest`.
- Hooks `WindowProc` to inject ad content into other windows.
- Modifies `hosts` file to redirect ad-network domains to localhost.
- Spawns `chrome.exe --headless` or `msedge.exe --headless` to click ads.
- Runs as a hidden process that periodically visits a list of URLs.
- Rotates User-Agent strings to evade ad network fraud detection.

High-confidence file/path indicators:
- Hidden process issuing many HTTPS GET requests to ad-network domains.
- Drops `*.dll` to `%AppData%` and injects into browser processes.
- Process runs with no visible UI but issues network requests at fixed
  intervals.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 13. Spyware / Surveillanceware (keyword: spyware, surveillance, monitor, record, keylog, capture, screen, webcam, mic)

Behavioral indicators:
- Captures keystrokes and writes them to an encrypted log file.
- Captures the clipboard on every change and logs clipboard text.
- Takes periodic screenshots (every 30 seconds, every minute).
- Accesses webcam/microphone without indicator and stores recordings.
- Logs window titles, foreground window changes, and idle time.
- Logs user location based on WiFi SSID scan or IP geolocation.
- Exfiltrates logs via email, FTP, or HTTPS to a personal server.
- Often disguised as a "parental control" or "employee monitoring" tool but
  runs silently with no UI and no uninstaller.

High-confidence file/path indicators:
- Writes to `%AppData%\Microsoft\` with a system-looking name.
- Stores keystrokes in a file named `*.log`, `*.dat`, `*.bin` with
  suspicious structure (timestamps + key codes).
- Captures screen to `*.bmp`/`*.jpg` in a hidden folder.

Action guidance: HIGH confidence after >=2 indicators. Auto-clean directory.

---

## 14. Self-propagating malware / USB worms (keyword: usb, autorun, worm, spread, removable)

Behavioral indicators:
- Creates `autorun.inf` on every removable drive plugged into the machine.
- Copies itself to removable drives with a misleading name (`passwords.txt.exe`,
  `invoice.pdf.exe`, `bank_statement.exe`).
- Listens for `WM_DEVICECHANGE` and writes itself to new removable media.
- Spreads via network shares by writing to `\\<host>\` paths.
- Drops a `.lnk` shortcut that points to a hidden copy of itself on the
  removable drive.

High-confidence file/path indicators:
- Writes `autorun.inf` (rarely used legitimately since Windows 7).
- Creates `*.lnk` files pointing to a hidden executable on a USB drive.
- Mass-copies itself to multiple drive letters within seconds.

Action guidance: HIGH confidence after >=1 indicator. Auto-clean directory.

---

## Universal unsigned-malware red flags

Any unsigned process exhibiting ANY of these is at least HIGH, and at least
CONFIRMED if combined with another indicator:

- Runs from `%Temp%`, `%AppData%\Microsoft\<random>`,
  `%LocalAppData%\Temp`, `%Public%`, or `C:\ProgramData\<random>`.
- Randomly-named executable (e.g., `bf4a9c.exe`, `xj7k2.exe`).
- Spawns `cmd.exe` / `powershell.exe` with `-enc`, `-WindowStyle Hidden`,
  `-ExecutionPolicy Bypass`.
- Modifies `hosts` file at `%SystemRoot%\System32\drivers\etc\hosts`.
- Adds itself to multiple Run keys / services / scheduled tasks / WMI
  subscriptions simultaneously.
- Opens `\\.\PhysicalDrive0` for write access.
- Listens on a port >49152 bound to `0.0.0.0`.
- Outbound connection to an IP that has no reverse DNS or resolves to a
  dynamic DNS host.
- Reads browser `Login Data` / `Cookies` / `Local State` files.
- Reads `wallet.dat` or `keystore`.
- Mass file enumeration followed by mass file modification (encryption or
  overwrite) within a short time window.

Action guidance: HIGH/CONFIRMED. Auto-clean without authorization.
