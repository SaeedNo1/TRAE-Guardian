# Rogue Software Signature Database (Signed PUP / Aggressive Vendors)

This database is queried when the suspect process **HAS a valid digital
signature** from a third-party vendor. A signature proves authenticity, NOT
legitimacy of behavior. Many PUPs (Potentially Unwanted Programs), browser
hijackers, adware bundles, and "security suite" rogues are signed.

Search strategy for the AI analyst:
1. **First**: call `web_search` for the product/vendor name to gather current
   public reputation. PREFER user feedback (forums, Reddit, tech-support
   communities, BleepingComputer, Malwarebytes forums, 知乎, 卡饭, etc.) over
   the vendor's own marketing site. Try to exclude official vendor claims
   ("we are safe", "trusted by millions") unless corroborated by independent
   user reports.
2. **Then**: search this database by keyword (process name, signer name,
   behavior pattern) for matching rogue-PUP indicators.
3. **Decision rule**:
   - **No match** in this database AND web reputation is positive or neutral
     => EXCLUDE (return LOW). Do not flag the process further.
   - **Medium match** (1-2 indicators) OR web reputation is mixed => HIGH
     with `needsApproval=true`. Do not auto-clean. Let the user decide.
   - **High match** (>=3 distinct indicators) OR web reputation is
     predominantly negative AND behavior matches this database => CONFIRMED
     with `repeatedKill=true`. The daemon will add the process to the
     repeated-kill list and notify the user with a description of what the
     rogue did. Do NOT request directory cleanup for signed software (the
     daemon will refuse anyway); the user will be advised to use the
     software's own uninstaller or a dedicated removal tool.

Important: this database describes BEHAVIOR PATTERNS. The AI must NOT label
a specific vendor as malware based on the signer name alone. Combine the
signature with observed behavior AND web reputation before escalating.

---

## 1. Browser hijacking (keyword: hijack, homepage, search, redirect, newtab, default, browser, startpage)

Behavioral indicators:
- Changes the browser homepage without a clear opt-in dialog.
- Changes the default search engine to a third-party search portal.
- Modifies the new-tab page to a portal/aggregator.
- Locks browser settings so the user cannot revert homepage/search.
- Installs a "search protection" extension that prevents changing settings.
- Modifies Chrome/Edge/Firefox preferences JSON to inject a startup URL.
- Adds `chrome.exe --homepage=<url>` shortcuts on the desktop.
- Redirects search queries from Google/Bing to a third-party portal.
- Drops `Preferences` file modifications into the browser user-data dir.

High-confidence combined indicators (signature + behavior):
- Signed process touching `HKCU\Software\Microsoft\Internet Explorer\Main`
  Start Page, and the user did not launch a browser installer.
- Signed process writing to `Chrome\User Data\Default\Preferences`
  `homepage`/`session.startup_urls` fields.

Action guidance: When >=2 indicators AND web reputation confirms the vendor
has a history of browser hijacking => CONFIRMED with `repeatedKill=true`.
Tell the user: "this signed process hijacked your browser settings
(homepage/search engine); added to the repeated-kill list. Use the software's
own uninstaller or a dedicated removal tool to fully remove it."

---

## 2. Forced toolbar / extension installation (keyword: toolbar, extension, addon, plugin, browser helper, BHO)

Behavioral indicators:
- Installs a browser extension/toolbar without a clear consent dialog.
- Loads a Browser Helper Object (BHO) into Internet Explorer.
- Drops `.crx`/`.xpi` extension packages into the browser extensions dir.
- Registers the extension with a hardcoded ID and prevents disable.
- Forces the extension to load via `--load-extension` command line.
- Re-installs the extension after the user removes it.

Action guidance: >=2 indicators + negative web reputation => CONFIRMED with
`repeatedKill=true`.

---

## 3. Anti-removal / Self-defense (keyword: anti-removal, self-defense, protect, restart, respawn, ACL, permission)

Behavioral indicators:
- Protects its own files with restrictive ACLs (`DENY` for `Everyone`).
- Restarts itself immediately after termination (watchdog process or
  service).
- Re-creates its Run key / service / scheduled task after deletion.
- Drops a watchdog service that re-launches the main process.
- Refuses to be killed via Task Manager (`Access denied`).
- Sets file ownership to `TrustedInstaller` to prevent deletion.
- Uses a kernel driver to protect its files/registry (signed driver, but
  used purely for self-protection).
- Mutually-restarting pair of processes (A restarts B, B restarts A).
- On uninstall, spawns a "repair" task that re-installs the product.

Action guidance: >=2 indicators + web reports of difficult removal =>
CONFIRMED with `repeatedKill=true`. The repeated-kill list is the only
reliable way to keep the rogue suppressed.

---

## 4. Anti-competitor behavior (keyword: anti-competitor, block, disable, uninstall, competitor, security, antivirus)

Behavioral indicators:
- Blocks installation of competing security software.
- Disables or uninstalls other antivirus products without consent.
- Adds itself to Windows Defender exclusions while removing competitors'
  exclusions.
- Marks competitor executables as "infected" and quarantines them.
- Modifies the hosts file to block competitor update/download servers.
- Refuses to start when a competitor is running.
- Instructs the user to uninstall competitors via fake warnings.

Action guidance: >=2 indicators => CONFIRMED with `repeatedKill=true`. This
is the most damaging PUP behavior because it removes user choice and weakens
overall security.

---

## 5. Silent bundling / Unwanted additional installs (keyword: bundle, silent, install, additional, extra, drop, offer)

Behavioral indicators:
- One installer drops multiple unrelated products without explicit opt-in.
- Pre-checked "Express install" checkboxes that install partner PUPs.
- Background download of additional payloads after the initial install.
- New unrelated vendor signed executables appear after an update.
- Drops a "software manager" / "update tracker" that periodically installs
  partner software.
- The uninstaller removes only the main product and leaves the bundles.

Action guidance: >=2 indicators + web reputation confirms bundling history
=> CONFIRMED with `repeatedKill=true`.

---

## 6. Excessive persistence (keyword: persistence, run, runonce, service, scheduled, task, wmi, startup)

Behavioral indicators:
- Single product creates multiple Run keys, services, AND scheduled tasks.
- Run key name does not match the product name (misleading).
- Service name impersonates a Windows component (`Windows Helper Service`).
- Scheduled task runs every minute or on every logon.
- WMI event subscription created for persistence (very rare for legit
  software).
- Multiple persistence mechanisms for a single executable (defense in
  depth against user removal).
- Adds itself to `Winlogon\Userinit` or `Winlogon\Shell` (very high
  confidence for rogue behavior).

Action guidance: >=3 persistence mechanisms => HIGH. Combined with another
indicator (anti-removal or anti-competitor) => CONFIRMED with
`repeatedKill=true`.

---

## 7. Fake security alerts / Scareware (keyword: scareware, fake, alert, warning, scan, virus, threat, purchase, license)

Behavioral indicators:
- Displays fake virus-detection popups to encourage purchase.
- Reports non-existent threats and offers a paid "full version" to clean.
- Triggers UAC prompts for trivial operations to look authoritative.
- Shows exaggerated scan results (hundreds of "errors" in the registry).
- Bundles a "registry cleaner" that invents errors to encourage upgrade.
- Triggers system tray notifications warning of non-existent threats.
- Pre-empts Windows Action Center with its own (fake) security status.

Action guidance: >=2 indicators + web reputation confirms scareware
history => CONFIRMED with `repeatedKill=true`.

---

## 8. Aggressive advertising / Ad injection (keyword: ad, advertise, popup, inject, banner, insert, commercial)

Behavioral indicators:
- Injects ads into web pages that did not have them.
- Opens popup windows with commercial content periodically.
- Inserts affiliate codes into e-commerce URLs.
- Replaces legitimate ads on web pages with its own.
- Tracks browsing to serve targeted ads without consent.
- Spawns hidden browser instances to generate ad impressions.
- Modifies search results to inject sponsored links.

Action guidance: >=2 indicators + web reputation confirms adware =>
CONFIRMED with `repeatedKill=true`.

---

## 9. Data harvesting without consent (keyword: collect, harvest, telemetry, tracking, data, personal, privacy)

Behavioral indicators:
- Collects browsing history without explicit consent.
- Uploads user behavior data to a third-party server.
- Reads contacts/email/address book and uploads them.
- Reads unique machine identifiers (MAC, disk serial, Windows product key)
  and uploads them.
- Collects installed software list and uploads.
- Reads clipboard content and uploads.
- Stores collected data in a hidden folder before upload.
- Continues collecting after the user disables "telemetry" in settings.

Action guidance: >=2 indicators + web reports of privacy concerns =>
CONFIRMED with `repeatedKill=true`.

---

## 10. Difficult uninstall / Leftover persistence (keyword: uninstall, leftover, residual, remain, remove, cannot)

Behavioral indicators:
- Uninstaller is missing, hidden, or requires a special removal tool.
- After uninstall, services / drivers / scheduled tasks remain.
- After uninstall, browser hijack settings remain.
- Uninstaller requires "Internet connection" or "repair" before it will run.
- Uninstaller pops up a "are you sure?" dialog with misleading warnings.
- Uninstaller requires the user to fill out a survey before completing.
- Files are locked during uninstall and require a reboot that never
  finishes the cleanup.
- Vendor offers a separate "Removal Tool" — admission that the normal
  uninstaller is incomplete.

Action guidance: >=2 indicators + web reputation reports removal difficulty
=> HIGH with `needsApproval=true`. The user should be advised to use the
vendor's removal tool or a dedicated PUP remover.

---

## 11. Driver / Service abuse (keyword: driver, service, kernel, system, privilege, esc, elevate)

Behavioral indicators:
- Installs a kernel driver for a user-mode product without clear purpose.
- Driver is signed but used purely to bypass user-mode restrictions.
- Service runs as SYSTEM for a feature that does not require it.
- Service impersonates a Windows component (`Windows Update Helper`).
- Installs a filter driver that intercepts file/network/registry requests.
- Uses the driver to terminate other processes (anti-competitor).
- Loads the driver at boot via `BootExecute` or `Services` (type=1).

Action guidance: >=2 indicators => HIGH. Combined with anti-competitor or
anti-removal => CONFIRMED with `repeatedKill=true`.

---

## 12. Misleading marketing / Fake trust signals (keyword: trust, certified, microsoft, partner, award, fake, misleading)

Behavioral indicators:
- UI claims "Microsoft Gold Partner" or "Certified by Microsoft" without
  verification.
- UI displays fake awards ("5-star editor review") from non-existent
  publications.
- Shows fake user testimonial screenshots.
- Marketing site uses countdown timers ("offer expires in 5 minutes").
- Uses a name that closely resembles a Microsoft or antivirus product.
- Uses a logo/color scheme similar to Windows Security Center.
- Pre-empts the Windows Security status with its own (misleading) panel.

Action guidance: >=2 indicators + web reputation reports misleading
marketing => HIGH with `needsApproval=true`.

---

## Universal signed-PUP red flags

A signed process exhibiting ANY combination of the following is at least HIGH,
and CONFIRMED if combined with negative web reputation:

- Multiple persistence mechanisms (Run + Service + Scheduled Task).
- Restarts itself immediately after being terminated.
- Modifies browser settings without an explicit consent dialog.
- Installs a browser extension that cannot be disabled.
- Disables or quarantines competitor executables.
- Displays fake security alerts or exaggerated scan results.
- Bundles additional products without explicit opt-in.
- Difficult to uninstall (services/drivers/registry remain).
- Reads and uploads user browsing data without consent.
- Uses a kernel driver purely for self-protection or anti-competitor action.
- Service runs as SYSTEM for a feature that does not require it.
- Adds itself to Windows Defender exclusions.
- Modifies the hosts file.
- Misleading service name impersonating a Windows component.

Action guidance: For signed software, the daemon will NOT auto-clean the
directory (to avoid breaking a legitimate signed product by mistake). The
correct response is:
- CONFIRMED + `repeatedKill=true` => the daemon will keep killing the
  process on every respawn and show the user a detailed description of the
  rogue behavior. The user is advised to use the official uninstaller or
  a dedicated removal tool.
- HIGH + `needsApproval=true` => popup to the user with a description of
  the concerning behavior; the user decides whether to allow it.

---

## Reputation heuristics (web_search signal processing)

When evaluating web_search results for a signed vendor, weight sources as
follows:

| Source type | Weight | Reason |
|---|---|---|
| Independent security vendor reports (Kaspersky, ESET, Bitdefender, Malwarebytes) | High | Professional analysis |
| Tech community forums (BleepingComputer, Malwarebytes, Reddit r/techsupport) | High | Real user experience |
| Regional tech communities (知乎, 卡饭论坛, V2EX, 远景论坛) | High | Local user feedback |
| Microsoft Community / Answers.Microsoft | Medium | Often user-reported |
| Software review sites (Softpedia, FileHorse, alternativeTo) | Medium | Editor + user reviews |
| Vendor's own site / official blog | LOW | Marketing, exclude unless corroborated |
| Press releases / sponsored articles | LOW | Marketing, exclude |
| Awards/certifications on vendor's own site | LOW | Self-claimed, exclude |

Signs that the vendor's reputation is NEGATIVE (independent of this DB):
- Multiple independent user reports of "cannot uninstall", "keeps coming back",
  "hijacked my browser", "disabled my antivirus".
- Security vendor classification as PUP/Adware/Hijacker.
- Removal guides published by independent security sites.
- Long-standing forum threads with many users complaining.
- Vendor listed on PUP/adware databases (without naming specific software
  here, the AI may use web_search results that reference such databases).

Signs that the vendor's reputation is POSITIVE:
- Multiple independent sources confirm legitimate purpose.
- No removal-guide articles from independent security sites.
- No PUP classification from major security vendors.
- Active user community with positive engagement (not fake reviews).
- Vendor responds promptly and helpfully to support questions.

Action guidance: If web reputation is positive AND no indicators from this
database match => EXCLUDE (return LOW). If web reputation is negative AND
>=1 indicator matches => CONFIRMED with `repeatedKill=true`.
