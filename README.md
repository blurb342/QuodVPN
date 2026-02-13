# QuodVPN

PowerShell-based VPN connector for Cisco Secure Client (AnyConnect), built for Quod Financial.

Automates VPN authentication (including TOTP multi-factor), provides one-click connectivity, and stores credentials securely using the Windows Data Protection API.

## Features

- **One-click VPN connection** with stored credentials and automatic OTP generation
- **Quick Connect** to the last-used endpoint with a single keypress
- **TOTP (RFC 6238)** built in — no separate authenticator app required
- **DPAPI-encrypted credential storage** (password and OTP secret never stored in plaintext)
- **Connectivity quality testing** against all configured endpoints (ICMP with TCP fallback)
- **Auto-update** via GitHub (Git blob SHA comparison — no manual version bumping)
- **Quod network detection** via DNS suffix matching
- **Process management** for QuodFrontEnd applications
- **Desktop shortcut** creation with Ctrl+Alt+V hotkey

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10 / 11 |
| PowerShell | 5.0 or higher (Core 7.x also supported) |
| Cisco Secure Client | `vpncli.exe` must be installed |
| Execution Policy | `RemoteSigned` or `Bypass` |

## Quick Start

```powershell
# Run directly
powershell -ExecutionPolicy Bypass -File .\Connect-QuodVPN.ps1

# Or create a desktop shortcut from the Setup menu (Option 2 > D)
```

On first launch, choose **Option 2 (Setup)** to configure:

1. VPN username and password
2. OTP secret (Base32-encoded, from your MFA enrollment)
3. VPN gateway addresses
4. DNS suffixes for Quod network detection

Settings are saved automatically when you choose **Save and Return**.

## Configuration Storage

Settings are stored in a centralized, user-specific location that is independent of where the script lives:

| File | Location | Contents |
|---|---|---|
| `settings.xml` | `%LOCALAPPDATA%\QuodVPN\` | VPN name, username, addresses, DNS suffixes, paths, preferences |
| `secure_settings.dat` | `%LOCALAPPDATA%\QuodVPN\` | DPAPI-encrypted VPN password and OTP secret |
| `VPNConnectionLog.txt` | `<script directory>\Logs\` | Application logs (stays with the script) |

This means you can move, copy, or update the script without losing your configuration. Feature branches and auto-updates work without affecting your saved credentials.

### Migration from Earlier Versions

If you are upgrading from a version that stored settings alongside the script:

- Settings are **automatically migrated** to `%LOCALAPPDATA%\QuodVPN\` on first run
- A `.quodvpn-migrated` marker file is left in the old location explaining where settings went
- If migration fails for any reason, the script falls back to the old location transparently

## Menu Reference

### Main Menu

| Key | Action |
|---|---|
| **1** | Connect or disconnect VPN (select from configured endpoints) |
| **2** | Setup options (credentials, paths, addresses) |
| **O** | Show live OTP code with countdown timer |
| **H** | Help screen |
| **Q** | Quick Connect to last-used endpoint |
| **T** | Connectivity quality test across all endpoints |
| **L** | Open log file |
| **9** | Exit |

When connected to the Quod network, the main menu displays connection status and latency quality.

If QuodFrontEnd processes are running, they are listed with options to kill individually (`k1`, `k2`, ...) or all at once (`K`).

### Setup Menu

| Key | Action |
|---|---|
| **1** | VPN Username |
| **2** | VPN Password (stored encrypted) |
| **3** | VPN Profile (group name on Cisco firewall) |
| **4** | OTP Secret (Base32-encoded, stored encrypted) |
| **5** | Cisco VPN CLI path (`vpncli.exe`) |
| **6** | Cisco VPN UI path (`csc_ui.exe`) |
| **7** | VPN Addresses (list editor — add, edit, delete endpoints) |
| **8** | DNS Suffixes (list editor — for Quod network detection) |
| **9** | Save and Return |
| **0** | Exit without Saving |
| **D** | Create Desktop Shortcut (Ctrl+Alt+V) |

## Parameters

All parameters are optional. Settings from the config file take precedence after first setup.

```powershell
.\Connect-QuodVPN.ps1 `
    -VpnName "MyVPN" `
    -VpnUsername "user@example.com" `
    -VpnPassword (Read-Host -AsSecureString) `
    -OtpSecret (Read-Host -AsSecureString) `
    -VpnProfile "SaaSVPN_RD_Profile" `
    -VpnAddresses @("vpn1.example.com", "vpn2.example.com:8443") `
    -QuodDnsSuffixes @("quod.local", "quodfinancial.com") `
    -LogDirectory "C:\Logs\QuodVPN" `
    -MaxLogSizeMB 10 `
    -VpnQueryTimeoutMs 15000 `
    -VpnConnectTimeoutMs 30000
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `VpnName` | string | — | VPN connection display name |
| `VpnUsername` | string | — | Authentication username |
| `VpnPassword` | SecureString | — | Authentication password |
| `OtpSecret` | SecureString | — | Base32-encoded TOTP secret |
| `VpnProfile` | string | — | Cisco group profile name |
| `VpnAddresses` | string[] | — | VPN gateway endpoints |
| `QuodDnsSuffixes` | string[] | — | DNS suffixes for network detection |
| `CiscoVpnCliPath` | string | Auto-detected | Path to `vpncli.exe` |
| `CiscoVpnUiPath` | string | Auto-detected | Path to `csc_ui.exe` |
| `LogDirectory` | string | `<script>\Logs` | Log output directory |
| `MaxLogSizeMB` | int | 5 | Log rotation threshold in MB |
| `VpnQueryTimeoutMs` | int | 10000 | Timeout for VPN profile query (1000-120000) |
| `VpnConnectTimeoutMs` | int | 25000 | Timeout for VPN handshake (1000-120000) |

## Security Architecture

### Credential Storage

Sensitive data (VPN password, OTP secret) is encrypted using the **Windows Data Protection API (DPAPI)** with `CurrentUser` scope. This means:

- Credentials can only be decrypted by the same Windows user on the same machine
- No master password or key file is needed — Windows handles the encryption key
- The encrypted file (`secure_settings.dat`) is useless if copied to another machine or user profile

### Credential Injection

During VPN connection, credentials are:

1. Decrypted from DPAPI into a `SecureString`
2. Converted to a `char[]` array (not an immutable .NET string)
3. Piped directly into the Cisco CLI via `StandardInput` — **never written to a temp file**
4. Explicitly zeroed with `[Array]::Clear()` immediately after use
5. BSTR pointers freed with `ZeroFreeBSTR()` to prevent memory disclosure

### OTP Generation

- Implements RFC 6238 (TOTP) with HMAC-SHA1
- 30-second time windows, 6-digit codes
- Secret stored as `SecureString`, decrypted only during code generation
- The OTP code is appended to the password and injected as a single credential payload

## Auto-Update

The script checks for updates on every launch by comparing Git blob SHA hashes with the GitHub repository.

- No manual version bumping required — any pushed commit triggers detection
- Shows the latest commit message and date before prompting to update
- Downloads are verified for integrity (minimum size and structural checks)
- File replacement uses an atomic batch-file mechanism to avoid lock issues
- Update check has a 5-second timeout to prevent startup delays on slow networks

## Connectivity Quality Test

Press **T** from the main menu to test latency to all configured VPN endpoints.

| Rating | ICMP Latency | TCP Latency |
|---|---|---|
| Excellent | ≤ 40 ms | ≤ 60 ms |
| Good | ≤ 80 ms | ≤ 120 ms |
| Poor | ≤ 150 ms | ≤ 200 ms |
| Bad | > 150 ms | > 200 ms |

- ICMP ping is preferred; TCP port 443 handshake is used as fallback when ICMP is blocked
- VPN addresses can include ports (`host:port` format) for TCP testing
- Quality is also checked automatically after connecting and cached for 15 seconds on the main menu

## Logging

- Logs are written to `<script directory>\Logs\VPNConnectionLog.txt`
- Format: `[YYYY-MM-DD HH:MM:SS] [LogType] - Message`
- Log types: `Information`, `Warning`, `Error`
- Automatic rotation when the log exceeds the configured max size (default 5 MB)
- Archived logs are named `VPNConnectionLog_YYYYMMDD-HHMMSS.txt`
- Recent warnings and errors (within 5 minutes) are displayed on the main menu

## Changelog

See the script header or `git log` for the full version history. Recent highlights:

| Version | Date | Changes |
|---|---|---|
| 5.30 | 2026-02-12 | Centralized config to `%LOCALAPPDATA%\QuodVPN` with automatic migration |
| 5.29 | 2026-02-12 | Git-native auto-update via SHA comparison; shows commit messages |
| 5.28 | 2026-02-12 | Forced update URL to public GitHub |
| 5.27 | 2026-02-12 | SecureString OTP, char[] credential injection, BSTR cleanup, async I/O |
| 5.26 | 2026-02-11 | Auto quality check on startup and after connection |
| 5.25 | 2026-02-09 | Update timeout, network stabilization delay, retry logic |

## License

Internal tool for Quod Financial. See repository for license details.
