# chrome_v20_decryption_cpp

**chrome_v20_decryption_cpp** is a Chrome v20 decrypter written in C++. It can retrieve the following:

- Login Info (passwords)
- Cookies
- History
- Downloads
- Credit Cards

This program is not malicious in nature. It simply reads data, decrypts it if needed, and prints it to screen and saves to file.

**Note: Must Be Run as Administrator to decrypt Passwords, Cookies, or Credit Cards.**

## Features

- **Zero External Dependencies**: Uses only Windows built-in APIs (BCrypt, NCrypt, DPAPI)
- **SQLite Included**: sqlite3.c amalgamation included in project
- **Full v20 Support**: Supports all Chrome v20 encryption variants (v10, v20, v20.2)
- **Multiple Browsers**: Automatically detects and decrypts data from all installed Chromium browsers
- **File Output**: Saves all results to `chrome_decrypted_data.txt`

## Update

Updated for better Chromium browser support. Now supports browsers that use different v20 encryption variants.

Now supports the following browsers (in no particular order):

* Google Chrome (Stable, Beta, Dev, Canary)
* Microsoft Edge
* Brave
* Vivaldi
* Opera / Opera GX
* Chromium
* Arc

## Compiling

This is coded in C++ using Visual Studio 2026.

### Requirements:
- Windows 10 version 1703+ (for ChaCha20-Poly1305 support)
- Visual Studio 2019 or newer
- Windows SDK

### Build Steps:
1. Open `chrome-v20-decryption-cpp.sln` in Visual Studio
2. Select configuration (Debug/Release) and platform (x86/x64)
3. Build → Build Solution (Ctrl+Shift+B)

Or via command line:
```cmd
msbuild chrome-v20-decryption-cpp.sln /p:Configuration=Release /p:Platform=x64
```

### Project Structure:
```
CPP/
├── chrome-v20-decryption-cpp/
│   ├── chrome-v20-decryption-cpp.cpp  # Main source file
│   ├── chrome-v20-decryption-cpp.vcxproj  # Project file
│   └── sqlite/
│       ├── sqlite3.c  # SQLite amalgamation
│       └── sqlite3.h  # SQLite header
└── chrome-v20-decryption-cpp.slnx  # Solution file
```

## Usage

**IMPORTANT:** Must be run as Administrator!

```cmd
# Run as Administrator
chrome-v20-decryption-cpp.exe
```

The program will:
1. Check for Administrator privileges
2. Scan for all installed Chromium browsers
3. Decrypt master keys (v10, v20, or v20.2)
4. Extract and decrypt all data from all profiles
5. Display results to console
6. Save results to `chrome_decrypted_data.txt`

## Technical Details

### Encryption Support

**v10** - Legacy DPAPI encryption
- Used by: Chrome Canary, older Edge, Opera, Vivaldi

**v20** - App-Bound encryption with lsass impersonation
- Used by: Chrome Stable/Beta/Dev (newer versions)
- Requires: lsass impersonation for LocalMachine DPAPI

**v20.2** - Simplified v20
- Used by: Microsoft Edge, Brave (newer versions)

### Cryptography

All cryptographic operations use Windows built-in APIs:

- **AES-GCM (256-bit)**: BCrypt API
- **ChaCha20-Poly1305**: BCrypt API (Windows 10 1703+)
- **DPAPI**: CryptUnprotectData
- **Windows CNG**: NCrypt API for key decryption

### Process

1. Read `Local State` file → extract encrypted_key or app_bound_encrypted_key
2. DPAPI decryption (LocalMachine scope via lsass impersonation)
3. DPAPI decryption (CurrentUser scope)
4. Parse KeyBlob structure (flag 1, 2, or 3)
5. Derive master key using AES-GCM or ChaCha20-Poly1305
6. Read SQLite databases (Login Data, Cookies, History, etc.)
7. Decrypt data using master key

## Output

Results are displayed in console and saved to `chrome_decrypted_data.txt` in the current directory.

Example output format:
```
=== Chrome v20 Decryption Results ===
Generated: [timestamp]

--- Login Data (X total) ---

URL: https://example.com
Username: user@example.com
Password: password123

--- Cookie Data (X total) ---

Host: .example.com
Name: session_id
Path: /
Value: abc123xyz
Expires: 1234567890

[...]
```

## Credits

I want to give credit to the following for playing their part in this code being created:

* [https://github.com/dev-196/ABCVV123](https://github.com/dev-196/ABCVV123) for C# version which this is ported from

## Comparison with C# Version

| Feature | C++ | C# |
|---------|-----|-----|
| External Dependencies | None | BouncyCastle |
| Executable Size | ~200KB | ~2MB |
| Performance | Faster | Slower |
| Command Line Args | No | Yes |
| File Output | Yes | Yes |
| Browser Support | 10+ | 12+ |

## Security & Legal

⚠️ **IMPORTANT:**

- This tool is for educational and security research purposes only
- Only use on systems you own or have explicit permission to test
- Requires Administrator privileges
- Works only with current user's data
- Does not bypass Windows security

## Troubleshooting

**"Not running as Administrator"**
- Right-click executable → Run as Administrator

**"Failed to impersonate lsass"**
- Ensure you have Administrator privileges
- Check that lsass.exe process is running

**"No logins found"**
- Close Chrome before running
- Verify you have saved passwords in Chrome
- Try saving a test password in Chrome

**"BCryptDecrypt failed"**
- Update Windows to version 1703 or later
- Some browsers may use different encryption

## Other

Currently the compiled executable may be detected as a virus by Windows Defender, because similar code patterns have been used in password stealing malware.

This is a false positive - the code is open source and does not contain any malicious functionality.

I am posting code only. No executable, to avoid false virus detections.

## License

Use responsibly and only for legal purposes.

Based on code from:
- C# version: chrome_v20_decryption_CSharp by dev-196
