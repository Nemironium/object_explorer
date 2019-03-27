#include "Processinfo.hpp"
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h>    // GetModuleFileNameEx
#include <sddl.h>     // ConvertSidToStringSid

bool Process::changePrivilege(std::wstring privilege, bool addFlag)
{
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilege.c_str(), &luid)) 
        return false;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hProcess)) {
            PTOKEN_PRIVILEGES pTokenPriv = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_PRIVILEGES));
            pTokenPriv->PrivilegeCount = 1;
            pTokenPriv->Privileges[0].Luid = luid;
            if (addFlag)
                pTokenPriv->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
                pTokenPriv->Privileges[0].Attributes = 0;
            if (AdjustTokenPrivileges(hProcess, FALSE, pTokenPriv, 0, NULL, NULL)) {
                HeapFree(GetProcessHeap(), 0, pTokenPriv);
                CloseHandle(hProcess);
                return true;
            }
            else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
                std::wcerr << "The token does not have the specified privilege. " << std::endl;
            else
                std::wcerr << "AdjustTokenPrivileges failed, code = " << GetLastError() << std::endl;
            HeapFree(GetProcessHeap(), 0, pTokenPriv);
        }
    }
    CloseHandle(hProcess);
    return false;
}

bool Process::setIntegrityLevel(std::wstring privilegeLevel)
{
    std::string sidLevel;
    if (privilegeLevel == L"Untrusted")
        sidLevel = "S-1-16-0";
    else if (privilegeLevel == L"Low")
        sidLevel = "S-1-16-4096";
    else if (privilegeLevel == L"Medium")
        sidLevel = "S-1-16-8192";
    else if (privilegeLevel == L"High")
        sidLevel = "S-1-16-12288";
    else {
        std::wcerr << L"Wrong integrity level. Avaible (Untrusted/Low/Medium/High)" << std::endl;
        return false;
        }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hProcess)) {
            DWORD dwSize = 0;
            if (GetTokenInformation(hProcess, TokenIntegrityLevel, NULL, 0, &dwSize) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                PTOKEN_MANDATORY_LABEL pTokenLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwSize);
                if (pTokenLevel != NULL) {
                    if (GetTokenInformation(hProcess, TokenIntegrityLevel, pTokenLevel, dwSize, &dwSize)) {
                        PSID pSID = NULL;
                        ZeroMemory(pTokenLevel, sizeof(pTokenLevel));
                        ConvertStringSidToSidA(sidLevel.c_str(), &pSID);
                        pTokenLevel->Label.Attributes = SE_GROUP_INTEGRITY;
                        pTokenLevel->Label.Sid = pSID;
                        SetTokenInformation(hProcess, TokenIntegrityLevel, pTokenLevel, dwSize);
                        CloseHandle(hProcess);
                        LocalFree(pTokenLevel);
                        return true;
                    }
                    LocalFree(pTokenLevel);
                } 
            }
        } 
    }
    CloseHandle(hProcess);
    return false;
}

bool Process::privilegeList()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcess)) {
            DWORD dwSize = 0;
            PTOKEN_PRIVILEGES pTokenPriv = NULL;
            if (GetTokenInformation(hProcess, TokenPrivileges, NULL, 0, &dwSize) 
                    || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                pTokenPriv = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                if (pTokenPriv != NULL) {
                    if (GetTokenInformation(hProcess, TokenPrivileges, pTokenPriv, dwSize, &dwSize)) {
                        for (size_t i = 0; i < pTokenPriv->PrivilegeCount; i++) {
                            DWORD dwSize_ = MAX_PATH;
                            WCHAR privBuf[MAX_PATH] = { 0 };
                            LookupPrivilegeNameW(NULL,  &pTokenPriv->Privileges[i].Luid, privBuf, &dwSize_);
                            if ((pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                                    == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                                this->privilegeList_.emplace(privBuf, L"Enabled by default");
                            else if ((pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                                    == SE_PRIVILEGE_ENABLED)
                                this->privilegeList_.emplace(privBuf, L"Enabled");
                            else if ((pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) 
                                    == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                                this->privilegeList_.emplace(privBuf, L"Enabled by default");
                            else if ((pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) 
                                    == SE_PRIVILEGE_USED_FOR_ACCESS)
                                this->privilegeList_.emplace(privBuf, L"Used for access");
                            else if ((pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) 
                                    == SE_PRIVILEGE_REMOVED)
                                this->privilegeList_.emplace(privBuf, L"Removed");
                            else
                                this->privilegeList_.emplace(privBuf, L"Disabled");
                        }
                        HeapFree(GetProcessHeap(), 0, pTokenPriv);
                        CloseHandle(hProcess);
                        return true; 
                    }
                    HeapFree(GetProcessHeap(), 0, pTokenPriv);
                }
            }
        }    
    }
    CloseHandle(hProcess);
    return false;
}

bool Process::integrityLevel()
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcess)) {
            DWORD dwSize = 0;
            if (GetTokenInformation(hProcess, TokenIntegrityLevel, NULL, 0, &dwSize) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                PTOKEN_MANDATORY_LABEL pTokenLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwSize);
                if (pTokenLevel != NULL) {
                    if (GetTokenInformation(hProcess, TokenIntegrityLevel, pTokenLevel, dwSize, &dwSize)) {
                        DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenLevel->Label.Sid,
                            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTokenLevel->Label.Sid) - 1));
                        if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
                            this->integrityLevel_ = L"Untrusted";
                        else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                            this->integrityLevel_ = L"Low";
                        else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
                            this->integrityLevel_ = L"Medium";
                        else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
                            this->integrityLevel_ = L"High";
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                            this->integrityLevel_ = L"System";

                        CloseHandle(hProcess);
                        LocalFree(pTokenLevel);
                        return true;
                    }
                    LocalFree(pTokenLevel);
                }
            }
        }
    }
    CloseHandle(hProcess);
    return false;
}

bool Process::dllList()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->processPID_);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    for (BOOL i = Module32First(hSnapshot, &moduleEntry); i; i = Module32Next(hSnapshot, &moduleEntry)) {
        std::wstring buf(&moduleEntry.szModule[0], &moduleEntry.szModule[strlen(moduleEntry.szModule)]);
        this->dllList_.push_back(buf);
        buf.clear();
    }
    CloseHandle(hSnapshot);
    return true;
}

bool Process::isASLR()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->processPID_);

    // Because of MinGW couldn't find this static library
    HMODULE lib=LoadLibraryA("Kernel32.dll");
    bool (*QtGetProcessMitigationPolicy)(HANDLE,PROCESS_MITIGATION_POLICY,PVOID,size_t) =
         (bool(*)(HANDLE,PROCESS_MITIGATION_POLICY,PVOID,size_t))GetProcAddress(lib,"GetProcessMitigationPolicy");
        
    if (hProcess != INVALID_HANDLE_VALUE) {
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = PROCESS_MITIGATION_ASLR_POLICY();
        if (QtGetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
            this->isASLR_ = L"On";
        else
            this->isASLR_ = L"Off";
        CloseHandle(hProcess);
        return true;
    }
    return false;   
}

bool Process::isDEP()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->processPID_);

    // Because of MinGW couldn't find this static library
    HMODULE lib=LoadLibraryA("Kernel32.dll");
    bool (*QtGetProcessMitigationPolicy)(HANDLE,PROCESS_MITIGATION_POLICY,PVOID,size_t) =
        (bool(*)(HANDLE,PROCESS_MITIGATION_POLICY,PVOID,size_t))GetProcAddress(lib,"GetProcessMitigationPolicy");

    if (hProcess != INVALID_HANDLE_VALUE) {
        PROCESS_MITIGATION_DEP_POLICY depPolicy = PROCESS_MITIGATION_DEP_POLICY();
        if (QtGetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
            this->isDEP_ = L"On";
        else
            this->isDEP_ = L"Off";
        CloseHandle(hProcess);
        return true;
    }
    return false;
}

bool Process::ownerNameSID()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        if (OpenProcessToken(hProcess, TOKEN_READ, &hProcess)) {
            DWORD dwSize = 0;
            PTOKEN_USER pTokenUser = NULL;
            if (GetTokenInformation(hProcess, TokenUser, (LPVOID)pTokenUser, 0, &dwSize) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                if (pTokenUser != NULL) {
                    if (GetTokenInformation(hProcess, TokenUser, (LPVOID)pTokenUser, dwSize, &dwSize)) {
                        SID_NAME_USE SidType;
                        wchar_t wName[MAX_PATH];
                        wchar_t wDomain[MAX_PATH];
                        LPWSTR pSID = NULL;
                        if (LookupAccountSidW(NULL, pTokenUser->User.Sid, wName, &dwSize, wDomain, &dwSize, &SidType)) {
                            if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSID)) {
                                this->ownerName_ = wName;
                                this->ownerSID_ = pSID;
                                CloseHandle(hProcess);
                                HeapFree(GetProcessHeap(), 0, (LPVOID)pTokenUser);
                                return true;
                            }
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, (LPVOID)pTokenUser);
                }
            }
        }
    }
    CloseHandle(hProcess);
    return false;
}

bool Process::path()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->processPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        wchar_t wBuf[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, wBuf, MAX_PATH)) {
            this->path_ = wBuf;
            CloseHandle(hProcess);
            return true;
        } 
    }
    return false;
}

bool Process::parentName()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->parentPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        wchar_t wBuf[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, wBuf, MAX_PATH)) {
            std::wstring temp(wBuf);
            this->parentName_ = temp.substr(temp.find_last_of(L"/\\") + 1);
            CloseHandle(hProcess);
            return true;
        }
    }
    return false;
}

bool Process::processType()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->parentPID_);
    if (hProcess != INVALID_HANDLE_VALUE) {
        BOOL isX64 = FALSE;
        if (IsWow64Process(hProcess, &isX64)) {
            this->processType_ = isX64 ? L"64-bit" : L"32-bit";
            CloseHandle(hProcess);
            return true;
        }
        CloseHandle(hProcess);
    }
    return false;
}

bool GetProcesslist(std::list<Process> &list)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE )
        return false;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    for (BOOL i = Process32First(hSnapshot, &processEntry); i; i = Process32Next(hSnapshot, &processEntry)) {
        std::wstring buf(&processEntry.szExeFile[0], &processEntry.szExeFile[strlen(processEntry.szExeFile)]);
        list.emplace_back(Process(buf, processEntry.th32ProcessID, processEntry.th32ParentProcessID));
    }
    CloseHandle(hSnapshot);
    return true;
}
