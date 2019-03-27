#include "File.hpp"

#include <sddl.h>     // ConvertSidToStringSid
#include <aclapi.h>   // GetNamedSecurityInfo
#include <Lm.h>       // NetUserEnum


void File::name()
{
    this->name_ = this->path_.substr(this->path_.find_last_of(L"/\\") + 1);
}

bool File::owner()
{
    PSID pOwnerSid = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (GetNamedSecurityInfoW(this->path_.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, 
        &pOwnerSid, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS) {
        if (pSD != NULL) {
            wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
            DWORD dwLen = MAX_PATH;
            SID_NAME_USE sidNameUse;
            if (LookupAccountSidW(NULL, pOwnerSid, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse)) {
                LPWSTR stringSid = NULL;
                ConvertSidToStringSidW(pOwnerSid, &stringSid);
                this->ownerName_ = wUser;
                this->ownerSID_ = stringSid;
                return true;
            }       
        }   
    }
    return false;
}

bool File::integrityLevel()
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pAcl = NULL;
    DWORD dwIntegrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    if (GetNamedSecurityInfoW(this->path_.c_str(), SE_FILE_OBJECT, 
        LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pAcl, &pSD) == ERROR_SUCCESS) {
        if (pAcl != 0 && pAcl->AceCount > 0) {
            SYSTEM_MANDATORY_LABEL_ACE *ace;
            if (GetAce(pAcl, 0, reinterpret_cast<void **>(&ace))) {
                SID *pSid = reinterpret_cast<SID *>(&ace->SidStart);
                dwIntegrityLevel = pSid->SubAuthority[0];
            }
        }
        PWSTR stringSD;
        ULONG stringSDLen = 0;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);
        if (pSD)
            LocalFree(pSD); 
    }
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
    return true;
}

bool File::setIntegrityLevel(std::wstring integrityLvl)
{
    LPCWSTR INTEGRITY_SDDL_SACL_W = NULL;
    if (integrityLvl == L"Untrusted")
        INTEGRITY_SDDL_SACL_W = L"";
    else if (integrityLvl == L"Low")
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
    else if (integrityLvl == L"Medium")
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
    else if (integrityLvl == L"High")
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";

    DWORD dwErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pSacl = NULL;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL)) {
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted)) {
            wchar_t *temp = const_cast<wchar_t *>(this->path_.c_str());
            dwErr = SetNamedSecurityInfoW((LPWSTR)temp, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                    NULL, NULL, NULL, pSacl);
            if (dwErr == ERROR_SUCCESS) {
                this->integrityLevel_ = integrityLvl;
                LocalFree(pSD);
                return true;
            } 
        }
        LocalFree(pSD);
    }
    return false;
}

bool File::aclList()
{
    PACL pDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    
    if (GetNamedSecurityInfoW(this->path_.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 
        NULL, NULL, &pDACL, NULL, &pSD) == ERROR_SUCCESS) {
        if (pDACL != NULL) {
            ACL_SIZE_INFORMATION aclInfo;
            if (GetAclInformation(pDACL, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
                for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                    void *ace;
                    if (GetAce(pDACL, i, &ace)) {
                        PSID *pSID = (PSID *)&((ACCESS_ALLOWED_ACE *)ace)->SidStart;
                        wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
                        SID_NAME_USE sidNameUse;
                        DWORD dwLen = MAX_PATH;
                        if (LookupAccountSidW(NULL, pSID, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse)) {
                            LPWSTR stringSid = NULL;
                            ConvertSidToStringSidW(pSID, &stringSid);

                            if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
                               this->aclList_.emplace(wUser, L"Allowed ACE");
                            if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
                                this->aclList_.emplace(wUser, L"Denied ACE");
                            if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
                                this->aclList_.emplace(wUser, L"System Alarm ACE");
                            if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
                                this->aclList_.emplace(wUser, L"System Audit ACE");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & WRITE_OWNER) == WRITE_OWNER)
                                this->aclList_.emplace(wUser, L"Change Owner");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & WRITE_DAC) == WRITE_DAC)
                                this->aclList_.emplace(wUser, L"Write DAC");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & DELETE) == DELETE)
                                this->aclList_.emplace(wUser, L"Delete");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
                                this->aclList_.emplace(wUser, L"Read");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
                                this->aclList_.emplace(wUser, L"Write");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
                                this->aclList_.emplace(wUser, L"Execute");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & SYNCHRONIZE) == SYNCHRONIZE)
                                this->aclList_.emplace(wUser, L"Synchronize");
                            if ((((ACCESS_ALLOWED_ACE *)ace)->Mask & READ_CONTROL) == READ_CONTROL)
                                this->aclList_.emplace(wUser, L"Read control");
                        }
                    }
                }
            }
        }
    }
    return true;
}

PSID NameSid(std::wstring ownerName)
{
    SID_NAME_USE sidNameUse;
    DWORD dwSizeDomain = 0;
    DWORD dwSizeSid = 0;
    PSID pSid = NULL;
    wchar_t  wDomain[MAX_PATH];

    if (!LookupAccountNameW(NULL, ownerName.c_str(), NULL, &dwSizeSid, NULL, &dwSizeDomain, 
            &sidNameUse) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        pSid = (PSID)LocalAlloc(0, dwSizeSid);
    if (!LookupAccountNameW(NULL, ownerName.c_str(), pSid, &dwSizeSid, wDomain, &dwSizeDomain, 
            &sidNameUse)) 
        std::wcerr << L"LookupAccountNameW2 failed, code = " << GetLastError() << std::endl;
    return pSid;
}

bool SetOwnershipPrivileges(HANDLE hCurrentprocess)
{
    HANDLE hToken = NULL;
    PTOKEN_PRIVILEGES pTokenPriv = (PTOKEN_PRIVILEGES)malloc(offsetof(TOKEN_PRIVILEGES, Privileges) + 2 * sizeof(LUID_AND_ATTRIBUTES));
    if (pTokenPriv != NULL) {
        pTokenPriv->PrivilegeCount = 2;
        pTokenPriv->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        pTokenPriv->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeTakeOwnershipPrivilege", &pTokenPriv->Privileges[0].Luid)) {
            if (LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &pTokenPriv->Privileges[1].Luid)) {
                if (OpenProcessToken(hCurrentprocess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                    if (AdjustTokenPrivileges(hToken, FALSE, pTokenPriv, 0, NULL, NULL)) 
                        return true;
                }
            }      
        }       
    }
    return false;
}

bool File::changeOwner(std::wstring ownerName)
{
    PSID pOwnerSid = NameSid(ownerName);
    if (pOwnerSid == NULL) {
        return false;
    }

    if (!SetOwnershipPrivileges(GetCurrentProcess())) {
        LocalFree(pOwnerSid);
        return false;
    }

    wchar_t * temp = const_cast<wchar_t *>(this->path_.c_str());
    if (SetNamedSecurityInfoW(temp, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            pOwnerSid, NULL, NULL, NULL) == ERROR_SUCCESS) {
        this->ownerName_ = ownerName;
        LocalFree(pOwnerSid);
        return true;
    }
    LocalFree(pOwnerSid);
    return false;
}

bool File::userList()
{
    LPUSER_INFO_3 pBuf = NULL, pTmpBuf;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0, dwTotalCount = 0, i;
    NET_API_STATUS nStatus;
    
    // Because of MinGW couldn't find this static library
    HMODULE lib=LoadLibraryA("netapi32.dll");
    NET_API_STATUS (*QtNetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD)=
            (NET_API_STATUS(*)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD))GetProcAddress(lib,"NetUserEnum");
    do
    {
        nStatus = QtNetUserEnum(NULL, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&pBuf,
            MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                for (i = 0; i < dwEntriesRead; i++)
                {
                    std::wstring temp(pTmpBuf->usri3_name);
                    this->userList_.emplace_back(temp);
                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }

        if (pBuf != NULL)
        {
            DWORD (*QtNetApiBufferFree)(LPVOID)=(DWORD(*)(LPVOID))GetProcAddress(lib,"NetApiBufferFree");
            QtNetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);
    return true;
}
