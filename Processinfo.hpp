#pragma once

#include <iostream>
#include <windows.h>
#include <list>
#include <string>
#include <map>

class Process;
typedef BOOL(APIENTRY *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
bool GetProcesslist(std::list<Process> &);
bool AdjustTokenIntegrityLevel(HANDLE, const char *);

class Process
{
  public:
    Process() = default;
    Process(std::wstring name, DWORD processPID, DWORD parentPID)
      : name_(name)
      , processPID_(processPID)
      , parentPID_(parentPID)
    { init(); }
    ~Process() {}
    Process(Process &&) = default;
    Process(const Process &) = default;
    Process &operator=(Process &&) = default;
    Process &operator=(const Process &) = default;

    /*#########GETTERS#########*/
    const std::wstring & getName() const { return name_; }
    const std::wstring & getPath() const { return path_; }
    const std::wstring & getParentName() const { return parentName_; }
    const std::wstring & getOwnerName() const { return ownerName_; }
    const std::wstring & getOwnerSID() const { return ownerSID_; }
    const std::wstring & getProcessType() const { return processType_; }
    const std::wstring & getIntegrityLevel() const { return integrityLevel_; }
    const std::list<std::wstring> & getDllList() const { return dllList_; }
    const std::map<std::wstring, std::wstring> & getPrivilegeList() const { return privilegeList_; }
    const DWORD & getProcessPID() const { return processPID_; }
    const DWORD & getParentPID() const { return parentPID_; }
    const std::wstring & getDEP() const { return isDEP_; }
    const std::wstring & getASLR() const { return isASLR_; }

    /*#########ADJUST#########*/
    bool setIntegrityLevel(std::wstring);
    bool changePrivilege(std::wstring, bool);

  private:
    std::wstring name_ = L"";
    std::wstring path_ = L"";
    std::wstring parentName_ = L"";
    std::wstring ownerName_ = L"";
    std::wstring ownerSID_ = L"";
    std::wstring processType_ = L"";
    std::wstring integrityLevel_ = L"Unknown";
    std::wstring isDEP_ = L"";
    std::wstring isASLR_ = L"";
    
    DWORD processPID_ = 0;
    DWORD parentPID_ = 0;
  
    std::list<std::wstring> dllList_;
    std::map<std::wstring, std::wstring> privilegeList_;

    /*#########FUNCTIONALITY#########*/
    bool path();
    bool processType();
    bool parentName();
    bool ownerNameSID();
    bool isDEP();
    bool isASLR();
    bool dllList();
    bool privilegeList();
    bool integrityLevel();

    void init()
    {
        path();
        processType();
        parentName();
        ownerNameSID();
        isDEP();
        isASLR();
        dllList();
        privilegeList();
        integrityLevel();
    }
};
