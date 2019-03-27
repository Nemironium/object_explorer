#pragma once

#include <string>
#include <list>
#include <map>
#include <iostream>
#include <windows.h>

class File
{
  public:
    File() = default;
    File(std::wstring path)
        : path_(path)
    { init(); }
    ~File() {}
    File(File &&) = default;
    File(const File &) = default;
    File &operator=(File &&) = default;
    File &operator=(const File &) = default;

    /*#########GETTERS#########*/
    const std::wstring & getName() const { return name_; }
    const std::wstring & getPath() const { return path_; }
    const std::wstring & getOwnerName() const { return ownerName_; }
    const std::wstring & getOwnerSID() const { return ownerSID_; }
    const std::wstring & getIntegrityLevel() const { return integrityLevel_; }
    const std::multimap<std::wstring, std::wstring> & getAclList() const { return aclList_; }
    const std::list<std::wstring> & getUserList() const { return userList_; }
    
    /*#########ADJUST#########*/
    bool changeOwner(std::wstring);
    bool setIntegrityLevel(std::wstring);

  private:
    std::wstring name_ = L"";
    std::wstring path_ = L"";
    std::wstring ownerName_ = L"";
    std::wstring ownerSID_ = L"";
    std::wstring integrityLevel_ = L"Unknown";
    std::multimap<std::wstring, std::wstring> aclList_;
    std::list<std::wstring> userList_;

    /*#########FUNCTIONALITY#########*/
    void name();
    bool owner();
    bool integrityLevel();
    bool aclList();
    bool userList();

    void init()
    {
        name();
        owner();
        integrityLevel();
        aclList();
        userList();
    }
};
