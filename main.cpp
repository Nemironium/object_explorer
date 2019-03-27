#include "Processinfo.hpp"
#include "File.hpp"

void PrintProcessInfo(std::list<Process> testList)
{
    size_t ctr = 0;
    for (auto &&i : testList) {
        std::wcout << ++ctr << L". Process name: " << i.getName() << std::endl;
        std::wcout << L"Process PID: " << i.getProcessPID() << std::endl;
        std::wcout << L"Process path: " << i.getPath() << std::endl;
        std::wcout << L"Process type: " << i.getProcessType() << std::endl; 
        std::wcout << L"Parent name: " << i.getParentName() << std::endl;
        std::wcout << L"Parent PID: " << i.getParentPID() << std::endl;
        std::wcout << L"Owner name: " << i.getOwnerName() << std::endl;
        std::wcout << L"Owner SID: " << i.getOwnerSID() << std::endl;
        std::wcout << L"Integrity level: " << i.getIntegrityLevel() << std::endl;
        std::wcout << L"DEP enabled: " << i.getDEP() << std::endl;
        std::wcout << L"ASLR enabled: " << i.getASLR() << std::endl;


        std::wcout << L"Dll list: " << std::endl;
        for (auto&& x : i.getDllList())
            std::wcout << "\t" << x << std:: endl;
        
        std::wcout << L"Privilege list: " << std::endl;
        for (auto const & [key, val] : i.getPrivilegeList())
            std::wcout << '\t' << key << " : " << val << std::endl;
       
        std::wcout << std::endl;
    }
}

void PrintFileInfo(std::wstring fileName)
{
    File file(fileName);
    std::wcout << file.getName() << std::endl;
    std::wcout << file.getPath() << std::endl;
    std::wcout << file.getOwnerName() << std::endl;
    std::wcout << file.getOwnerSID() << std::endl;
    std::wcout << file.getIntegrityLevel() << std::endl;

    /*std::wcout << file.setIntegrityLevel(L"Low") << std::endl;
    std::wcout << file.getIntegrityLevel() << std::endl;*/

   /*file.changeOwner(L"Administrator");
   std::wcout << file.getOwnerName() << std::endl;*/

    std::multimap<std::wstring, std::wstring> testAcl;
    for(auto const & [key, val] : file.getAclList())
        std::wcout << key << ':' << val << std::endl;
}


int main(int argc, char const *argv[])
{
    setlocale(LC_ALL, "Russian");
    std::list<Process> testList;
    if (GetProcesslist(testList)) 
        PrintProcessInfo(testList);
    system("pause");

    PrintFileInfo(L"C:\\Program Files");
    system("pause");

    return 0;
}
