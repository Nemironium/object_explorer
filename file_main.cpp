#include "File.hpp"

int main(int argc, char const *argv[])
{
    setlocale(LC_ALL, "Russian");
    File file(L"C:\\Program Files");
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

  

   system("pause");
}
