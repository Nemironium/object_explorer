# object_explorer
These code shows how to use Win API functions to get information about processes and files. Functionality similar to Process Hacker/Process Explorer programs. But much easy to understand code. Also you can get information about any file of file system.

Program was developed to MinGW gcc 7.3 version on Windows 10 1803

### compiling:
  g++ main.cpp File.cpp Processinfo.cpp -o test.exe -DPSAPI_VERSION=2 -std=gnu++1z
