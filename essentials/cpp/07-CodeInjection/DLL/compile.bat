@ECHO OFF

cl.exe /O2 /D_USRDLL /D_WINDLL implant.cpp implant.def /MT /link /DLL /OUT:implant.dll
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcinjector.cpp /link /OUT:injector.exe /SUBSYSTEM:CONSOLE /MACHINE:x64