#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload [] = {
	0x90,
	0x90,
	0xcc,
	0xc3
};
	
unsigned int payload_len = 4;

int main(void) {
	void * exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
	
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