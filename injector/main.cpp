// "main.cpp" project's main file
// this tool tries to get debug privileges and inject "watcher.dll" library into each one

#include <Windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <time.h>

// this function tries do get SE_DEBUG_NAME privileges
// and returns boolean value as result of it
BOOL getPrivileges() {
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tkp, tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	// try to open thread token
	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) {
				return FALSE;
			}
			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				return FALSE;
			}
		}
		else {
			return FALSE;
		}
	}

	// try to enable SeDebugPrivilege
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		wprintf(L"\nTRYING TO GET SE_DEBUG_NAME : ");

		// first pass. get current privilege setting
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
		
		// second pass. set privilege based on previous setting
		tpPrevious.PrivilegeCount			= 1;
		tpPrevious.Privileges[0].Luid		= luid;
		tpPrevious.Privileges[0].Attributes	|= (SE_PRIVILEGE_ENABLED);

		// set privileges if successed
		if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL)) {
			return TRUE;
		}
	}

	// if we here - we're failed
	return FALSE;
}

int main(void) {
	PROCESSENTRY32 PE32; // info about process
	HANDLE hTool32; // processes state
	HANDLE hProcess;
	HANDLE hThread;
	DWORD Injected[10000]; // array, that contains list of already injected processes
	DWORD dwInjected; // current size of list of already injected processes
	DWORD dwSize = 0;
	DWORD dwExitCode = 0;
	WCHAR wszTime[100] = {0};
	WCHAR LibPath [] = L"C:\\Windows\\ransomware_analyzer\\watcher.dll"; // path to injecting lib
	LPVOID LoadLibraryAddr;
	LPVOID LLParam;
	BOOL flag; // flag
	struct tm stTime;
	time_t Time;

	// try to get additional privileges
	if (getPrivileges()) {
		wprintf(L"OK!\n\n");
	}
	else {
		wprintf(L"FAILED :(\n\n");
	}

	// infinite cycle for injecting
	dwInjected = 0;
	wprintf(L"CURRENT PROCESSES - INJECTING\n");
	while (true) {
		hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); // get current list of processes
		PE32.dwSize = sizeof(PROCESSENTRY32); // set size of structure
		if(Process32First(hTool32, &PE32)) {
			// if all ok, just list all processes of snapshot
			while(Process32Next(hTool32, &PE32)) {
				// check this process at list of already injected processes
				flag = FALSE;
				for (DWORD i = 0; i < dwInjected; i++) {
					if (Injected[i] == PE32.th32ProcessID)	{
						flag = TRUE; // if current process is at list of injected
						break;
					}
				}
				if (flag == TRUE) continue;

				// inject our dll
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PE32.th32ProcessID);
				LoadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
				LLParam = VirtualAllocEx(hProcess, NULL, sizeof(LibPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				WriteProcessMemory(hProcess, LLParam, LibPath, sizeof(LibPath), NULL);
				hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, LLParam, NULL, NULL);

				// check for success
				dwExitCode = 0;
				WaitForSingleObject(hThread, 100);
				GetExitCodeThread(hThread, &dwExitCode);

				// closeall handles
				CloseHandle(hThread);
				CloseHandle(hProcess);

				// generate time string
				Time = time(NULL);
				localtime_s(&stTime, &Time);
				swprintf_s(wszTime, L"%04d.%02d.%02d %02d:%02d:%02d", stTime.tm_year + 1900, stTime.tm_mon + 1, stTime.tm_mday, stTime.tm_hour, stTime.tm_min, stTime.tm_sec);

				// if dll is injected, add current process to list of already injected process and write string to console 
				if (dwExitCode != 0) {
					Injected[dwInjected] = PE32.th32ProcessID;
					dwInjected++;
					wprintf(L"%ls : PID = %d (%ls) - INJECT : OK!\n", wszTime, PE32.th32ProcessID, PE32.szExeFile);
				}
			}
		}
		CloseHandle(hTool32); // close list of processes

		// do delay
		Sleep(100);
	}

	// return to OS
	return 0;
}
