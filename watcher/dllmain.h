// "dllmain.h" project's main header file
// this header file defines constants, types and functions prototypes

#ifndef _dllmain_h_
#define _dllmain_h_

// define constants
#define MAX_FILESIZE_BACKUP 102400 // max size of file for archiving
#define MAX_FILESIZE_ENTROPY 10240 // max size of file for entropy calculating
#define MAX_FILESIZE_INTEGRITY 1024000 // max size of file for integrity checking
#define BUFFER 1024 // size of buffer to read
#define PATH_LOG		L"C:\\Windows\\ransomware_analyzer\\log\\log_%d.dll"
#define PATH_LOGBAN		L"C:\\Windows\\ransomware_analyzer\\log\\log_ban.dll"
#define PATH_LOGMAIN	L"C:\\Windows\\ransomware_analyzer\\log\\log_main.dll"
#define MINIZ_HEADER_FILE_ONLY

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;

// HOOKED FUNCTIONS
BOOL	(WINAPI * TrueCreateProcessW) (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) = CreateProcessW;
HANDLE	(WINAPI * TrueCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
BOOL	(WINAPI * TrueCloseHandle) (HANDLE hObject) = CloseHandle;
BOOL	(WINAPI * TrueDeleteFileW) (LPCWSTR lpFileName) = DeleteFileW;
BOOL	(WINAPI * TrueDeleteFileTransactedW) (LPCWSTR lpFileName, HANDLE hTransaction) = DeleteFileTransactedW;
BOOL	(WINAPI * TrueDeleteFileA) (LPCSTR lpFileName) = DeleteFileA;
BOOL	(WINAPI * TrueDeleteFileTransactedA) (LPCSTR lpFileName, HANDLE hTransaction) = DeleteFileTransactedA;
BOOL	(WINAPI * TrueMoveFileW) (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) = MoveFileW;
BOOL	(WINAPI * TrueMoveFileExW) (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags) = MoveFileExW;
BOOL	(WINAPI * TrueWriteFile) (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = WriteFile;
BOOL	(WINAPI * TrueWriteFileEx) (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WriteFileEx;
BOOL	(WINAPI * TrueReadFile) (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = ReadFile;
BOOL	(WINAPI * TrueReadFileEx) (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = ReadFileEx;
HANDLE	(WINAPI * TrueCreateFileMappingW) (HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName) = CreateFileMappingW;
LPVOID	(WINAPI * TrueMapViewOfFile) (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile;
LPVOID	(WINAPI * TrueMapViewOfFileEx) (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) = MapViewOfFileEx;
#endif
