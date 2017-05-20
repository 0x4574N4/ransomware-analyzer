// "dllmain.h" project's main header file
// this header file defines constants, types and functions prototypes

#ifndef _dllmain_h_
#define _dllmain_h_
// include header files
#include <math.h>
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#pragma comment (lib,"psapi.lib")
#include <Shlwapi.h>
#pragma comment (lib,"shlwapi.lib")
#include "C:\Program Files (x86)\Microsoft Research\Detours Express 3.0\include\detours.h"
#pragma comment (lib, "C:\\Program Files (x86)\\Microsoft Research\\Detours Express 3.0\\lib.X86\\detours.lib")

// define constants
#define MAX_FILESIZE_BACKUP 102400 // max size of file for archiving
#define MAX_FILESIZE_ENTROPY 10240 // max size of file for entropy calculating
#define MAX_FILESIZE_INTEGRITY 1024000 // max size of file for integrity checking
#define BUFFER 1024 // size of buffer to read
#define PATH_LOG L"C:\\Windows\\ransomware_analyzer\\log\\log_%d.dll"
#define PATH_DUMP L"C:\\Windows\\ransomware_analyzer\\dump\\dump_%d_%d.dll"
#define MINIZ_HEADER_FILE_ONLY

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;

// GLOBAL VARS
DWORD dwDumpNum = 0;

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
BOOL	(WINAPI * TrueCryptGenKey) (HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey) = CryptGenKey;
BOOL	(WINAPI * TrueCryptGenRandom) (HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) = CryptGenRandom;
BOOL	(WINAPI * TrueCryptDeriveKey) (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY  *phKey) = CryptDeriveKey;
BOOL	(WINAPI * TrueCryptDuplicateKey) (HCRYPTKEY hKey, DWORD *pdwReserved, DWORD dwFlags, HCRYPTKEY *phKey) = CryptDuplicateKey;
BOOL	(WINAPI * TrueCryptExportKey) (HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) = CryptExportKey;
BOOL	(WINAPI * TrueCryptImportKey) (HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey) = CryptImportKey;
BOOL	(WINAPI * TrueCryptDestroyKey) (HCRYPTKEY hKey) = CryptDestroyKey;
BOOL	(WINAPI * TrueCryptEncrypt) (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) = CryptEncrypt;
BOOL	(WINAPI * TrueCryptDecrypt) (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) = CryptDecrypt;
BOOL	(WINAPI * TrueCryptCreateHash) (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) = CryptCreateHash;
BOOL	(WINAPI * TrueCryptHashData) (HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) = CryptHashData;
BOOL	(WINAPI * TrueCryptDestroyHash) (HCRYPTHASH hHash) = CryptDestroyHash;
#endif
