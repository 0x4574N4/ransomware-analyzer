// "dllmain.cpp" project's main file
// this file contains description of all interception functions and secondary functions

// include header files
#include <math.h>
#include <stdio.h>
#include <Windows.h>
#include <Shlwapi.h>
#pragma comment (lib,"shlwapi.lib")
#include "C:\Program Files (x86)\Microsoft Research\Detours Express 3.0\include\detours.h"
#pragma comment (lib, "C:\\Program Files (x86)\\Microsoft Research\\Detours Express 3.0\\lib.X86\\detours.lib")
#include "dllmain.h" // main header file
#include "miniz.c"   // mini ZIP-library

// write input string szMsg into log file
void logMessage(WCHAR* szMsg) {
	HANDLE hLog = NULL;
	DWORD dwSize = 0;
	DWORD dwCount = 0;
	WCHAR szLog[1000] = {0};

	if (szMsg != NULL) {
		// generate filename
		swprintf(szLog, PATH_LOG, GetCurrentProcessId());

		// open log file
		hLog = TrueCreateFileW(szLog, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLog != INVALID_HANDLE_VALUE) {
			// write to end of file
			SetFilePointer(hLog, 0, NULL, FILE_END);

			// write string
			dwSize = (wcslen(szMsg)+1)*sizeof(WCHAR);
			TrueWriteFile(hLog, (BYTE *) szMsg, dwSize, &dwCount, NULL);
		}		
		TrueCloseHandle(hLog); // close log file
	}
}

// check if file has protected extension
BOOL checkFileExtension(LPCWSTR lpFileName) {
	// list of protected extensions
	WCHAR *szExtension = PathFindExtensionW(lpFileName);
	WCHAR aszProtected[13][6] = {L".docx", L".doc", L".pptx", L".ppt", L".xslx", L".xsl", L".pdf", L".rtf", L".jpg", L".jpeg", L".png", L".zip", L".rar"};

	// if length of extension greater than zero
	if (wcslen(szExtension) > 0) {
		// run on list of protected extensions
		for (DWORD i = 0; i < sizeof(aszProtected); i++) {
			if (_wcsicmp(szExtension, &aszProtected[i][0])==0) {
				return TRUE; // if extension found at list, then return TRUE
			}
		}
	}

	// otherwise return FALSE
	return FALSE;
}

// check if file has extension of ZIP-format
BOOL checkZipFileExtension(LPCWSTR lpFileName) {
	// list of protected extensions
	WCHAR *szExtension = PathFindExtensionW(lpFileName);
	WCHAR aszProtected[4][6] = {L".docx", L".pptx", L".xslx", L".zip"};

	// if length of extension greater than zero
	if (wcslen(szExtension) > 0) {
		// run on list of protected extensions
		for (DWORD i = 0; i < sizeof(aszProtected); i++) {
			if (_wcsicmp(szExtension, &aszProtected[i][0])==0) {
				return TRUE; // if extension found at list, then return TRUE
			}
		}
	}

	// otherwise return FALSE
	return FALSE;
}

// check if drive has protected devicename
BOOL checkDrive (LPCWSTR lpDriveName) {
	VOLUME_DISK_EXTENTS diskExtents;
	HANDLE hDrive = NULL;
	DWORD Drives = GetLogicalDrives(); // get drives
	DWORD dwSize;
	WCHAR szDrive[MAX_PATH+1];

	// fast check
	if (StrStrIW(lpDriveName, L"\\\\.\\") == NULL) {
		return FALSE;
	}

	// run throw all drives [A-Z]
	for (DWORD ci = 0; ci < 26; ci++) {
		swprintf(szDrive, L"%c:\\", 'A'+ci); // convert bit to letter
		if (((Drives >> ci) & 0x1) == 0x1) {
			// we need for only HDDs
			if (GetDriveType(szDrive) == DRIVE_FIXED) {
				// check if we can access it
				swprintf(szDrive, L"\\\\.\\%c:", 'A'+ci);

				// compare szDrive (example "\\.\C:") with input value lpDriveName
				if (_wcsicmp(szDrive, lpDriveName) == 0) {
					return TRUE; // return TRUE if equal
				}

				// get access to drive
				hDrive = TrueCreateFileW(szDrive,  GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
				if (hDrive != INVALID_HANDLE_VALUE) {
					// drive is ok, main work from here
					if (DeviceIoControl(hDrive, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, (LPVOID) &diskExtents, (DWORD) sizeof(diskExtents), (LPDWORD) &dwSize, NULL)) {
						// get number of the phisical drive
						for (DWORD cj = 0; cj < diskExtents.NumberOfDiskExtents; cj++) {
							// add drive name to list
							swprintf(szDrive, L"\\\\.\\PhysicalDrive%d", diskExtents.Extents[cj].DiskNumber);

							// compare szDrive (example "\\.\C:") with input value lpDriveName
							if (_wcsicmp(szDrive, lpDriveName) == 0) {
								return TRUE; // return TRUE if equal
							}
						}
					}
				}
				TrueCloseHandle(hDrive);
			}
		}
	}

	// otherwise return FALSE
	return FALSE;
}

// check if zip archive is correct
BOOL checkZipIntegrity (LPCWSTR lpFileName) {
	HANDLE hFile = NULL;
	HANDLE hMap  = NULL;
	LPVOID lpView = NULL;
	DWORD dwSize = 0;    // size of file
	BYTE *pbRead = NULL; // memory buffer
	int ci;
	void *p;
	size_t uncomp_size;
	mz_bool status;
	mz_zip_archive zip_archive;

	// open and read file
	hFile = TrueCreateFileW(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// get size of file
	dwSize = GetFileSize(hFile, NULL);
	if ((dwSize == INVALID_FILE_SIZE) || (dwSize < 4)) {
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// MAX file size of integrity check
	if (dwSize > MAX_FILESIZE_INTEGRITY) {
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// create mapping
	hMap = TrueCreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL) {
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// create view of file
	lpView = TrueMapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
	if (hMap == NULL) {
		TrueCloseHandle(hMap);
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// open the archive.
	memset(&zip_archive, 0, sizeof(zip_archive));
	status = mz_zip_reader_init_mem(&zip_archive, lpView, dwSize, 0);
	if (!status) {
		return FALSE;
	}

	for (ci = 0; ci < (int)mz_zip_reader_get_num_files(&zip_archive); ci++) {
		// get information about each file in the archive
		mz_zip_archive_file_stat file_stat;
		if (!mz_zip_reader_file_stat(&zip_archive, ci, &file_stat))
		{
			mz_zip_reader_end(&zip_archive);
			return FALSE;
		}

		// try to extract this file
		p = mz_zip_reader_extract_file_to_heap(&zip_archive, file_stat.m_filename, &uncomp_size, 0);
		if (!p)
		{
			mz_zip_reader_end(&zip_archive);
			return FALSE;
		}
		
		// we're done.
		mz_free(p);
	}

	// close the archive, freeing any resources it was using
	mz_zip_reader_end(&zip_archive);

	// close all handles
	UnmapViewOfFile(lpView);
	TrueCloseHandle(hMap);
	TrueCloseHandle(hFile);

	// return result
	return TRUE;
}

// get main file info, result: TRUE - success, FALSE - fail
// _in_ lpFileName = filename
// _out_ abSignature[4] = signature
// _out_ dblEntropy = shannon's entropy
// 1 - get signature
// 2 - count Entropy
BOOL getFileInfo(LPCWSTR lpFileName, BYTE abSignature[4], double *lpEntropy) {
	HANDLE hFile = NULL;
	DWORD dwPos = 0;   // file pointer
	DWORD dwSize = 0;  // size of file
	DWORD dwCount = 0; // counter of readen bytes
	DWORD dwRatio = 0; // ratio [size of file]/[size of block to be read]
	DWORD aBytes[256] = {0}; // array of bytes for calculating of probability
	BYTE *pbRead = NULL; //
	double H, P; // Shannon's entropy

	// open and read file
	hFile = TrueCreateFileW(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// get size of file
	dwSize = GetFileSize(hFile, NULL);
	if ((dwSize == INVALID_FILE_SIZE) || (dwSize < 4)) {
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// allocate memory
	pbRead = (BYTE *) malloc(BUFFER);
	if (pbRead == NULL) {
		TrueCloseHandle(hFile);
		return FALSE;
	}

	// read signature
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!TrueReadFile(hFile, pbRead, 4, &dwCount, NULL)) {
		TrueCloseHandle(hFile);
		free(pbRead);
		return FALSE;
	}

	// copy first 4 bytes to abSignature
	for (DWORD ci = 0; ci < 4; ci++) {
		abSignature[ci] = pbRead[ci];
	}

	// set ratio
	dwRatio = dwSize / (MAX_FILESIZE_ENTROPY);

	// main work
	dwSize = 0;
	dwPos = SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	while (TRUE) {
		// read 1 KB from file
		if (!TrueReadFile(hFile, pbRead, BUFFER, &dwCount, NULL)) {
			TrueCloseHandle(hFile);
			free(pbRead);
			return FALSE;
		}
		dwSize += dwCount;

		// check number of bytes read
		if (dwCount == 0) {
			break;
		}

		// count number of repetitions
		for (DWORD ci = 0; ci < dwCount; ci++) {
			aBytes[pbRead[ci]]++;
		}

		// skip [1024*ratio] bytes
		for (DWORD ci = 0; ci < dwRatio; ci++) {
			dwPos = SetFilePointer(hFile, BUFFER, NULL, FILE_CURRENT);
		}
	}

	// count entropy
	H = 0; P = 0;
	for (DWORD i = 0; i < 0x100; i++) {
		P = (double) aBytes[i] / dwSize;
		if (P>0) H = H + P * log(P) / log (2.0);
	}
	*lpEntropy = -H;

	// free memory and close file
	free(pbRead);
	TrueCloseHandle(hFile);

	return TRUE;
}

// this hooking function looks for suspicious strings in command line,
// like "vssadmin", "shadowcopy", "IVssBackupComponents"
// todo: add strings
__declspec(dllexport) BOOL WINAPI MyCreateProcessW (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueCreateProcessW (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	// find suspicious substrings
	if ((StrStrIW(lpApplicationName, L"vssadmin") != NULL) || (StrStrIW(lpCommandLine, L"vssadmin") != NULL) || (StrStrIW(lpApplicationName, L"shadowcopy") != NULL) || (StrStrIW(lpCommandLine, L"shadowcopy") != NULL)) {
		// create message for log
		swprintf(szMsg, L"CreateProcess (ApplicationName = \"%ls\", CommandLine = \"%ls\") = %s", lpApplicationName, lpCommandLine, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for CreateFileW
__declspec(dllexport) HANDLE WINAPI MyCreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	HANDLE hResult;
	WCHAR szMsg[1000];
	BYTE abSignature[4];
	BOOL bIntegrity;
	double dblEntropy;

	// if process trying to access to file with protected extension or to protected drive
	if (checkFileExtension(lpFileName)) {
		// get main file info
		getFileInfo(lpFileName, abSignature, &dblEntropy);

		// check integrity of file
		if (checkZipFileExtension(lpFileName)) {
			bIntegrity = checkZipIntegrity(lpFileName);
		}
		else {
			bIntegrity = FALSE;
		}

		// get result of true function
		hResult = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		// create message for log
		swprintf(szMsg, L"CreateFile (FileName = \"%ls\", DesiredAccess = %d) = %p; Signature = %02x %02x %02x %02x; Entropy = %fl; Integrity = %s",
			lpFileName, dwDesiredAccess, hResult, abSignature[0], abSignature[1], abSignature[2], abSignature[3], dblEntropy, bIntegrity ? "TRUE" : "FALSE");
	}
	else if (checkDrive(lpFileName)) {
		// get result of true function
		hResult = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		// create message for log
		swprintf(szMsg, L"CreateFile (FileName = \"%ls\", DesiredAccess = %d) = %p", lpFileName, dwDesiredAccess, hResult);
	}

	// return result of true function
	return hResult;
}

// this hooking function for CloseHandle
__declspec(dllexport) BOOL WINAPI MyCloseHandle (HANDLE hObject)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	BYTE abSignature[4];
	BOOL bIntegrity;
	double dblEntropy;

	// get result of true function
	BOOL bResult = TrueCloseHandle(hObject);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hObject, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension or to protected drive
	if (checkFileExtension(szPath)) {
		// get main file info
		getFileInfo(szPath, abSignature, &dblEntropy);

		// check integrity of file
		bIntegrity = checkZipIntegrity(szPath);

		// create message for log
		swprintf(szMsg, L"CloseHandle (Object = \"%p\", FileName = \"%ls\") = %s; Signature = %02x %02x %02x %02x; Entropy = %fl; Integrity = %s",
			hObject, szPath, bResult ? "TRUE" : "FALSE", abSignature[0], abSignature[1], abSignature[2], abSignature[3], dblEntropy, bIntegrity ? "TRUE" : "FALSE");
	}
	else {
		// create message for log
		swprintf(szMsg, L"CloseHandle (Object = \"%p\", FileName = \"%ls\") = %s", hObject, szPath, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for DeleteFileW
__declspec(dllexport) BOOL WINAPI MyDeleteFileW (LPCWSTR lpFileName)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueDeleteFileW (lpFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpFileName) == TRUE) {
		// create message for log
		swprintf(szMsg, L"DeleteFileW (FileName = \"%ls\") = %s", lpFileName, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for DeleteFileTransactedW
__declspec(dllexport) BOOL WINAPI MyDeleteFileTransactedW (LPCWSTR lpFileName, HANDLE hTransaction)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueDeleteFileTransactedW (lpFileName, hTransaction);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpFileName) == TRUE) {
		// create message for log
		swprintf(szMsg, L"DeleteFileTransactedW (FileName = \"%ls\", Transaction = \"%p\") = %s", lpFileName, hTransaction, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for DeleteFileA
__declspec(dllexport) BOOL WINAPI MyDeleteFileA (LPCSTR lpFileName)
{
	WCHAR szFileName[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueDeleteFileA (lpFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szFileName) == TRUE) {
		// convert ANSI to UNICODE and create message for log
		swprintf(szFileName, MAX_PATH+1, L"%hs", lpFileName);
		swprintf(szMsg, L"DeleteFileA (FileName = \"%ls\") = %s", szFileName, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for DeleteFileTransactedA
__declspec(dllexport) BOOL WINAPI MyDeleteFileTransactedA (LPCSTR lpFileName, HANDLE hTransaction)
{
	WCHAR szFileName[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueDeleteFileTransactedA (lpFileName, hTransaction);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szFileName) == TRUE) {
		// create message for log
		swprintf(szFileName, MAX_PATH+1, L"%hs", lpFileName);
		swprintf(szMsg, L"DeleteFileTransactedA (FileName = \"%ls\", Transaction = \"%p\") = %s", szFileName, hTransaction, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for MoveFileExW
__declspec(dllexport) BOOL WINAPI MyMoveFileW (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueMoveFileW (lpExistingFileName, lpNewFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpExistingFileName) == TRUE) {
		// create message for log
		swprintf(szMsg, L"MoveFileW (ExistingFileName = \"%ls\", NewFileName = \"%ls\") = %s", lpExistingFileName, lpNewFileName, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for MoveFileExW
__declspec(dllexport) BOOL WINAPI MyMoveFileExW (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueMoveFileExW (lpExistingFileName, lpNewFileName, dwFlags);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpExistingFileName) == TRUE) {
		// create message for log
		swprintf(szMsg, L"MoveFileExW (ExistingFileName = \"%ls\", NewFileName = \"%ls\", Flags = %d) = %s", lpExistingFileName, lpNewFileName, dwFlags, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for WriteFile
__declspec(dllexport) BOOL WINAPI MyWriteFile (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// get result of true function
		bResult = TrueWriteFile (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}
	// check if process trying to access to protected drive
	else if (checkDrive(szPath) == TRUE) {
		// set false result
		bResult = FALSE;
	}
	else {
		// get result of true function
		bResult = TrueWriteFile (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}

	// create message for log
	swprintf(szMsg, L"WriteFile (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d, NumberOfBytesWritten = %d) = %s", hFile, szPath, nNumberOfBytesToWrite, *lpNumberOfBytesWritten, bResult ? "TRUE" : "FALSE");

	// return result of true function
	return bResult;
}

// hooking function for WriteFileEx
__declspec(dllexport) BOOL WINAPI MyWriteFileEx (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// get result of true function
		bResult = TrueWriteFileEx (hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	}
	// check if process trying to access to protected drive
	else if (checkDrive(szPath) == TRUE) {
		// set false result
		bResult = FALSE;
	}
	else {
		// get result of true function
		bResult = TrueWriteFileEx (hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	}

	// create message for log
	swprintf(szMsg, L"WriteFileEx (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d) = %s", hFile, szPath, nNumberOfBytesToWrite, bResult ? "TRUE" : "FALSE");

	// return result of true function
	return bResult;
}

// hooking function for ReadFile
__declspec(dllexport) BOOL WINAPI MyReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueReadFile (hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// create message for log
		swprintf(szMsg, L"ReadFile (File = \"%p\", FileName = \"%ls\", NumberOfBytesToRead = %d, NumberOfBytesRead = %d) = %s", hFile, szPath, nNumberOfBytesToRead, *lpNumberOfBytesRead, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for ReadFileEx
__declspec(dllexport) BOOL WINAPI MyReadFileEx (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueReadFileEx (hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// create message for log
		swprintf(szMsg, L"ReadFileEx (File = \"%p\", FileName = \"%ls\", NumberOfBytesToRead = %d) = %s", hFile, szPath, nNumberOfBytesToRead, bResult ? "TRUE" : "FALSE");
	}

	// return result of true function
	return bResult;
}

// hooking function for CreateFileMapping
__declspec(dllexport) HANDLE WINAPI MyCreateFileMappingW (HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	HANDLE hResult = TrueCreateFileMappingW (hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// create message for log
		swprintf(szMsg, L"CreateFileMapping (File = \"%p\", FileName = \"%ls\", Protect = %d) = %p", hFile, szPath, flProtect, hResult);
	}

	// return result of true function
	return hResult;
}

// hooking function for MapViewOfFile
// todo : check is it works?
__declspec(dllexport) LPVOID WINAPI MyMapViewOfFile (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	LPVOID lpResult = TrueMapViewOfFile (hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFileMappingObject, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// create message for log
		swprintf(szMsg, L"MapViewOfFile (FileMappingObject = \"%p\", FileName = \"%ls\", DesiredAccess = %d) = %p", hFileMappingObject, szPath, dwDesiredAccess, lpResult);
	}

	// return result of true function
	return lpResult;
}

// hooking function for MapViewOfFile
// todo : check is it works?
__declspec(dllexport) LPVOID WINAPI MyMapViewOfFileEx (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	LPVOID lpResult = TrueMapViewOfFileEx (hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);

	// get filename by handle
	if (!GetFinalPathNameByHandle(hFileMappingObject, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath) == TRUE) {
		// create message for log
		swprintf(szMsg, L"MapViewOfFileEx (FileMappingObject = \"%p\", FileName = \"%ls\", DesiredAccess = %d) = %p", hFileMappingObject, szPath, dwDesiredAccess, lpResult);
	}

	// return result of true function
	return lpResult;
}

// main dll function
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	WCHAR szLogFile[MAX_PATH+1] = {0};

	// if dll is loaded
	if (dwReason == DLL_PROCESS_ATTACH) 
	{
		// attach
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
		DetourAttach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
		DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
		DetourAttach(&(PVOID&)TrueDeleteFileW, MyDeleteFileW);
		DetourAttach(&(PVOID&)TrueDeleteFileTransactedW, MyDeleteFileTransactedW);
		DetourAttach(&(PVOID&)TrueDeleteFileA, MyDeleteFileA);
		DetourAttach(&(PVOID&)TrueDeleteFileTransactedA, MyDeleteFileTransactedA);
		DetourAttach(&(PVOID&)TrueMoveFileW, MyMoveFileW);
		DetourAttach(&(PVOID&)TrueMoveFileExW, MyMoveFileExW);
		DetourAttach(&(PVOID&)TrueWriteFile, MyWriteFile);
		DetourAttach(&(PVOID&)TrueWriteFileEx, MyWriteFileEx);
		DetourAttach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourAttach(&(PVOID&)TrueReadFileEx, MyReadFileEx);
		DetourAttach(&(PVOID&)TrueCreateFileMappingW, MyCreateFileMappingW);
		DetourAttach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
		DetourAttach(&(PVOID&)TrueMapViewOfFileEx, MyMapViewOfFileEx);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// detach
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
		DetourDetach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
		DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
		DetourDetach(&(PVOID&)TrueDeleteFileW, MyDeleteFileW);
		DetourDetach(&(PVOID&)TrueDeleteFileTransactedW, MyDeleteFileTransactedW);
		DetourDetach(&(PVOID&)TrueDeleteFileA, MyDeleteFileA);
		DetourDetach(&(PVOID&)TrueDeleteFileTransactedA, MyDeleteFileTransactedA);
		DetourDetach(&(PVOID&)TrueMoveFileW, MyMoveFileW);
		DetourDetach(&(PVOID&)TrueMoveFileExW, MyMoveFileExW);
		DetourDetach(&(PVOID&)TrueWriteFile, MyWriteFile);
		DetourDetach(&(PVOID&)TrueWriteFileEx, MyWriteFileEx);
		DetourDetach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourDetach(&(PVOID&)TrueReadFileEx, MyReadFileEx);
		DetourDetach(&(PVOID&)TrueCreateFileMappingW, MyCreateFileMappingW);
		DetourDetach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
		DetourDetach(&(PVOID&)TrueMapViewOfFileEx, MyMapViewOfFileEx);
		DetourTransactionCommit();
	}
	return TRUE;
}
