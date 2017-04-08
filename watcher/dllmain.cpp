// "dllmain.cpp" project's main file
// this file contains description of all interception functions and secondary functions

#include "dllmain.h" // main header file
#include "miniz.c"   // mini ZIP-library

// write input string szMsg into log file
void logMessage (WCHAR* szMsg) {
	HANDLE hLog = NULL;
	DWORD dwSize = 0;
	DWORD dwCount = 0;
	WCHAR szLog[1000] = {0};
	WCHAR szPath[1000] = {0};
	WCHAR szRecord[1000] = {0};

	if (szMsg != NULL) {
		// generate filename
		swprintf_s(szLog, PATH_LOG, GetCurrentProcessId());

		// get path of current process and set ransomware flag
		GetModuleFileName(NULL, szPath, MAX_PATH);

		// generate string
		swprintf_s(szRecord, L"%ls (id = %d): %ls\r\n", szPath, GetCurrentProcessId(), szMsg);

		// open log file
		hLog = TrueCreateFileW(szLog, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLog != INVALID_HANDLE_VALUE) {
			// write to end of file
			SetFilePointer(hLog, 0, NULL, FILE_END);

			// write string
			dwSize = (wcslen(szRecord)+1)*sizeof(WCHAR);
			TrueWriteFile(hLog, (BYTE *) szRecord, dwSize, &dwCount, NULL);
		}		
		TrueCloseHandle(hLog); // close log file
	}
}

// check if file has protected extension
BOOL checkFileExtension (LPCWSTR lpFileName) {
	// list of protected extensions
	WCHAR aszProtected[13][6] = {L".docx", L".doc", L".pptx", L".ppt", L".xslx", L".xsl", L".pdf", L".rtf", L".jpg", L".jpeg", L".png", L".zip", L".rar"};
	
	// is length of filename greater than zero
	if (wcslen(lpFileName) > 0) {
		// run on list of protected extensions
		for (DWORD i = 0; i < 13; i++) {
			if (wcsstr(lpFileName, &aszProtected[i][0])) {
				return TRUE; // if extension found at list, then return TRUE
			}
		}
	}

	// otherwise return FALSE
	return FALSE;
}

// check if file has extension of ZIP-format
BOOL checkZipFileExtension (LPCWSTR lpFileName) {
	// list of protected extensions
	WCHAR *szExtension = PathFindExtensionW(lpFileName);
	WCHAR aszProtected[4][6] = {L".docx", L".pptx", L".xslx", L".zip"};

	// is length of extension greater than zero
	if (wcslen(szExtension) > 0) {
		// run on list of protected extensions
		for (DWORD i = 0; i < 4; i++) {
			if (_wcsicmp(szExtension, &aszProtected[i][0]) == 0) {
				return TRUE; // if extension found at list, then return TRUE
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
		// return result
		return FALSE;
	}

	// get size of file
	dwSize = GetFileSize(hFile, NULL);
	if ((dwSize == INVALID_FILE_SIZE) || (dwSize < 4)) {
		// close all handles
		TrueCloseHandle(hFile);

		// return result
		return FALSE;
	}

	// MAX file size of integrity check
	if (dwSize > MAX_FILESIZE_INTEGRITY) {
		// close all handles
		TrueCloseHandle(hFile);

		// return result
		return FALSE;
	}

	// create mapping
	hMap = TrueCreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL) {
		// close all handles
		TrueCloseHandle(hFile);

		// return result
		return FALSE;
	}

	// create view of file
	lpView = TrueMapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
	if (hMap == NULL) {
		// close all handles
		TrueCloseHandle(hMap);
		TrueCloseHandle(hFile);

		// return result
		return FALSE;
	}

	// open the archive.
	memset(&zip_archive, 0, sizeof(zip_archive));
	status = mz_zip_reader_init_mem(&zip_archive, lpView, dwSize, 0);
	if (!status) {
		// close all handles
		UnmapViewOfFile(lpView);
		TrueCloseHandle(hMap);
		TrueCloseHandle(hFile);

		// return result
		return FALSE;
	}

	for (ci = 0; ci < (int)mz_zip_reader_get_num_files(&zip_archive); ci++) {
		// get information about each file in the archive
		mz_zip_archive_file_stat file_stat;
		if (!mz_zip_reader_file_stat(&zip_archive, ci, &file_stat))
		{
			// close the archive, freeing any resources it was using
			mz_zip_reader_end(&zip_archive);

			// close all handles
			UnmapViewOfFile(lpView);
			TrueCloseHandle(hMap);
			TrueCloseHandle(hFile);

			// return result
			return FALSE;
		}

		// try to extract this file
		p = mz_zip_reader_extract_file_to_heap(&zip_archive, file_stat.m_filename, &uncomp_size, 0);
		if (!p)
		{
			// close the archive, freeing any resources it was using
			mz_zip_reader_end(&zip_archive);

			// close all handles
			UnmapViewOfFile(lpView);
			TrueCloseHandle(hMap);
			TrueCloseHandle(hFile);

			// return result
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

// check if drive has protected devicename
// opt: do drive listing
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
		swprintf_s(szDrive, L"%c:\\", 'A'+ci); // convert bit to letter
		if (((Drives >> ci) & 0x1) == 0x1) {
			// we need for only HDDs
			if (GetDriveType(szDrive) == DRIVE_FIXED) {
				// check if we can access it
				swprintf_s(szDrive, L"\\\\.\\%c:", 'A'+ci);

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
							swprintf_s(szDrive, L"\\\\.\\PhysicalDrive%d", diskExtents.Extents[cj].DiskNumber);

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

// get main file info, result: TRUE - success, FALSE - fail
// _in_ lpFileName = filename
// _out_ abSignature[4] = signature
// _out_ dblEntropy = shannon's entropy
// 1 - get signature
// 2 - count Entropy
BOOL getFileInfo(LPCWSTR lpFileName, DWORD *dwFileSize, BYTE abSignature[4], double *lpEntropy) {
	HANDLE hFile = NULL;
	DWORD dwPos = 0;   // file pointer
	DWORD dwSize = 0;  // size of file (for pieces)
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
	*dwFileSize = GetFileSize(hFile, NULL);
	if ((*dwFileSize == INVALID_FILE_SIZE) || (*dwFileSize < 4)) {
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
	dwRatio = *dwFileSize / (MAX_FILESIZE_ENTROPY);

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
__declspec(dllexport) BOOL WINAPI MyCreateProcessW (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	WCHAR szMsg[1000];

	// get result of true function
	BOOL bResult = TrueCreateProcessW (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	// find suspicious substrings
	if (StrStrIW(lpApplicationName, L"vssadmin") || StrStrIW(lpCommandLine, L"vssadmin") || StrStrIW(lpApplicationName, L"shadowcopy") || StrStrIW(lpCommandLine, L"shadowcopy")) {
		// create message for log
		swprintf_s(szMsg, L"CreateProcess (ApplicationName = \"%ls\", CommandLine = \"%ls\") = %ls", lpApplicationName, lpCommandLine, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}

	// return result of true function
	return bResult;
}

// hooking function for CreateFileW
__declspec(dllexport) HANDLE WINAPI MyCreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	HANDLE hResult = NULL;
	WCHAR szMsg[1000] = {0};
	WCHAR szInfo[100] = {0};
	WCHAR szIntegrity[100] = {0};
	DWORD dwFileSize = INVALID_FILE_SIZE;
	BYTE abSignature[4] = {0};
	BOOL bIntegrity = FALSE;
	double dblEntropy = 0;

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpFileName)) {
		// get main file info
		if (getFileInfo(lpFileName, &dwFileSize, abSignature, &dblEntropy)) {
			swprintf_s(szInfo, L"FileSize = %d, Signature = %02x %02x %02x %02x; Entropy = %fl;", dwFileSize, abSignature[0], abSignature[1], abSignature[2], abSignature[3], dblEntropy);
		}
		else {
			swprintf_s(szInfo, L"File not exist");
		}

		// check integrity of file
		if (checkZipFileExtension(lpFileName)) {
			swprintf_s(szIntegrity, L"Integrity = %ls;", checkZipIntegrity(lpFileName) ? L"TRUE" : L"FALSE");
		}

		// get result of true function
		hResult = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		// create message for log
		swprintf_s(szMsg, L"CreateFile (FileName = \"%ls\", DesiredAccess = %d) = %p; %ls %ls", lpFileName, dwDesiredAccess, hResult, szInfo, szIntegrity);
		logMessage(szMsg);
	}
	// if process trying to access to protected drive
	else if (checkDrive(lpFileName)) {
		// get result of true function
		hResult = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		// create message for log
		swprintf_s(szMsg, L"CreateFile (FileName = \"%ls\", DesiredAccess = %d) = %p", lpFileName, dwDesiredAccess, hResult);
		logMessage(szMsg);
	}
	else {
		// get result of true function
		hResult = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	// return result of true function
	return hResult;
}

// this hooking function for CloseHandle
__declspec(dllexport) BOOL WINAPI MyCloseHandle (HANDLE hObject)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	WCHAR szInfo[100] = {0};
	WCHAR szIntegrity[100] = {0};
	DWORD dwFileSize = INVALID_FILE_SIZE;
	BYTE abSignature[4] = {0};
	BOOL bIntegrity = FALSE;
	double dblEntropy = 0;

	// get filename by handle
	if (!GetFinalPathNameByHandleW(hObject, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// get result of true function
	BOOL bResult = TrueCloseHandle(hObject);

	// if process trying to access to file with protected extension or to protected drive
	if (checkFileExtension(szPath)) {
		// get main file info
		if (getFileInfo(szPath, &dwFileSize, abSignature, &dblEntropy)) {
			swprintf_s(szInfo, L"FileSize = %d, Signature = %02x %02x %02x %02x; Entropy = %fl;", dwFileSize, abSignature[0], abSignature[1], abSignature[2], abSignature[3], dblEntropy);
		}

		// check integrity of file
		if (checkZipFileExtension(szPath)) {
			swprintf_s(szIntegrity, L"Integrity = %ls;", checkZipIntegrity(szPath) ? L"TRUE" : L"FALSE");
		}

		// create message for log
		swprintf_s(szMsg, L"CloseHandle (Object = \"%p\", FileName = \"%ls\") = %ls; %ls %ls", hObject, szPath, bResult ? L"TRUE" : L"FALSE", szInfo, szIntegrity);
		logMessage(szMsg);
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
	if (checkFileExtension(lpFileName)) {
		// create message for log
		swprintf_s(szMsg, L"DeleteFileW (FileName = \"%ls\") = %ls", lpFileName, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
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
	if (checkFileExtension(lpFileName)) {
		// create message for log
		swprintf_s(szMsg, L"DeleteFileTransactedW (FileName = \"%ls\", Transaction = \"%p\") = %ls", lpFileName, hTransaction, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
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

	// convert ANSI to UNICODE filename
	swprintf_s(szFileName, MAX_PATH+1, L"%hs", lpFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szFileName)) {
		// create message for log
		swprintf_s(szMsg, L"DeleteFileA (FileName = \"%ls\") = %ls", szFileName, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
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

	// convert ANSI to UNICODE filename
	swprintf_s(szFileName, MAX_PATH+1, L"%hs", lpFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szFileName)) {
		// create message for log
		swprintf_s(szMsg, L"DeleteFileTransactedA (FileName = \"%ls\", Transaction = \"%p\") = %ls", szFileName, hTransaction, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}

	// return result of true function
	return bResult;
}

// hooking function for MoveFileExW
__declspec(dllexport) BOOL WINAPI MyMoveFileW (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
	BOOL bResult;
	WCHAR szMsg[1000];

	// get result of true function
	bResult = TrueMoveFileW (lpExistingFileName, lpNewFileName);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpExistingFileName)) {
		// create message for log
		swprintf_s(szMsg, L"MoveFileW (ExistingFileName = \"%ls\", NewFileName = \"%ls\") = %ls", lpExistingFileName, lpNewFileName, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}

	// return result of true function
	return bResult;
}

// hooking function for MoveFileExW
__declspec(dllexport) BOOL WINAPI MyMoveFileExW (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
{
	BOOL bResult;
	WCHAR szMsg[1000];

	// get result of true function
	bResult = TrueMoveFileExW (lpExistingFileName, lpNewFileName, dwFlags);

	// if process trying to access to file with protected extension
	if (checkFileExtension(lpExistingFileName)) {
		// create message for log
		swprintf_s(szMsg, L"MoveFileExW (ExistingFileName = \"%ls\", NewFileName = \"%ls\", Flags = %d) = %ls", lpExistingFileName, lpNewFileName, dwFlags, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}

	// return result of true function
	return bResult;
}

// hooking function for WriteFile
__declspec(dllexport) BOOL WINAPI MyWriteFile (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szBytes[10240];
	WCHAR szMsg[1000];
	WCHAR szHex[10];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandleW(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// get result of true function
		bResult = TrueWriteFile (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

		// create message for log
		swprintf_s(szMsg, 10240, L"WriteFile (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d) = %ls", hFile, szPath, nNumberOfBytesToWrite, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}
	// check if process trying to access to protected drive
	else if (checkDrive(szPath)) {
		// set false result
		bResult = FALSE;

		// save bytes
		if (nNumberOfBytesToWrite<1024) {
			// create string of hexs
			wcscpy_s (szBytes, L"bytes = ");
			for (unsigned int ci = 0; ci < nNumberOfBytesToWrite; ci++) {
				swprintf_s(szHex, L"%02x ", (unsigned char *) lpBuffer+ci);
				wcscat_s (szBytes, szHex);
			}
		}
		else {
			wcscpy_s (szBytes, L"bytes = too long");
		}

		// create message for log
		swprintf_s(szMsg, 10240, L"WriteFile (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d, NumberOfBytesWritten = %d) = %ls;\r\nbytes = %ls", hFile, szPath, nNumberOfBytesToWrite, *lpNumberOfBytesWritten, bResult ? L"TRUE" : L"FALSE", szBytes);
		logMessage(szMsg);
	}
	else {
		// get result of true function
		bResult = TrueWriteFile (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}

	// return result of true function
	return bResult;
}

// hooking function for WriteFileEx
__declspec(dllexport) BOOL WINAPI MyWriteFileEx (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szBytes[10240];
	WCHAR szMsg[1000];
	WCHAR szHex[10];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandleW(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// get result of true function
		bResult = TrueWriteFileEx (hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);

		// create message for log
		swprintf_s(szMsg, 10240, L"WriteFileEx (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d) = %ls", hFile, szPath, nNumberOfBytesToWrite, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}
	// check if process trying to access to protected drive
	else if (checkDrive(szPath)) {
		// set false result
		bResult = FALSE;

		// save bytes
		if (nNumberOfBytesToWrite<1024) {
			// create string of hexs
			wcscpy_s (szBytes, L"bytes = ");
			for (unsigned int ci = 0; ci < nNumberOfBytesToWrite; ci++) {
				swprintf_s(szHex, L"%02x ", (unsigned char *) lpBuffer+ci);
				wcscat_s (szBytes, szHex);
			}
		}
		else {
			wcscpy_s (szBytes, L"bytes = too long");
		}

		// create message for log
		swprintf_s(szMsg, 10240, L"WriteFileEx (File = \"%p\", FileName = \"%ls\", NumberOfBytesToWrite = %d) = %ls", hFile, szPath, nNumberOfBytesToWrite, bResult ? L"TRUE" : L"FALSE", szBytes);
		logMessage(szMsg);
	}
	else {
		// get result of true function
		bResult = TrueWriteFileEx (hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
	}

	// return result of true function
	return bResult;
}

// hooking function for ReadFile
__declspec(dllexport) BOOL WINAPI MyReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandleW(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// get result of true function
	bResult = TrueReadFile (hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// create message for log
		swprintf_s(szMsg, L"ReadFile (File = \"%p\", FileName = \"%ls\", NumberOfBytesToRead = %d) = %ls", hFile, szPath, nNumberOfBytesToRead, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
	}

	// return result of true function
	return bResult;
}

// hooking function for ReadFileEx
__declspec(dllexport) BOOL WINAPI MyReadFileEx (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];
	BOOL bResult;

	// get filename by handle
	if (!GetFinalPathNameByHandleW(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// get result of true function
	bResult = TrueReadFileEx (hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// create message for log
		swprintf_s(szMsg, L"ReadFileEx (File = \"%p\", FileName = \"%ls\", NumberOfBytesToRead = %d) = %ls", hFile, szPath, nNumberOfBytesToRead, bResult ? L"TRUE" : L"FALSE");
		logMessage(szMsg);
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
	if (!GetFinalPathNameByHandleW(hFile, szPath, MAX_PATH, 0)) {
		// if fails, manually set FileName
		wcscpy_s (szPath, L"unknown");
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// create message for log
		swprintf_s(szMsg, L"CreateFileMapping (File = \"%p\", FileName = \"%ls\", Protect = %d) = %p", hFile, szPath, flProtect, hResult);
		logMessage(szMsg);
	}

	// return result of true function
	return hResult;
}

// hooking function for MapViewOfFile
__declspec(dllexport) LPVOID WINAPI MyMapViewOfFile (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	LPVOID lpResult = TrueMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

	// get filename by handle
	if (lpResult) {
		if (!GetMappedFileNameW(GetCurrentProcess(), lpResult, szPath, MAX_PATH)) {
			// if fails, manually set FileName
			wcscpy_s (szPath, L"unknown");
		}
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// create message for log
		swprintf_s(szMsg, L"MapViewOfFile (FileMappingObject = \"%p\", FileName = \"%ls\", DesiredAccess = %d) = %p", hFileMappingObject, szPath, dwDesiredAccess, lpResult);
		logMessage(szMsg);
	}

	// return result of true function
	return lpResult;
}

// hooking function for MapViewOfFile
__declspec(dllexport) LPVOID WINAPI MyMapViewOfFileEx (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)
{
	WCHAR szPath[MAX_PATH+1];
	WCHAR szMsg[1000];

	// get result of true function
	LPVOID lpResult = TrueMapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);

	// get filename by handle
	if (lpResult) {
		if (!GetMappedFileNameW(GetCurrentProcess(), lpResult, szPath, MAX_PATH)) {
			// if fails, manually set FileName
			wcscpy_s (szPath, L"unknown");
		}
	}

	// if process trying to access to file with protected extension
	if (checkFileExtension(szPath)) {
		// create message for log
		swprintf_s(szMsg, L"MapViewOfFileEx (FileMappingObject = \"%p\", FileName = \"%ls\", DesiredAccess = %d) = %p", hFileMappingObject, szPath, dwDesiredAccess, lpResult);
		logMessage(szMsg);
	}

	// return result of true function
	return lpResult;
}

// main dll function
BOOL WINAPI DllMain (HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
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
