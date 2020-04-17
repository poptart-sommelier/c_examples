#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdbool.h>

int main()
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof(si) };
	TCHAR name[] = _T("notepad");
	BOOL success = CreateProcess(0, name, 0, 0, FALSE, 0, 0, 0, &si, &pi);
	DWORD code;

	if (!success) {
		printf("Failed!\n");
		return 1;
	}
	else {
		printf("hProcess: %d\n", pi.hProcess);
		printf("PID: %d\n", pi.dwProcessId);

		WaitForSingleObject(pi.hProcess, INFINITE);
		
		GetExitCodeProcess(pi.hProcess, &code);
		printf("Exit Code: %d\n", code);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	return 0;
}

