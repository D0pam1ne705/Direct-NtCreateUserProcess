#include <stdio.h>
#include <Windows.h>
#include "nttypes.h"
#include "csrtypes.h"

#define IS_NATIVE

NTSTATUS DoDirect(LPCWSTR lpProcessImageName) {
	PS_CREATE_INFO createInfo;
	RTL_USER_PROCESS_PARAMETERS procParams;
	PS_ATTRIBUTE_LIST attrList;
	PS_PROTECTION protectionInfo;

	NTSTATUS status = STATUS_PENDING;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	
	HMODULE hm = GetModuleHandleA("ntdll.dll");
	if (!hm) {
		printf("[-] %-30s = %d\n", "get ntdll.dll failed", ::GetLastError());
		return -1;
	}

	fpNtCreateUserProcess _NtCreateUserProcess = (fpNtCreateUserProcess)GetProcAddress(hm, "NtCreateUserProcess");
	fpNtResumeThread _NtResumeThread = (fpNtResumeThread)GetProcAddress(hm, "NtResumeThread");

	fpNtQueryInformationProcess _NtQueryInformationProcess = (fpNtQueryInformationProcess)GetProcAddress(hm, "NtQueryInformationProcess");
	fpRtlInitUnicodeString _RtlInitUnicodeString = (fpRtlInitUnicodeString)GetProcAddress(hm, "RtlInitUnicodeString");
	fpRtlCreateProcessParametersEx _RtlCreateProcessParametersEx = (fpRtlCreateProcessParametersEx)GetProcAddress(hm, "RtlCreateProcessParametersEx");
	fpRtlDestroyProcessParameters _RtlDestroyProcessParameters = (fpRtlDestroyProcessParameters)GetProcAddress(hm, "RtlDestroyProcessParameters");
	fpNtClose _NtClose = (fpNtClose)GetProcAddress(hm, "NtClose");

	fpCsrCaptureMessageMultiUnicodeStringsInPlace _CsrCaptureMessageMultiUnicodeStringsInPlace = (fpCsrCaptureMessageMultiUnicodeStringsInPlace)
		GetProcAddress(hm, "CsrCaptureMessageMultiUnicodeStringsInPlace");
	fpCsrClientCallServer _CsrClientCallServer = (fpCsrClientCallServer)
		GetProcAddress(hm, "CsrClientCallServer");

	if (_CsrCaptureMessageMultiUnicodeStringsInPlace == 0 || _CsrClientCallServer == 0) {
		printf("[-] %-30s = %d\n", "get csrss fucns failed", ::GetLastError());
		return -1;
	}

	PCLIENT_ID pClientId = nullptr;
	PSECTION_IMAGE_INFORMATION pSecImgInfo = nullptr;
	do {
		UNICODE_STRING ustrProcessImageName;
		WCHAR ntProcessImagePath[MAX_PATH];
		memset(ntProcessImagePath, 0, sizeof(WCHAR) * MAX_PATH);
		swprintf_s(ntProcessImagePath, MAX_PATH, L"\\??\\%ws", lpProcessImageName);
		_RtlInitUnicodeString(&ustrProcessImageName, ntProcessImagePath);		// ustr has prefix '\\??\\'

		protectionInfo.Signer = (UCHAR)PsProtectedSignerNone;
		protectionInfo.Type = (UCHAR)PsProtectedTypeNone;
		protectionInfo.Audit = 0;

		// init
		RtlSecureZeroMemory(&procParams, sizeof(RTL_USER_PROCESS_PARAMETERS));
		RtlSecureZeroMemory(&attrList, sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE));
		RtlSecureZeroMemory(&createInfo, sizeof(PS_CREATE_INFO));
		
		// set process parameters
		PRTL_USER_PROCESS_PARAMETERS pProcParams = nullptr;
		status = _RtlCreateProcessParametersEx(
			&pProcParams,
			&ustrProcessImageName,
			NULL,
			NULL,
			&ustrProcessImageName,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RTL_USER_PROC_PARAMS_NORMALIZED);

		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = %d\n", "RtlCreateProcessParametersEx failed", status);
			break;
		}
		
		// set create info
		createInfo.State = PsCreateInitialState;
		createInfo.Size = sizeof(PS_CREATE_INFO);
#ifdef IS_NOT_MININAL
		createInfo.InitState.InitFlags = 3; // WriteOutputOnExit | DetectManifest
		createInfo.InitState.AdditionalFileAccess = 0x1000a1; // Synch | Read/List | Execute/Traverse | ReadAttr (used by SxS)
#endif // IS_NOT_MININAL

		// set attribute list
		attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
		attrList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);	// set image name
		attrList.Attributes[0].Size = ustrProcessImageName.Length;
		attrList.Attributes[0].ValuePtr = ustrProcessImageName.imgBuffer;
#ifdef IS_NOT_MININAL
		pClientId = (PCLIENT_ID)malloc(sizeof(CLIENT_ID));
		if (!pClientId)
			break;
		memset(pClientId, 0, sizeof(CLIENT_ID));
		attrList.Attributes[1].Attribute = PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
		attrList.Attributes[1].Size = 0x10;
		attrList.Attributes[1].ValuePtr = pClientId;	// [OUT]

		pSecImgInfo = (PSECTION_IMAGE_INFORMATION)malloc(sizeof(SECTION_IMAGE_INFORMATION));
		if (!pSecImgInfo)
			break;
		memset(pSecImgInfo, 0, sizeof(SECTION_IMAGE_INFORMATION));
		attrList.Attributes[2].Attribute = PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE);
		attrList.Attributes[2].Size = sizeof(SECTION_IMAGE_INFORMATION);
		attrList.Attributes[2].ValuePtr = pSecImgInfo;	// [OUT]
#endif // IS_NOT_MININAL

		status = _NtCreateUserProcess( // NtCreateProcessEx
			&hProcess,
			&hThread,
			MAXIMUM_ALLOWED,
			MAXIMUM_ALLOWED,
			NULL,
			NULL,
			PROCESS_CREATE_FLAGS_SUSPENDED,	// ProcessFlags
			THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
			pProcParams,	// <--- 
			&createInfo,
			&attrList);
		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = %d\n", "NtCreateUserProcess failed", status);
			break;
		}
		_RtlDestroyProcessParameters(pProcParams);

		printf("[+] %-30s = 0x%p\n", "Process Handle", hProcess);
		printf("[+] %-30s = 0x%p\n", "Thread Handle", hThread);
		printf("[+] %-30s = 0x%x\n", "target process pid", ::GetProcessId(hProcess));
		printf("[+] %-30s = 0x%x\n", "target thread pid", ::GetThreadId(hThread));

		printf("[+] %-30s = 0x%x\n", "createInfo.State", createInfo.State);
		if (createInfo.State == 6) {
			printf("[+] %-30s = 0x%p\n", "createInfo.FileHandle", createInfo.SuccessState.FileHandle);
			printf("[+] %-30s = 0x%p\n", "createInfo.SectionHandle", createInfo.SuccessState.SectionHandle);
			printf("[+] %-30s = 0x%llx\n", "createInfo.PebAddressNative", createInfo.SuccessState.PebAddressNative);
			printf("[+] %-30s = 0x%llx\n", "createInfo.ManifestAddress", createInfo.SuccessState.ManifestAddress);
			printf("[+] %-30s = 0x%x\n", "createInfo.ManifestSize", createInfo.SuccessState.ManifestSize);
		}

#ifdef IS_NOT_MININAL
		// 
		// check peb
		//
		PROCESS_BASIC_INFORMATION pbi;
		PEB* pebAddr;
		ULONG ReturnLength;

		status = _NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pbi,
			sizeof(PROCESS_BASIC_INFORMATION),
			&ReturnLength);
		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = %d\n", "NtQueryInformationProcess failed", status);
			break;
		}
		pebAddr = (PEB*)pbi.PebBaseAddress;
		printf("[>] %-30s = 0x%p\n", "peb", pbi.PebBaseAddress);

		if (createInfo.SuccessState.PebAddressNative != (ULONGLONG)pbi.PebBaseAddress) {
			break; // make sure peb of target process is valid
		}

		//
		// build msg for csr
		//

		BASE_API_MSG m;
		memset(&m, 0, sizeof(m));

		// basic fields
		m.CreateProcessMSG.ProcessHandle = (HANDLE)((DWORD64)hProcess | 2);
		m.CreateProcessMSG.ThreadHandle = hThread;
		m.CreateProcessMSG.ClientId.UniqueProcess = pClientId->UniqueProcess;
		m.CreateProcessMSG.ClientId.UniqueThread = pClientId->UniqueThread;
		m.CreateProcessMSG.CreationFlags = 0x0;
		m.CreateProcessMSG.VdmBinaryType = 0x0;
		m.CreateProcessMSG.PebAddressNative = (ULONG64)pebAddr;
		m.CreateProcessMSG.PebAddressWow64 = 0x0;
		m.CreateProcessMSG.ProcessorArchitecture = 9; // AMD64(=9)

		// sxs
		m.CreateProcessMSG.Sxs.Flags = 0x40;
		m.CreateProcessMSG.Sxs.ProcessParameterFlags = 0x4001;
		m.CreateProcessMSG.Sxs.FileHandle = createInfo.SuccessState.FileHandle; // used by sxssrv!InternalSxsCreateProcess
		m.CreateProcessMSG.Sxs.PolicyStream.ManifestAddress = createInfo.SuccessState.ManifestAddress;
		m.CreateProcessMSG.Sxs.PolicyStream.ManifestSize = createInfo.SuccessState.ManifestSize;

		_RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.FileName1, lpProcessImageName);
		_RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.FileName2, ntProcessImagePath);
		_RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.FileName4, L"-----------------------------------------------------------");
		m.CreateProcessMSG.Sxs.FileName3.Length = 0x10;						// need 4 extra blank bytes (used by ActiveContext)
		m.CreateProcessMSG.Sxs.FileName3.MaximumLength = 0x14;
		m.CreateProcessMSG.Sxs.FileName3.imgBuffer = (PWCH)malloc(0x28);
		if (!m.CreateProcessMSG.Sxs.FileName3.imgBuffer) {
			break;
		}
		memset(m.CreateProcessMSG.Sxs.FileName3.imgBuffer, 0, 0x28);
		wcscpy_s(m.CreateProcessMSG.Sxs.FileName3.imgBuffer, 0x10, L"en-US");

		//
		// notify windows subsystem
		//

		PVOID captureBuffer = 0;
		PUNICODE_STRING stringToCapture[6] = { 0, };
		stringToCapture[0] = &m.CreateProcessMSG.Sxs.FileName1;
		stringToCapture[1] = &m.CreateProcessMSG.Sxs.FileName2;
		stringToCapture[2] = &m.CreateProcessMSG.Sxs.FileName3;
		stringToCapture[3] = &m.CreateProcessMSG.Sxs.FileName4;

		status = _CsrCaptureMessageMultiUnicodeStringsInPlace(&captureBuffer, 4, stringToCapture);
		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = %d\n", "capture string failed", status);
			break;
		}
		printf("[+] %-30s = 0x%p\n", "capture success!", captureBuffer);

		status = _CsrClientCallServer(&m, captureBuffer, 0x1001D, 0x218);
		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = 0x%X\n", "CsrClientCallServer failed", m.ReturnValue);
			break;
		}
#endif 
		//
		// everything is ready, lets go!
		//

		status = _NtResumeThread(
			hThread,
			0
		);
		if (!NT_SUCCESS(status)) {
			printf("[-] %-30s = %d\n", "NtResumeThread failed", status);
			break;
		}
	} while (0);
	if (hThread)
		_NtClose(hThread);
	if (hProcess)
		_NtClose(hProcess);
	if (pClientId)
		free(pClientId);
	if (pSecImgInfo)
		free(pSecImgInfo);		

	return status;
}

int wmain(int argc, wchar_t *argv[])
{
	if (argc != 2) {
		printf("[-] usage: *.exe <target image path>");
		return 0;
	}

	NTSTATUS res = DoDirect(argv[1]);

	printf("[>] done!\n");
	return 0;
}