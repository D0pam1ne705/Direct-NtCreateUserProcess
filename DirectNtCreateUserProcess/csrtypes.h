#pragma once
#include <windows.h>
#include "nttypes.h"

/*	[NOTICE]
 * The following fields of structures were obtained by reversing.
 * Test Environment: Win10 21H2 (19044.1415)
 * 
 */

typedef struct
{
	ULONG_PTR UniqueProcess;
	ULONG_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

__declspec(align(8))
typedef struct
{
	BYTE byte0;						// +00		(+0xB8)
	BYTE byte1;						// +01
	BYTE byte2;						// +02
	BYTE byte3;						// +02
	ULONG64 DUMMY;					// +08		(+0xC0)
	ULONG_PTR ManifestAddress;		// +10		(+0xC8)
	ULONG64 ManifestSize;			// +18		(+0xD0)
	HANDLE SectionHandle;			// +20
	ULONG64 Offset;					// +28
	ULONG_PTR Size;					// +30
} BASE_SXS_STREAM;					// 0x38

typedef struct
{
	ULONG Flags;					// +00      // direct set, value = 0x40
	ULONG ProcessParameterFlags;	// +04      // direct set, value = 0x4001
	HANDLE FileHandle;				// +08      // we can get this value
	UNICODE_STRING FileName1;	    // +10      // UNICODE_STRING, we can build!
	UNICODE_STRING FileName2;	    // +20      // UNICODE_STRING, we can build!
	BYTE    Field30[0x10];          // +30      // blank, ignore
	BASE_SXS_STREAM PolicyStream;	// +40      // !!!
	UNICODE_STRING AssemblyName;	// +78      // blank, ignore
	UNICODE_STRING FileName3;		// +88      // UNICODE_STRING, we can build!
	BYTE    Field98[0x10];			// +98      // blank, ignore
	UNICODE_STRING FileName4;		// +a8      // UNICODE_STRING, we can build!
	BYTE OtherFileds[0x110];		// +b8		// blank, ignore
} BASE_SXS_CREATEPROCESS_MSG;		// 0x1C8

__declspec(align(8))
typedef struct {
	HANDLE ProcessHandle;			// +00      // can get
	HANDLE ThreadHandle;			// +08      // can get
	CLIENT_ID ClientId;				// +10      // can get, PID, TID
	ULONG CreationFlags;			// +20      // direct set, must be zero
	ULONG VdmBinaryType;			// +24      // direct set, must be zero
	ULONG VdmTask;					// +28      // ignore
	HANDLE hVDM;					// +30      // ignore
	BASE_SXS_CREATEPROCESS_MSG Sxs;	// +38      // deep, need analyze, (for BASE_API_MSG, start with 0x78)
	ULONG64 PebAddressNative;       // +200     // can get
	ULONG_PTR PebAddressWow64;		// +208     // direct set, must be zero (Win64 limit)
	USHORT ProcessorArchitecture;	// +210     // direct set, must be 9 (AMD64 limit)
} BASE_CREATEPROCESS_MSG;

////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CSHORT
#define CSHORT short
#endif

typedef struct {
	BYTE dummy[0x28];
} PORT_MESSAGE;

typedef struct _CSR_CAPTURE_HEADER {
	ULONG Length;
	PVOID RelatedCaptureBuffer;         // real: PCSR_CAPTURE_HEADER
	ULONG CountMessagePointers;
	PCHAR FreeSpace;
	ULONG_PTR MessagePointerOffsets[1]; // Offsets within CSR_API_MSG of pointers
} CSR_CAPTURE_HEADER, * PCSR_CAPTURE_HEADER;

typedef ULONG CSR_API_NUMBER;

////////////////////////////////////////////////////////////////////////////////////////////////////

__declspec(align(8))
typedef struct {
	PORT_MESSAGE h;
	PCSR_CAPTURE_HEADER CaptureBuffer;			// 0x28 
	CSR_API_NUMBER ApiNumber;					// 0x30 
	ULONG ReturnValue;							// 0x34 
	ULONG64 Reserved;							// 0x38
	BASE_CREATEPROCESS_MSG CreateProcessMSG;		// 0x40
} BASE_API_MSG, *PBASE_API_MSG;

////////////////////////////////////////////////////////////////////////////////////////////////////

typedef
NTSTATUS(__stdcall* fpCsrCaptureMessageMultiUnicodeStringsInPlace)(
	PVOID* CaptureBuffer,
	ULONG StringsCount,
	PUNICODE_STRING* MessageStrings);

typedef
NTSTATUS(__stdcall* fpCsrClientCallServer)(
	PBASE_API_MSG ApiMessage,
	PVOID CaptureBuffer,
	CSR_API_NUMBER ApiNumber,
	ULONG DataLength);