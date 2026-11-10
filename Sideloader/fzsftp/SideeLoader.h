#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess				((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread				((HANDLE)(LONG_PTR)-2)
#define RVA(type, base, rva)			(type)((ULONG_PTR) base + rva)
#define WIN_FUNC(f) __typeof__(f) * f;
#define C_PTR( x )          ( ( LPVOID ) x )
#define U_PTR( x )          ( ( UINT_PTR ) x )

#define CUSTOM_HASH_SEED       0xC0DEBABE
#define ROTL32( x, n )         ( ( ( x ) << ( n ) ) | ( ( x ) >> ( 32 - ( n ) ) ) )

#define HASH_GETFOREGROUNDWINDOW             0x40386D6F
#define HASH_SHOWWINDOW                      0xC4ED7100
#define HASH_RTLCREATEUSERTHREAD             0xD230B8FB
#define HASH_NTCLOSE                         0xD603EB29

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _ANSI_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef VOID (*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);


#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

NTAPI NTSTATUS RtlCreateUserThread(
        IN HANDLE ProcessHandle,
        IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
        IN BOOLEAN CreateSuspended,
        IN ULONG StackZeroBits OPTIONAL,
        IN SIZE_T StackReserve OPTIONAL,
        IN SIZE_T StackCommit OPTIONAL,
        IN PTHREAD_START_ROUTINE StartAddress,
        IN PVOID Parameter OPTIONAL,
        OUT PHANDLE ThreadHandle OPTIONAL,
        OUT PCLIENT_ID ClientId OPTIONAL
);

NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
        HANDLE    ProcessHandle,
        PVOID     *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T   RegionSize,
        ULONG     AllocationType,
        ULONG     Protect
);

NTSYSCALLAPI NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
);

NTSYSCALLAPI NTSTATUS NtOpenSection(
  OUT PHANDLE            SectionHandle,
  IN  ACCESS_MASK        DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI NTSTATUS NtMapViewOfSection(
	HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress, 
    ULONG_PTR ZeroBits, 
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, 
    PSIZE_T ViewSize, 
    DWORD InheritDisposition, 
    ULONG AllocationType, 
    ULONG Win32Protect
);

NTSYSCALLAPI NTSTATUS NtUnmapViewOfSection(
	IN  OPTIONAL	HANDLE              ProcessHandle,				// INPUT  : in case of null, the function will run localy
	IN  			PVOID				BaseAddress				// INPUT  : can't be NULL
);

NTSYSCALLAPI NTSTATUS NtQueueApcThreadEx(
    _In_ HANDLE ThreadHandle,
	_In_opt_ HANDLE UserApcReserveHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);

NTSYSCALLAPI NTSTATUS NtTestAlert( VOID );
NTSYSCALLAPI NTSTATUS NtClose( HANDLE Handle );

NTSYSCALLAPI NTSTATUS LdrGetProcedureAddress(
    IN PVOID        Module,
    IN PANSI_STRING FunctionName,
    IN ULONG        Ordinal,
    OUT PVOID      *FunctionAddress
);

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

/* InLoadOrder layout: LdrModulePeb casts InLoadOrderModuleList entries to this
   struct, so the InLoadOrder links must be the first member (real ntdll layout). */
typedef struct _LDR_DATA_TABLE_ENTRY1
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY1, * PLDR_DATA_TABLE_ENTRY1;

typedef PEB_LDR_DATA FULL_PEB_LDR_DATA, * PFULL_PEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STRING usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} PEB, * PPEB;


typedef struct {

    struct {
        HMODULE hKernel32;
        HMODULE hNtdll;
        HMODULE hUser32;
    } Lib;

    struct {
        WIN_FUNC ( RtlCreateUserThread );
        WIN_FUNC ( NtClose );
    } $NTDLL;

    struct {
        WIN_FUNC ( ShowWindow );
        WIN_FUNC ( GetForegroundWindow );
        // WIN_FUNC ( MessageBoxA );
    } $USER32;

    struct {
        WIN_FUNC ( LdrGetProcedureAddress );
    } Win32;

} Instance;

typedef Instance * PINSTANCE;

extern Instance xInstance;
