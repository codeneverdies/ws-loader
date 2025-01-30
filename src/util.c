#include "util.h"

VOID setmem(PVOID dst, UCHAR value, UINT64 size) {

    PUCHAR tmp = (PUCHAR)dst;

    for ( UINT64 i = 0; i < size; i++ )
        tmp[i] = value;

}

ULONG djb2(PCHAR str) {

    INT c;
    ULONG hash = 5381;

    while ( c = *str++ ) {
        hash = (((hash << 5) + hash) + c) & 0xFFFFFFFF;
    }

    return hash;
}

ULONG djb2_w(PWCHAR wstr) {

    INT c;
    ULONG hash = 5381;

    while ( c = *wstr++ ) {
        hash = (((hash << 5) + hash) + c) & 0xFFFFFFFF;
    }

    return hash;
}

HMODULE get_mod_handle(ULONG mod_hash) {

    HMODULE mod                    = NULL;
    LIST_ENTRY *entry              = NULL;
    LIST_ENTRY *next_entry         = NULL;
    LDR_DATA_TABLE_ENTRY *data_tbl = NULL;

    PPEB peb = get_peb();

    if ( !mod_hash )
        return (HMODULE)(peb->lpImageBaseAddress);

    PPEB_LDR_DATA ldr = peb->Ldr;

    entry = &ldr->InMemoryOrderModuleList;
    next_entry = entry->Flink;

    for ( LIST_ENTRY *e = next_entry; e != entry; e = e->Flink ) {

        data_tbl = (LDR_DATA_TABLE_ENTRY *)((BYTE *)e - sizeof(LIST_ENTRY));

       if ( djb2_w(data_tbl->BaseDllName.pBuffer) == mod_hash ) {
            mod = (HMODULE)(data_tbl->DllBase);
            break;
       }
    }

    return mod;
}

FARPROC get_proc_addr(HMODULE mod, ULONG proc_hash) {

    PVOID proc_addr = NULL;
    PIMAGE_DOS_HEADER dos_hdr = NULL;
    PIMAGE_NT_HEADERS64 nt_hdr = NULL;
    PIMAGE_OPTIONAL_HEADER opt_hdr = NULL;
    PIMAGE_DATA_DIRECTORY exp_dir_start = NULL;
    PIMAGE_EXPORT_DIRECTORY exp_dir = NULL;

    if ( !mod )
        return proc_addr;

    void *mod_base = (void *)mod;

    dos_hdr = (PIMAGE_DOS_HEADER)mod_base;
    nt_hdr = (PIMAGE_NT_HEADERS64)(mod_base + dos_hdr->e_lfanew);
    opt_hdr = &nt_hdr->OptionalHeader; 
    exp_dir_start = (PIMAGE_DATA_DIRECTORY)(&opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    exp_dir = (PIMAGE_EXPORT_DIRECTORY)(mod_base + exp_dir_start->VirtualAddress);

    if ( !exp_dir )
        return proc_addr;

    PDWORD names = (PDWORD)(mod_base + exp_dir->AddressOfNames);
    PDWORD functions = (PDWORD)(mod_base + exp_dir->AddressOfFunctions);
    PWORD ordinals = (PWORD)(mod_base + exp_dir->AddressOfNameOrdinals);

    for ( DWORD i = 0; i < exp_dir->AddressOfNames; i++ ) {

        PCHAR proc_name = (PCHAR)(mod_base + names[i]);

        if ( djb2(proc_name) == proc_hash ) {
            proc_addr = (FARPROC)( mod_base + functions[ordinals[i]] );
            return proc_addr;
        }
    }

    return NULL;
}