#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {

        switch (reason) {

                case DLL_PROCESS_ATTACH:
                        MessageBoxA(NULL, "wsl", "wsl", MB_OK);
                        break;

                case DLL_THREAD_ATTACH:
                        break;

                case DLL_THREAD_DETACH:
                        break;

                case DLL_PROCESS_DETACH:
                        break;

        }

        return TRUE;
}
