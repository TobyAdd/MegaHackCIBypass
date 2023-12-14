#include "utilities.hpp"

DWORD WINAPI ThreadMain(void* hModule) {
    HMODULE mh = NULL;
    MODULEINFO mhModuleInfo;
    
    while (mh == NULL) {
        mh = GetModuleHandleA("hackpro.dll");
        Sleep(1000);
    }    

    if (GetModuleInformation(GetCurrentProcess(), mh, &mhModuleInfo, sizeof(MODULEINFO))) {
        uintptr_t address;
        address = PatternScan(reinterpret_cast<uintptr_t>(mhModuleInfo.lpBaseOfDll), mhModuleInfo.SizeOfImage, "74 ? 83 e9 ? 74 ? 8b 45");
        if (address != 0) {
            WriteBytesToProcess(address, {0x90, 0x90});
            address += 5;    
            WriteBytesToProcess(address, {0x90, 0x90});
            address += 8;  
            WriteBytesToProcess(address, {0x90, 0x90});
        }

        address = PatternScan(reinterpret_cast<uintptr_t>(mhModuleInfo.lpBaseOfDll), mhModuleInfo.SizeOfImage, "74 ? 83 e8 ? 74 ? 83 e8 ? 74 ? 66 c7 45");
        if (address) {
            WriteBytesToProcess(address, {0x90, 0x90});
        }    

        address = PatternScan(reinterpret_cast<uintptr_t>(mhModuleInfo.lpBaseOfDll), mhModuleInfo.SizeOfImage, "74 ? 66 c7 45 ? ? ? 8d 45");
        if (address) {
            WriteBytesToProcess(address, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
        }
    }
    
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(0, 0, &ThreadMain, 0, 0, 0);
    }
    return true;
}