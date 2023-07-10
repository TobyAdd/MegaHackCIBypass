#include "utilities.hpp"

int main() {
    printf("Mega Hack cheat indicator bypass by TobyAdd and Eimaen\n");
    DWORD processId = GetPIDByName("GeometryDash.exe");
    if (processId == 0) {
        printf("Failed to find Geometry Dash!\n");
        Sleep(3000);
        return 1;
    }
    else {
        printf("Geometry Dash founded\n");
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    MODULEINFO hackProInfo = GetModule(processHandle, "hackpro.dll");
    uintptr_t hackProBase = reinterpret_cast<uintptr_t>(hackProInfo.lpBaseOfDll);

    if (hackProBase == 0) {
        printf("Failed to find Mega Hack!\n");
        Sleep(3000);
        return 1;
    }
    else {
        printf("Mega Hack founded\n");
    }

    printf("Patching #1\n");
    LPVOID address = LPVOID(PatternScan(processHandle, hackProBase, hackProInfo.SizeOfImage, "74 ? 83 e9 ? 74 ? 8b 45"));
    WriteBytesToProcess(processHandle, address, {0x90, 0x90});

    printf("Patching #2\n");
    LPVOID address2 = LPVOID(PatternScan(processHandle, hackProBase, hackProInfo.SizeOfImage, "74 ? 83 e8 ? 74 ? 83 e8 ? 74 ? 66 c7 45"));
    WriteBytesToProcess(processHandle, address2, {0x90, 0x90});

    printf("Patching #3\n");
    LPVOID address3 = LPVOID(PatternScan(processHandle, hackProBase, hackProInfo.SizeOfImage, "74 ? 66 c7 45 ? ? ? 8d 45"));
    WriteBytesToProcess(processHandle, address3, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90});

    printf("Cheat Indicator successfully bypassed!\n");

    Sleep(3000);

    return 0;
}
