#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <iostream>

DWORD GetPIDByName(std::string processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_stricmp(entry.szExeFile, processName.c_str()) == 0) {
            DWORD processId = entry.th32ProcessID;
            CloseHandle(snapshot);
            return processId;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

MODULEINFO GetModule(HANDLE processHandle, const char* moduleName) {
    if (processHandle != NULL) {
        HMODULE moduleHandles[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(processHandle, moduleHandles, sizeof(moduleHandles), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char moduleNameBuffer[MAX_PATH];
                if (GetModuleBaseNameA(processHandle, moduleHandles[i], moduleNameBuffer, sizeof(moduleNameBuffer) / sizeof(char))) {
                    if (_stricmp(moduleNameBuffer, moduleName) == 0) {
                        MODULEINFO moduleInfo;
                        if (GetModuleInformation(processHandle, moduleHandles[i], &moduleInfo, sizeof(moduleInfo))) {
                            return moduleInfo;
                        }
                    }
                }
            }
        }
    }
    return MODULEINFO{};
}

uintptr_t PatternScan(HANDLE processHandle, uintptr_t base, uintptr_t scanSize, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern)
    {
        auto bytes = std::vector<char>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back('\?');
            }
            else
            {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto patternBytes = pattern_to_byte(signature);

    uintptr_t patternLength = patternBytes.size();
    auto data = patternBytes.data();

    std::vector<char> buffer(scanSize);

    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(base), buffer.data(), scanSize, &bytesRead))
    {
        return 0;
    }

    for (uintptr_t i = 0; i < scanSize - patternLength; i++)
    {
        bool found = true;
        for (uintptr_t j = 0; j < patternLength; j++)
        {
            char a = '\?';
            char b = *(reinterpret_cast<char*>(buffer.data() + i + j));
            found &= data[j] == a || data[j] == b;
        }
        if (found)
        {
            return base + i;
        }
    }
    return 0;
}

void WriteBytesToProcess(HANDLE processHandle, LPVOID address, std::vector<uint8_t> const bytes)
{
    DWORD oldProtect;
    VirtualProtectEx(processHandle, address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(processHandle, address, bytes.data(), bytes.size(), NULL);
    VirtualProtectEx(processHandle, address, bytes.size(), oldProtect, &oldProtect);
}