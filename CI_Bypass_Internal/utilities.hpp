#include <Windows.h>
#include <vector>
#include <iostream>
#include <Psapi.h>
#include <string>

uintptr_t PatternScan(uintptr_t base, uintptr_t scanSize, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern)
    {
        std::vector<char> bytes;
        char* start = const_cast<char*>(pattern);
        char* end = const_cast<char*>(pattern) + strlen(pattern);

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
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(base), buffer.data(), scanSize, &bytesRead))
        return 0;

    for (uintptr_t i = 0; i < scanSize - patternLength; i++)
    {
        bool found = true;
        for (uintptr_t j = 0; j < patternLength; j++)
        {
            found &= data[j] == '\?' || data[j] == *(reinterpret_cast<char*>(buffer.data() + i + j));
        }
        if (found)
        {
            return base + i;
        }
    }
    return 0;
}

void WriteBytesToProcess(uintptr_t address, std::vector<uint8_t> const bytes)
{
    DWORD oldProtect;
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)address, bytes.data(), bytes.size(), NULL);
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)address, bytes.size(), oldProtect, &oldProtect);
}