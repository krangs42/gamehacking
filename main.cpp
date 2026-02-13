#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>

DWORD GetProcId(const wchar_t* name)
{
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (!_wcsicmp(pe.szExeFile, name))
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName)
{
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snap == INVALID_HANDLE_VALUE) return 0;

    uintptr_t base = 0;
    if (Module32FirstW(snap, &me))
    {
        do {
            if (!_wcsicmp(me.szModule, modName))
            {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

uintptr_t FindDMA(HANDLE hProc, uintptr_t base, std::vector<uintptr_t> offsets)
{
    uintptr_t addr = base;
    for (auto off : offsets)
    {
        if (!ReadProcessMemory(hProc, (LPCVOID)addr, &addr, sizeof(addr), nullptr))
            return 0;
        addr += off;
    }
    return addr;
}

int main()
{
    AllocConsole();
  

    std::wcout << L"Basladi\n";

    DWORD pid = GetProcId(L"DurumleGGJ2.exe");
    if (!pid)
    {
        std::cout << "PID bulunamadi\n";
        Sleep(3000);
        return 0;
    }

    uintptr_t modBase = GetModuleBase(pid, L"DurumleGGJ2.exe");
    if (!modBase)
    {
        std::cout << "Module base bulunamadi\n";
        Sleep(3000);
        return 0;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        std::cout << "OpenProcess fail\n";
        Sleep(3000);
        return 0;
    }

    uintptr_t basePtr = modBase + 0x12695B18;
    std::vector<uintptr_t> offsets = { 0xD0, 0xC8, 0x698, 0xC8 };

    uintptr_t healthAddr = FindDMA(hProc, basePtr, offsets);
    if (!healthAddr)
    {
        std::cout << "Health adresi cozulemedi\n";
        Sleep(3000);
        return 0;
    }

    std::cout << "Health addr OK: 0x" << std::hex << healthAddr << std::endl;
    std::cout << "Health kilitlendi\n";

    double health = 99999.0;

    // ---- KILIT DONGUSU ----
    while (true)
    {
        WriteProcessMemory(
            hProc,
            (LPVOID)healthAddr,
            &health,
            sizeof(double),
            nullptr
        );
        Sleep(10);
    }
}
