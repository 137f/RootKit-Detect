#include "includes.h"
#include <handleapi.h>
#include <heapapi.h>
#include <winnt.h>
#include <wow64apiset.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

int parse_disk_ntdll64(void** ntdll_text_buffer, int* virt_size) {
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file.\n");
        return 1;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0) {
        printf("Could not create file mapping.\n");
        goto disk64_parse_exit0;
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == 0) {
        printf("Could not map view of file.\n");
        goto disk64_parse_exit1;
    }

    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file.\n");
        goto disk64_parse_exit2;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpFileBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file.\n");
        goto disk64_parse_exit2;
    }

    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;
        i++, sectionHeader++) {
        if (strncmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            *virt_size = sectionHeader->Misc.VirtualSize;
            *ntdll_text_buffer =
                HeapAlloc(GetProcessHeap(), 0, sectionHeader->SizeOfRawData);
            if (*ntdll_text_buffer) {
                memcpy(
                    *ntdll_text_buffer,
                    (LPVOID)((DWORD_PTR)lpFileBase + sectionHeader->PointerToRawData),
                    sectionHeader->SizeOfRawData);
            }
        }
    }
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return 0;
disk64_parse_exit2:
    UnmapViewOfFile(lpFileBase);
disk64_parse_exit1:
    CloseHandle(hFileMapping);
disk64_parse_exit0:
    CloseHandle(hFile);
    return 1;
}

int parse_disk_ntdll32(void** ntdll_text_buffer, int* virt_size,
    DWORD* base_addr) {
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS32 ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    hFile = CreateFile("C:\\Windows\\SysWOW64\\ntdll.dll", GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file.\n");
        return 1;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0) {
        printf("Could not create file mapping.\n");
        goto disk32_parse_exit0;
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == 0) {
        printf("Could not map view of file.\n");
        goto disk32_parse_exit1;
    }

    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file.\n");
        goto disk32_parse_exit2;
    }

    ntHeaders =
        (PIMAGE_NT_HEADERS32)((DWORD_PTR)lpFileBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file.\n");
        goto disk32_parse_exit2;
    }
    *base_addr = ntHeaders->OptionalHeader.ImageBase;

    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;
        i++, sectionHeader++) {
        if (strncmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            *virt_size = sectionHeader->Misc.VirtualSize;
            *base_addr += sectionHeader->VirtualAddress;
            *ntdll_text_buffer =
                HeapAlloc(GetProcessHeap(), 0, sectionHeader->SizeOfRawData);
            if (*ntdll_text_buffer) {
                memcpy(
                    *ntdll_text_buffer,
                    (LPVOID)((DWORD_PTR)lpFileBase + sectionHeader->PointerToRawData),
                    sectionHeader->SizeOfRawData);
            }
        }
    }
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return 0;
disk32_parse_exit2:
    UnmapViewOfFile(lpFileBase);
disk32_parse_exit1:
    CloseHandle(hFileMapping);
disk32_parse_exit0:
    CloseHandle(hFile);
    return 1;
}

BOOL Get32BitNtdllBaseAddress(HANDLE hProcess, LPVOID* baseAddress) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded,
        LIST_MODULES_32BIT)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(WCHAR))) {
                if (_wcsicmp(szModName, L"ntdll.dll") == 0) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo,
                        sizeof(modInfo))) {
                        *baseAddress = modInfo.lpBaseOfDll;
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

int parse_process_ntdll32(HANDLE _hProcess, void** virt_address_text,
    int* virt_size, DWORD pid, DWORD* base_virt_addr) {

    LPVOID ntdllModuleHandle = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS32 ntHeaders = NULL;
    IMAGE_SECTION_HEADER* sectionHeaders = NULL;
    SIZE_T bytes_read = 0;

    *virt_address_text = NULL;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("Invalid handle value: %lu\n", GetLastError());
        goto process32_parse_exit;
    }
    dosHeader = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_DOS_HEADER));
    ntHeaders = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_NT_HEADERS32));
    if (!Get32BitNtdllBaseAddress(_hProcess, &ntdllModuleHandle)) {
        printf("Failed to get base address of the 32 bit ntdll.dll\n");
        goto process32_parse_exit;
    }

    if (!ntdllModuleHandle) {
        printf("ntdll.dll is not loaded in the current process.\n");
        goto process32_parse_exit;
    }

    if (!ReadProcessMemory(hProcess, ntdllModuleHandle, dosHeader,
        sizeof(IMAGE_DOS_HEADER), &bytes_read)) {
        printf("Failed to read the DOS header or invalid DOS signature.\n");
        printf("Error: %lu\n", GetLastError());
        goto process32_parse_exit;
    }
    if (!ReadProcessMemory(hProcess, ntdllModuleHandle, dosHeader,
        sizeof(IMAGE_DOS_HEADER), &bytes_read) ||
        dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Failed to read the DOS header or not a valid DOS signature.\n");
        goto process32_parse_exit;
    }

    LPVOID ntHeadersAddress = (LPBYTE)ntdllModuleHandle + dosHeader->e_lfanew;
    if (!ReadProcessMemory(hProcess, ntHeadersAddress, ntHeaders,
        sizeof(IMAGE_NT_HEADERS32), &bytes_read) ||
        ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Failed to read NT headers or invalid PE signature.\n");
        goto process32_parse_exit;
    }

    sectionHeaders = (IMAGE_SECTION_HEADER*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY,
        ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (!sectionHeaders) {
        printf("Could not allocate memory for section headers.\n");
        goto process32_parse_exit;
    }

    LPVOID sectionHeadersAddress = (LPBYTE)ntHeadersAddress + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        ntHeaders->FileHeader.SizeOfOptionalHeader;
    if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders,
        ntHeaders->FileHeader.NumberOfSections *
        sizeof(IMAGE_SECTION_HEADER),
        &bytes_read)) {
        printf("Failed to read section headers.\n");
        goto process32_parse_exit;
    }

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sectionHeaders[i].Name, ".text",
            IMAGE_SIZEOF_SHORT_NAME) == 0) {
            LPVOID sectionAddress =
                (LPBYTE)ntdllModuleHandle + sectionHeaders[i].VirtualAddress;
            *base_virt_addr = (DWORD)sectionAddress;
            *virt_size = sectionHeaders[i].Misc.VirtualSize;
            *virt_address_text =
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *virt_size);

            if (!*virt_address_text) {
                printf("Failed to allocate buffer for the .text section.\n");
                goto process32_parse_exit;
            }

            if (!ReadProcessMemory(hProcess, sectionAddress, *virt_address_text,
                *virt_size, &bytes_read)) {
                printf("Failed to read the .text section.\n");
                goto process32_parse_exit;
            }
            CloseHandle(hProcess);
            HeapFree(GetProcessHeap(), 0, sectionHeaders);
            return 0;
        }
    }

process32_parse_exit:
    if (sectionHeaders) {
        HeapFree(GetProcessHeap(), 0, sectionHeaders);
    }
    if (*virt_address_text) {
        HeapFree(GetProcessHeap(), 0, *virt_address_text);
        *virt_address_text = NULL;
    }
    if (dosHeader) {
        HeapFree(GetProcessHeap(), 0, dosHeader);
    }
    if (ntHeaders) {
        HeapFree(GetProcessHeap(), 0, ntHeaders);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }
    return 1;
}

int main() {
    void* stock_text32;
    void* stock_text64;
    int stock_size32;
    int stock_size64;
    DWORD base_addr32;
    parse_disk_ntdll64(&stock_text64, &stock_size64);
    parse_disk_ntdll32(&stock_text32, &stock_size32, &base_addr32);
    printf("Disk parse OK\n");
    return 0;
}
