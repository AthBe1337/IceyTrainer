//
// Created by athbe on 2024/11/10.
//

#include "trainer.h"

DWORD trainer::get_process_id(const char* process_name) {
    DWORD process_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            if (!strcmp(process_entry.szExeFile, process_name)) {
                process_id = process_entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    if(process_id == 0) {
        throw std::runtime_error("Failed to get process id");
    }
    CloseHandle(snapshot);
    return process_id;
}

HANDLE trainer::open_process(DWORD process_id) {
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if(process_handle == nullptr) {
        throw std::runtime_error("Failed to open process");
    }
    return process_handle;
}

void trainer::close_handle(HANDLE handle) {
    CloseHandle(handle);
}

bool trainer::set_health(LPVOID health_address, int health) {

    int sp = 5;
    if(WriteProcessMemory(process_handle, health_address, &health, sizeof(health), 0) &&
        WriteProcessMemory(process_handle, (LPVOID)((uintptr_t)health_address + (uintptr_t)0x14), &sp, sizeof(sp), 0)) {
        return true;
    }


    throw std::runtime_error("Failed to write process memory");
    return false;
}

bool trainer::set_money(int money) {
    LPVOID money_address = (LPVOID)0x5FD27660;

    if(WriteProcessMemory(process_handle, money_address, &money, sizeof(money), nullptr)) {
        return true;
    }
    throw std::runtime_error("Failed to write process memory");
    return false;
}

void trainer::set_health_C(int health) {
    while(setHP) {
        set_health(health_addr, health);
        Sleep(10);
    }
}

void trainer::get_health_addr(uintptr_t startAddr, uintptr_t endAddr) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    const char* pattern = "\x00\x00\x00\x00\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x41";
    size_t pattern_size = 18;
    const char* mask = "\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

    MEMORY_BASIC_INFORMATION mbi;

    while (startAddr < endAddr) {
        if (VirtualQueryEx(process_handle, (LPVOID)startAddr, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // 跳过非可访问内存区域
        if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && ((mbi.Protect & PAGE_NOACCESS) == 0)) {

            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(process_handle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - pattern_size; i++) {
                    bool found = true;

                    // 按照掩码检查特征码匹配
                    for (size_t j = 0; j < pattern_size; j++) {
                        if ((mask[j] == 0xFF && buffer[i + j] != pattern[j]) ||
                            (mask[j] != 0xFF && (buffer[i + j] & mask[j]) != (pattern[j] & mask[j]))) {
                            found = false;
                            break;
                            }
                    }

                    // 如果找到了匹配，保存地址并返回
                    if (found) {
                        health_addr = (LPVOID)((uintptr_t)mbi.BaseAddress + i);
                        return; // 找到后退出
                    }
                }
            }
        }

        startAddr += mbi.RegionSize;
    }
}

void trainer::get_health_addr_P(LPVOID pointer, std::vector<LPVOID> offset_list, int index) {
    if(index >= offset_list.size()) {
        health_addr = pointer;
        return;
    }
    ReadProcessMemory(process_handle, pointer, &pointer, sizeof(pointer), nullptr);
    pointer = (LPVOID)((uintptr_t)pointer + (uintptr_t)offset_list[index]);
    get_health_addr_P(pointer, offset_list, index+1);
}

void trainer::initialize() {
    std::cout << "Initializing..." << std::endl;

    // 获取目标进程 ID
    while (!process_id) {
        try {
            process_id = get_process_id("ICEY.exe");
        } catch (std::runtime_error& e) {
            std::cout << e.what() << std::endl;
            Sleep(1000);
        }
    }

    // 打开进程句柄
    while (!process_handle) {
        try {
            process_handle = open_process(process_id);
        } catch (std::runtime_error& e) {
            std::cout << e.what() << std::endl;
            Sleep(1000);
        }
    }

    /*
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t startAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t endAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    size_t numThreads = 16; // 设定线程数
    size_t rangeSize = (endAddr - startAddr) / numThreads;

    std::vector<std::thread> threads;

    // 启动多个线程，每个线程扫描不同的内存区间
    for (size_t i = 0; i < numThreads; i++) {
        uintptr_t threadStartAddr = startAddr + i * rangeSize;
        uintptr_t threadEndAddr = (i == numThreads - 1) ? endAddr : threadStartAddr + rangeSize;

        threads.push_back(std::thread([this, threadStartAddr, threadEndAddr]() {
            get_health_addr(threadStartAddr, threadEndAddr);
        }));
    }

    // 等待所有线程完成
    for (auto& t : threads) {
        t.join();
    }
    */

    std::vector<LPVOID> offset_list;
    offset_list.push_back((LPVOID)0x38);
    offset_list.push_back((LPVOID)0x478);
    offset_list.push_back((LPVOID)0x128);
    offset_list.push_back((LPVOID)0x58);
    offset_list.push_back((LPVOID)0x318);
    offset_list.push_back((LPVOID)0xB0);
    offset_list.push_back((LPVOID)0x160);

    LPVOID pointer = (LPVOID)(0x7FF7EC6C0000+0x012EC560);

    get_health_addr_P(pointer, offset_list, 0);

    if (health_addr != nullptr) {
        std::cout << "Found health address: " << health_addr << std::endl;
    } else {
        std::cout << "Health address not found." << std::endl;
    }
}


void trainer::start_cheat() {
    initialize();

    std::cout << "Starting cheat..." << std::endl;

    try {
        set_money(999);
    } catch (std::runtime_error& e) {
        std::cout << e.what() << std::endl;
    }

    setHP = true;
    std::thread health_thread(&trainer::set_health_C, this, 250);

    std::string command;
    std::cout << "Enter 'exit' to stop the cheat" << std::endl;
    while(std::cin >> command) {
        if(command == "exit") {
            setHP = false;
            health_thread.join();
            break;
        }
    }
}
