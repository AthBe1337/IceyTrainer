//
// Created by athbe on 2024/11/10.
//

#ifndef TRAINER_H
#define TRAINER_H

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <atomic>
#include <thread>

class trainer {
private:
    std::atomic<bool> setHP = false;
    LPVOID health_addr = nullptr;
    LPVOID money_addr = nullptr;
    DWORD process_id = 0;
    HANDLE process_handle = nullptr;

    static DWORD get_process_id(const char* process_name);
    static HANDLE open_process(DWORD process_id);
    static void close_handle(HANDLE handle);
    bool set_health(LPVOID health_addr, int health);
    bool set_money(int money);
    void get_health_addr(uintptr_t startAddr, uintptr_t endAddr);
public:
    void initialize();
    void set_health_C(int health);
    void start_cheat();

};



#endif //TRAINER_H
