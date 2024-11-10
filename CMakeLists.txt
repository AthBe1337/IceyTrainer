cmake_minimum_required(VERSION 3.29)
project(IceyTrainer)

set(CMAKE_CXX_STANDARD 20)

add_executable(IceyTrainer main.cpp
        cheat/trainer.cpp
        cheat/trainer.h)

target_include_directories(IceyTrainer PRIVATE cheat)