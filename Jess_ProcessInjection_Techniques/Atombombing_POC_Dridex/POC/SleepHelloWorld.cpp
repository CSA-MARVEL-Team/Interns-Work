#include <Windows.h>
#include <iostream>

int main(){
    char buffer[64];
    SleepEx(100000,true);
    std::cout << "Sleep Done!" << std::endl;
    std::cin >> buffer;
    MessageBoxA(NULL,buffer,"hello world",0);
}