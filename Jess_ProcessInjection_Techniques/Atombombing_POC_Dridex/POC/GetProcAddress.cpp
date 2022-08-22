#include <stdio.h>
#include <windows.h>
#include <ntdef.h>

using func_LdrLoadDll = NTSYSAPI
    NTSTATUS
    (NTAPI*)(

        PWCHAR PathToFile OPTIONAL,
        ULONG Flags OPTIONAL,
        PUNICODE_STRING ModuleFileName,
        HMODULE* ModuleHandle);

using func_RtlInitUnicodeString = NTSYSAPI VOID (NTAPI*)(
  PUNICODE_STRING         DestinationString,
  PCWSTR SourceString
);

using func_MessageBoxA = WINUSERAPI int (WINAPI*) (HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);

void RtlInitUnicodeString(PUNICODE_STRING         DestinationString,
  PWSTR SourceString,size_t Size)
{
 
     if (SourceString)
     {
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(wchar_t);
     }
     else
     {
         DestinationString->Length = 0;
         DestinationString->MaximumLength = 0;
     }
 
     DestinationString->Buffer = SourceString;
     return;
 
 }

long long getHashFromString(char *func_name)
{
    unsigned long long hash = 12;
    int count = 0;
    while (func_name[count] != 0)
    {
        hash += (hash * 0xe31feaa3642a189d + func_name[count]) & 0xffffffffffffff;
        count++;
    }
    return hash;
}

PDWORD getProcAddress(HMODULE libraryBase, char *func_name)
{
    PDWORD functionAddress = (PDWORD)0;
    long long hash = getHashFromString(func_name);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    // Get RVAs to exported function related information
    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);
        // Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
        // If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
    {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char *functionName = (char *)functionNameVA;
        DWORD_PTR functionAddressRVA = 0;
        // Calculate hash for this exported function
        long long functionNameHash = getHashFromString(functionName);
        // If hash for CreateThread is found, resolve the function address
        if (functionNameHash == hash)
        {
            functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            return functionAddress;
        }
    }
}

int main()
{
    void *ret = __builtin_return_address(0);
    ret = (long long)ret & ~0xffff;
    long long mod = (long long)ret;
    while (((int *)mod)[0] != 0x00905a4d)
    {
        mod -= 0x4000;
    }
    UNICODE_STRING string;
    byte rtlinitString[] = {0x52,0x74,0x6C,0x49,0x6E,0x69,0x74,0x55,0x6E,0x69,0x63,0x6F,0x64,0x65,0x53,0x74,0x72,0x69,0x6E,0x67};
    func_RtlInitUnicodeString RtlInitUnicodeStringg = (func_RtlInitUnicodeString) getProcAddress((HMODULE)mod,(char*)rtlinitString);
    byte kernel[] = {0X55,0X00,0X73,0X00,0X65,0X00,0X72,0X00,0X33,0X00,0X32,0X00,0x00,0x00};
    RtlInitUnicodeString(&string,(PWSTR)kernel,12);
    byte ldr[] = {0x4C ,0X64 ,0X72 ,0X4C,0X6F ,0X61 ,0X64 ,0X44 ,0X6C ,0X6C,0x00};
    func_LdrLoadDll LdrLoadDll = (func_LdrLoadDll)getProcAddress((HMODULE)mod,(char*)ldr);
    HMODULE kernel32;
    LdrLoadDll(NULL,NULL,&string,&kernel32);
    byte messagebox[] = {0x4D ,0X65 ,0X73 ,0X73 ,0X61 ,0X67 ,0X65 ,0X42 ,0X6F ,0X78 ,0X41,0x00};
    func_MessageBoxA MessageBoxA = (func_MessageBoxA)getProcAddress(kernel32,(char*)messagebox);
    byte die[] = {0x44 ,0X49 ,0X45,0x00};
    byte diedie[] = {0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x44 ,0X49 ,0X45,0x00};
    MessageBoxA(NULL,(char*)diedie,(char*)die,0);
    return 0;
}
