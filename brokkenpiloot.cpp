/* Brokkenpiloot.cpp: Brokkenpiloot is a tool that can replace bytes in the
                      virtual memory (including the code segment) of a
                      running Windows process with the intention of modifying
                      its behaviour.

                      Brokkenpiloot modifies the target process in-memory.
                      This means it does not harm the target binary on the
                      disk. This is also what allows Brokkenpiloot to turn
                      the patch on and off without relaunching the target
                      binary.

                      ===
                      HISTORY

                      Brokkenpiloot was written in 2019 as a proof-of-concept
                      tool that disabled presence checking in Fly UK's
                      Skytrack logging software for Prepar3d and X-Plane.

                      The virtual airline Fly UK requires flightsimmers to log
                      all their FlyUK flights with Skytrack, a software tool
                      which automatically records flight details such as
                      departure and arrival times, position data and fuel
                      consumption. On longer flights (2+ hours), Skytrack checks
                      to make sure virtual pilots are at their desks during the
                      whole flight by asking them to tune the aircraft
                      communication radios to a random frequency every 1-3 hours.

                      Brokkenpiloot disabled these checks by modifying a single
                      byte in the skytrack.exe process at the machine code level,
                      such that Skytrack would accept rather than reject incorrect
                      frequencies programmed in the radios. Because Brokkenpiloot
                      reversed Skytrack's checking logic, this also meant the
                      correct frequency would be rejected by Skytrack if both
                      radios accidentally happen to be tuned to it. The
                      statistical chance of this happening is small: around 1.2%
                      for an 18-hour flight and 0.6% for a 9-hour flight. This
                      risk could be eliminated entirely by making sure the
                      communication radios were not tuned to the same frequency.

                      Brokkenpiloot was written as an exercise in learning how to
                      reverse engineer Windows applications with IDA Free. As the
                      name "Brokkenpiloot" implies, using it in the real (virtual)
                      world would be questionable. The TARGET_BYTES and
                      REPLACEMENT_BYTES below have been changed to prevent any
                      actual use.

*/

#define DEBUG

#define TARGET_APP        "Fly UK SkyTrack"
#define TARGET_BYTES      "\x44\x32\x18\x23\x84\x1D\xFF\x00\x00\x0F\x27\x68\xFF\x84\x14\x19\x0E\x00"
#define REPLACEMENT_BYTES "\x44\x32\x18\x23\x85\x1D\xFF\x00\x00\x0F\x27\x68\xFF\x85\x14\x19\x0E\x00"

#include <iostream>
#include <vector> 
#include <olectl.h>
#include <Psapi.h>

// Class TargetModule contains all the properties and methods
// that we want TARGET_APP's Windows process module to deal with
//
class TargetModule {
public:
    char name[201] = { NULL };
    MODULEINFO info;
    byte* memory = NULL;
    DWORD memory_size = 0;

    BOOL LoadMemory(HANDLE p_handle) {
        memory = new byte[info.SizeOfImage];
        if (!ReadProcessMemory(p_handle, info.lpBaseOfDll, memory, info.SizeOfImage, &memory_size)) {
            CloseHandle(p_handle);
            exit(100);
        }
        return TRUE;
    }

    BOOL SearchMemory(byte* bytes_to_search, DWORD query_length, DWORD* offset) {
        DWORD matches = 0;
        for (DWORD i = 0; i < memory_size; i++) {
            for (DWORD j = 0; j < query_length; j++) {
                if (memory[i + j] == bytes_to_search[j]) {
                    if (j == query_length - 1) {
                        *offset = i;
#ifdef DEBUG
                        printf("Match at 0x%08X (offset from module base address: 0x%08X)\n",
                            *offset + (DWORD)info.lpBaseOfDll, *offset);
#endif
                        matches++;
                    }
                }
                else {
                    break;
                }
            }
        }
        if (matches < 1) {
            return FALSE;
        }
        else if (matches > 1) {
#ifdef DEBUG
            std::cout << "Error: Target bytestring found more than once in target module.\n";
#endif
            return FALSE;
        }
        return TRUE;
    }

    BOOL ReplaceMemory(HANDLE p_handle, DWORD offset, byte* buffer, DWORD query_length) {
        DWORD old_protect = NULL;
        if (!VirtualProtectEx(p_handle, (DWORD*)offset, query_length, PAGE_EXECUTE_READWRITE, &old_protect)) {
            CloseHandle(p_handle);
            exit(200);
        }

        DWORD bytes_written = 0;
        if (!WriteProcessMemory(p_handle, (DWORD*)offset, buffer, query_length, &bytes_written)) {
            CloseHandle(p_handle);
            exit(300);
        }

        if (!VirtualProtectEx(p_handle, (DWORD*)offset, query_length, old_protect, &old_protect)) {
            CloseHandle(p_handle);
            exit(400);
        }

        if (!FlushInstructionCache(p_handle, NULL, NULL)) {
            CloseHandle(p_handle);
            exit(500);
        }

        return TRUE;
    }

    // Destructor
    ~TargetModule() {
        delete[] memory;
    }
};

// Class TargetProcess contains all the properties and methods we want
// TARGET_APP's Windows process to deal with
//
class TargetProcess {
public:
    HWND window_handle;
    DWORD pid;
    HANDLE process_handle;
    char full_image_name[201] = { NULL };
    char* image_name = NULL;

    // Constructor
    TargetProcess(char* window_name) {
        window_handle = FindWindowA(NULL, window_name);
        if (!window_handle) {
            exit(600);
        }
        GetWindowThreadProcessId(window_handle, &pid);
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!process_handle) {
            exit(700);
        }
        if (!GetProcessImageFileNameA(process_handle, full_image_name, 200)) {
            CloseHandle(process_handle);
            exit(800);
        }

        image_name = strrchr(full_image_name, '\\') + 1; // remove full path
        if (!image_name) {
            CloseHandle(process_handle);
            exit(900);
        }
    }

    BOOL GrabModuleInfo(char* module_name, TargetModule* module_p) {
        HMODULE modules[1024] = { NULL };
        DWORD bytes_read = 0;
        if (!EnumProcessModules(process_handle, modules, sizeof(modules), &bytes_read)) {
            CloseHandle(process_handle);
            exit(900);
        }
        for (DWORD i = 0; i < bytes_read; i++) {
            if (!GetModuleBaseNameA(process_handle, modules[i], module_p->name, sizeof(module_p->name))) {
                CloseHandle(process_handle);
                exit(1000);
            }
            if (strncmp(image_name, module_p->name, strlen(image_name)) == 0) {
                if (!GetModuleInformation(process_handle, modules[i], &module_p->info, sizeof(MODULEINFO))) {
                    CloseHandle(process_handle);
                    exit(1100);
                }
                return TRUE;
            }
        }
        return FALSE;
    }

    // Destructor
    ~TargetProcess() {
        if (!CloseHandle(process_handle)) {
            exit(1200);
        }
    }

};

int main()
{
    // Welcome message and promt user for input
    std::cout << "Welcome to Brokkenpiloot! Enter 'q' to quit. Enter any other characters to activate / deactivate the binary patch.\n\n";
    std::cout << "Brokkenpiloot: ";
    char prompt = getchar();
    while (getchar() != '\n'); // discard all user input after the first char

    while (prompt != 'q') {
        char window_name[] = TARGET_APP;

        // Search all Windows processess for the TARGET_APP and return the process handle
        TargetProcess process(window_name);
        TargetModule module;

        // Grab TARGET_APP's module info and assign it to our TargetModule instance
        if (!process.GrabModuleInfo(process.image_name, &module)) {
            CloseHandle(process.process_handle);
            exit(1300);
        }
        // Load TARGET_APP's memory into our TargetModule instance
        if (!module.LoadMemory(process.process_handle)) {
            CloseHandle(process.process_handle);
            exit(1400);
        }


        // Print debugging information
#ifdef DEBUG
        std::cout << "\nPID: " << process.pid << "\n";
        std::cout << "Process image filename: " << process.image_name << "\n";
        std::cout << "Matching module name: " << module.name << "\n";
        std::cout << "Module base address: 0x" << module.info.lpBaseOfDll << "\n";
        std::cout << "Module entry point: 0x" << module.info.EntryPoint << "\n";
        std::cout << "Module size: " << module.info.SizeOfImage << " bytes\n";
        std::cout << "Read bytes: " << module.memory_size << " bytes\n";
        std::cout << "First 16 bytes:";
        for (int j = 0; j < 16; j++) {
            if (j % 8 == 0) {
                std::cout << "\n";
            }
            printf("%02x\t", module.memory[j]);
        }
        std::cout << "\n";
#endif

        // Replace the TARGET_BYTES within TARGET_APP's process memory with REPLACEMENT_BYTES
        byte bytestring_a[] = TARGET_BYTES;
        byte bytestring_b[] = REPLACEMENT_BYTES;
        DWORD query_offset = 0;
        if (module.SearchMemory(bytestring_a, sizeof(bytestring_a) - 1, &query_offset)) {
            if (!module.ReplaceMemory(process.process_handle, (DWORD)module.info.lpBaseOfDll + query_offset, bytestring_b, sizeof(bytestring_a) - 1)) {
                std::cout << "\nError: could not patch the target application.\n\n";
            }
            else {
                std::cout << "\nSuccess: target application patched.\n\n";
            }
        }
        else if (module.SearchMemory(bytestring_b, sizeof(bytestring_b) - 1, &query_offset)) {
            if (!module.ReplaceMemory(process.process_handle, (DWORD)module.info.lpBaseOfDll + query_offset, bytestring_a, sizeof(bytestring_b) - 1)) {
                std::cout << "\nError: could not unpatch target application.\n\n";
            }
            else {
                std::cout << "\nSuccess: unpatched target application.\n\n";
            }
        }
        else {
            std::cout << "\nError: could not patch or unpatch target application.\n\n";
        }

        // Ask user again for input
        std::cout << "Brokkenpiloot: ";
        prompt = getchar();
        while (getchar() != '\n'); // discard all user input after the first char
    }

    return 0;
}