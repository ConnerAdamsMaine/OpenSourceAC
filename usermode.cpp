#include <windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <intrin.h>

#define DEVICE_SYMLINK L"\\\\.\\HyperionAntiCheat"

#define IOCTL_ANTICHEAT_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_ANTICHEAT_ENCRYPTED_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

static BYTE gKey[32] = {0}; // Must match kernel key, securely loaded in production
static BYTE gIV[12] = {0};  // Initialization vector for AES GCM

// Utility function: Print error messages
void PrintLastError(const char* msg) {
    DWORD err = GetLastError();
    LPVOID lpMsgBuf;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
    std::cerr << msg << ": " << (LPSTR)lpMsgBuf << std::endl;
    LocalFree(lpMsgBuf);
}

// AES-GCM encrypt placeholder using Windows CNG (simplified)
// In real scenario, synchronize keys securely with driver
bool AESEncrypt(const BYTE* plaintext, DWORD plaintextLen, std::vector<BYTE>& ciphertext)
{
    // Placeholder - do real encryption here
    ciphertext.assign(plaintext, plaintext + plaintextLen);
    return true;
}

// AES-GCM decrypt placeholder
bool AESDecrypt(const BYTE* ciphertext, DWORD ciphertextLen, std::vector<BYTE>& plaintext)
{
    // Placeholder - do real decryption here
    plaintext.assign(ciphertext, ciphertext + ciphertextLen);
    return true;
}

// Open handle to anti-cheat driver device
HANDLE OpenAntiCheatDevice()
{
    HANDLE hDevice = CreateFileW(DEVICE_SYMLINK, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        PrintLastError("Failed to open device");
        return NULL;
    }
    return hDevice;
}

// Query hypervisor detection from driver
bool QueryHypervisorPresence(HANDLE hDevice)
{
    BOOLEAN hvDetected = FALSE;
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(hDevice, IOCTL_ANTICHEAT_QUERY, NULL, 0, &hvDetected, sizeof(hvDetected), &bytesReturned, NULL);
    if (!result || bytesReturned != sizeof(hvDetected))
    {
        PrintLastError("Failed to query hypervisor presence");
        return false;
    }
    return hvDetected ? true : false;
}

// Send encrypted command to driver and receive encrypted response
bool SendEncryptedCommand(HANDLE hDevice, const std::string& cmd, std::string& response)
{
    std::vector<BYTE> encryptedCmd;
    if (!AESEncrypt(reinterpret_cast<const BYTE*>(cmd.data()), (DWORD)cmd.size(), encryptedCmd))
    {
        std::cerr << "Encryption failed\n";
        return false;
    }

    // Prepare input buffer: [DWORD ciphertextLen][ciphertext]
    DWORD inputSize = sizeof(DWORD) + (DWORD)encryptedCmd.size();
    std::vector<BYTE> inputBuffer(inputSize);
    memcpy(inputBuffer.data(), &encryptedCmd.size(), sizeof(DWORD));
    memcpy(inputBuffer.data() + sizeof(DWORD), encryptedCmd.data(), encryptedCmd.size());

    // Output buffer to hold encrypted response (size arbitrarily large)
    std::vector<BYTE> outputBuffer(1024);
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(hDevice, IOCTL_ANTICHEAT_ENCRYPTED_COMMAND,
        inputBuffer.data(), inputSize, outputBuffer.data(), (DWORD)outputBuffer.size(),
        &bytesReturned, NULL);

    if (!result)
    {
        PrintLastError("DeviceIoControl failed");
        return false;
    }

    if (bytesReturned < sizeof(DWORD))
    {
        std::cerr << "Invalid response length\n";
        return false;
    }

    DWORD responseLen = *(DWORD*)outputBuffer.data();
    if (responseLen + sizeof(DWORD) != bytesReturned)
    {
        std::cerr << "Response length mismatch\n";
        return false;
    }

    std::vector<BYTE> decryptedResponse;
    if (!AESDecrypt(outputBuffer.data() + sizeof(DWORD), responseLen, decryptedResponse))
    {
        std::cerr << "Decryption failed\n";
        return false;
    }

    response.assign(reinterpret_cast<char*>(decryptedResponse.data()), decryptedResponse.size());
    return true;
}

// Enumerate all threads of a process and detect suspicious thread start addresses
bool DetectThreadInjection(DWORD pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintLastError("CreateToolhelp32Snapshot failed");
        return false;
    }

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(THREADENTRY32);
    bool suspiciousFound = false;

    if (Thread32First(hSnapshot, &te))
    {
        do {
            if (te.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    // Query thread start address (Windows 7+)
                    PVOID startAddress = NULL;
                    typedef BOOL(WINAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                    static NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
                    if (NtQueryInformationThread)
                    {
                        ULONG retLen = 0;
                        struct THREAD_BASIC_INFORMATION {
                            PVOID ExitStatus;
                            PVOID TebBaseAddress;
                            PVOID ProcessEnvironmentBlock;
                            PVOID StartAddress;
                            ULONG_PTR AffinityMask;
                            LONG Priority;
                            LONG BasePriority;
                        } tbi;

                        if (NtQueryInformationThread(hThread, 9 /*ThreadQuerySetWin32StartAddress*/, &startAddress, sizeof(PVOID), &retLen) == 0)
                        {
                            // You can add checks here, e.g., startAddress not in module ranges, suspicious DLLs, etc.
                            // For demonstration, flag if startAddress is NULL or in suspicious range

                            if (startAddress == NULL)
                            {
                                suspiciousFound = true;
                                std::cout << "Suspicious thread " << te.th32ThreadID << " with NULL start address\n";
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return suspiciousFound;
}

// Hypervisor detection fallback user mode (CPUID)
bool DetectHypervisorUserMode()
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

// Main monitoring loop
void MonitoringLoop(HANDLE hDevice, DWORD targetPid)
{
    while (true)
    {
        // Check hypervisor presence
        bool hvPresent = QueryHypervisorPresence(hDevice);
        if (!hvPresent) {
            // Fallback user mode detection
            hvPresent = DetectHypervisorUserMode();
        }

        if (hvPresent) {
            std::cout << "[Warning] Hypervisor detected on system!\n";
        }

        // Thread injection detection
        if (DetectThreadInjection(targetPid))
        {
            std::cout << "[Warning] Potential thread injection detected in process " << targetPid << "\n";
        }

        // Send encrypted heartbeat to driver
        std::string response;
        if (!SendEncryptedCommand(hDevice, "Heartbeat", response))
        {
            std::cerr << "Failed to send heartbeat to driver\n";
        }
        else
        {
            std::cout << "Driver response: " << response << std::endl;
        }

        Sleep(5000); // 5 seconds interval
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: UserModeAntiCheat.exe <target_pid>\n";
        return 1;
    }

    DWORD targetPid = atoi(argv[1]);
    if (targetPid == 0)
    {
        std::cerr << "Invalid target PID\n";
        return 1;
    }

    HANDLE hDevice = OpenAntiCheatDevice();
    if (!hDevice)
    {
        return 1;
    }

    std::cout << "Starting monitoring loop for process " << targetPid << std::endl;

    MonitoringLoop(hDevice, targetPid);

    CloseHandle(hDevice);
    return 0;
}