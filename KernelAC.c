#include <ntifs.h>
#include <wdm.h>
#include <windef.h>
#include <intrin.h>
#include <ntimage.h>

#define IOCTL_ANTICHEAT_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_ANTICHEAT_ENCRYPTED_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

UNICODE_STRING gDeviceName = RTL_CONSTANT_STRING(L"\\Device\\HyperionAntiCheat");
UNICODE_STRING gSymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\HyperionAntiCheat");
PDEVICE_OBJECT gDeviceObject = NULL;
PDRIVER_OBJECT gDriverObject = NULL;

typedef struct _CRYPTO_CONTEXT {
    UCHAR Key[32];
    UCHAR IV[12];
    // For simplicity, no replay protection here but can be added
} CRYPTO_CONTEXT;

CRYPTO_CONTEXT gCryptoContext;

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH DispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DispatchDeviceControl;

VOID HideDriver(PDRIVER_OBJECT DriverObject);
VOID RemoveDriverFromModuleLists();
BOOLEAN DetectInlineHooks();
BOOLEAN ScanSSDTHooks();
BOOLEAN ScanVADForRWX(PEPROCESS Process);
VOID ScanDebugRegisters();
BOOLEAN DetectHypervisor();
VOID ProtectDriverMemory(PDRIVER_OBJECT DriverObject);
VOID InitializeCrypto();
NTSTATUS AESEncrypt(const UCHAR* plaintext, ULONG plaintextLen, UCHAR* ciphertext, ULONG* ciphertextLen);
NTSTATUS AESDecrypt(const UCHAR* ciphertext, ULONG ciphertextLen, UCHAR* plaintext, ULONG* plaintextLen);

VOID LogMessage(const char* fmt, ...);

// Simple spinlock for protecting sensitive data
KSPIN_LOCK gSpinLock;

#pragma alloc_text(INIT, DriverEntry)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    gDriverObject = DriverObject;

    status = IoCreateDevice(
        DriverObject,
        0,
        &gDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &gDeviceObject);

    if (!NT_SUCCESS(status)) {
        LogMessage("Failed to create device: 0x%x\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&gSymLinkName, &gDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDeviceObject);
        LogMessage("Failed to create symbolic link: 0x%x\n", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    KeInitializeSpinLock(&gSpinLock);

    HideDriver(DriverObject);
    RemoveDriverFromModuleLists();
    InitializeCrypto();
    ProtectDriverMemory(DriverObject);

    LogMessage("HyperionAntiCheat Driver Loaded\n");

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteSymbolicLink(&gSymLinkName);
    IoDeleteDevice(gDeviceObject);

    LogMessage("HyperionAntiCheat Driver Unloaded\n");
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ANTICHEAT_QUERY:
        {
            // Respond with detection status (simplified)
            BOOLEAN hvDetected = DetectHypervisor();

            if (outputLen >= sizeof(BOOLEAN))
            {
                *(BOOLEAN*)buffer = hvDetected;
                information = sizeof(BOOLEAN);
                status = STATUS_SUCCESS;
            }
        }
        break;

    case IOCTL_ANTICHEAT_ENCRYPTED_COMMAND:
        {
            // Receive encrypted commands, decrypt, process, encrypt response
            // Buffer format: [ciphertextLength][ciphertext]
            if (inputLen < sizeof(ULONG)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            ULONG ciphertextLen = *(ULONG*)buffer;
            if (ciphertextLen + sizeof(ULONG) > inputLen || ciphertextLen > 1024) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            UCHAR* ciphertext = (UCHAR*)buffer + sizeof(ULONG);
            UCHAR plaintext[1024] = {0};
            ULONG plaintextLen = sizeof(plaintext);

            status = AESDecrypt(ciphertext, ciphertextLen, plaintext, &plaintextLen);
            if (!NT_SUCCESS(status)) break;

            // Pseudo: Process plaintext command (e.g. run full scans)
            // Here we just respond with a simple OK encrypted response

            const char* responseStr = "OK";
            UCHAR responseCipher[128] = {0};
            ULONG responseCipherLen = sizeof(responseCipher);

            status = AESEncrypt((const UCHAR*)responseStr, (ULONG)strlen(responseStr), responseCipher, &responseCipherLen);
            if (!NT_SUCCESS(status)) break;

            if (outputLen < sizeof(ULONG) + responseCipherLen) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            *(ULONG*)buffer = responseCipherLen;
            RtlCopyMemory((UCHAR*)buffer + sizeof(ULONG), responseCipher, responseCipherLen);
            information = sizeof(ULONG) + responseCipherLen;
            status = STATUS_SUCCESS;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// Driver hiding removes from PsLoadedModuleList and other kernel module lists
VOID HideDriver(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
        return;

    RemoveDriverFromModuleLists();
    LogMessage("Driver hidden from PsLoadedModuleList and kernel module lists.\n");
}

VOID RemoveDriverFromModuleLists()
{
    // Remove this driver from PsLoadedModuleList and kernel module lists to hide presence
    // This requires locking and manipulating linked lists carefully.

    // For demonstration, we do basic removal here, no locking shown:

    PLIST_ENTRY listEntry = NULL;

    // Remove from PsLoadedModuleList
    listEntry = PsLoadedModuleList.Flink;
    while (listEntry != &PsLoadedModuleList)
    {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->DllBase == (PVOID)gDriverObject->DriverStart)
        {
            RemoveEntryList(&entry->InLoadOrderLinks);
            RemoveEntryList(&entry->InMemoryOrderLinks);
            RemoveEntryList(&entry->InInitializationOrderLinks);
            break;
        }
        listEntry = listEntry->Flink;
    }
}

// Very detailed inline hooking detection
BOOLEAN DetectInlineHooks()
{
    // Check known kernel functions for inline hooks (first bytes do not match expected prologues)
    // Scan SSDT entries and compare with expected function addresses

    // Return TRUE if any hooks found

    BOOLEAN hooked = FALSE;

    hooked |= ScanSSDTHooks();

    // Further inline hooks checks on common API sets can be added here

    return hooked;
}

BOOLEAN ScanSSDTHooks()
{
    // SSDT hooking detection:
    // Walk SSDT and compare entries to expected kernel function addresses

    // Requires Windows internal symbols and version-specific SSDT access

    // Pseudocode placeholder here, returns FALSE for demo

    return FALSE;
}

BOOLEAN ScanVADForRWX(PEPROCESS Process)
{
    // Traverse the VAD tree of the target process looking for any RWX memory regions

    // This is complex and version-specific; simplified demonstration:

    if (!Process)
        return FALSE;

    // Use PsLookupProcessByProcessId and then access VadRoot (internal)

    // Pseudo-code:

    /*
    For each VAD node in Process->VadRoot:
       If Vad->Protection has RWX or Execute + Write flags
          Return TRUE (suspicious)
    */

    return FALSE; // Placeholder
}

VOID ScanDebugRegisters()
{
    // Iterate all threads in system and check debug registers Dr0-Dr3 for breakpoints set

    // Using PsGetNextProcess / PsGetNextThread

    PEPROCESS process = NULL;
    PETHREAD thread = NULL;

    for (process = PsGetNextProcess(NULL); process != NULL; process = PsGetNextProcess(process))
    {
        for (thread = PsGetNextThread(process, NULL); thread != NULL; thread = PsGetNextThread(process, thread))
        {
            CONTEXT context = { 0 };
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (NT_SUCCESS(KeStackAttachProcess(process, &context)))
            {
                if (NT_SUCCESS(KeGetThreadContext(thread, &context)))
                {
                    if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3)
                    {
                        LogMessage("Thread %p in process %p has debug registers set\n", thread, process);
                    }
                }
                KeUnstackDetachProcess(&context);
            }
        }
    }
}

BOOLEAN DetectHypervisor()
{
    int cpuInfo[4] = {0};

    __try
    {
        __cpuid(cpuInfo, 1);
        // Hypervisor bit is 31 in ECX
        if ((cpuInfo[2] & (1 << 31)) != 0)
        {
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    return FALSE;
}

VOID ProtectDriverMemory(PDRIVER_OBJECT DriverObject)
{
    // Mark the driver code and data sections read-only and/or no-execute
    // Requires parsing PE headers and using MmProtectMdlSystemAddress

    PVOID base = DriverObject->DriverStart;
    ULONG size = DriverObject->DriverSize;

    PMDL mdl = IoAllocateMdl(base, size, FALSE, FALSE, NULL);
    if (!mdl)
        return;

    MmBuildMdlForNonPagedPool(mdl);

    // Change protections to PAGE_EXECUTE_READ (no write)
    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status))
    {
        IoFreeMdl(mdl);
        return;
    }
}

VOID InitializeCrypto()
{
    // Initialize AES 256 GCM key and IV securely
    // In production, keys loaded securely or derived at runtime; here zeroed for demo

    RtlZeroMemory(gCryptoContext.Key, sizeof(gCryptoContext.Key));
    RtlZeroMemory(gCryptoContext.IV, sizeof(gCryptoContext.IV));

    // Could use RNG for IV
    // For demo only, this is insecure
}

// AES-GCM encryption/decryption pseudocode using kernel crypto API or custom

NTSTATUS AESEncrypt(const UCHAR* plaintext, ULONG plaintextLen, UCHAR* ciphertext, ULONG* ciphertextLen)
{
    UNREFERENCED_PARAMETER(plaintext);
    UNREFERENCED_PARAMETER(plaintextLen);
    UNREFERENCED_PARAMETER(ciphertext);
    UNREFERENCED_PARAMETER(ciphertextLen);

    // Kernel crypto APIs or manual implementation needed
    // Placeholder returns STATUS_NOT_IMPLEMENTED

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS AESDecrypt(const UCHAR* ciphertext, ULONG ciphertextLen, UCHAR* plaintext, ULONG* plaintextLen)
{
    UNREFERENCED_PARAMETER(ciphertext);
    UNREFERENCED_PARAMETER(ciphertextLen);
    UNREFERENCED_PARAMETER(plaintext);
    UNREFERENCED_PARAMETER(plaintextLen);

    // Kernel crypto APIs or manual implementation needed
    // Placeholder returns STATUS_NOT_IMPLEMENTED

    return STATUS_NOT_IMPLEMENTED;
}

VOID LogMessage(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    char buffer[256];
    RtlZeroMemory(buffer, sizeof(buffer));
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, buffer);

    va_end(args);
}