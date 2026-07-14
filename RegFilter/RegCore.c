#include "Structs.h"






// Get the SID of HKCU (i still have PTITS from this (PTITS: Post Trumatic IT Syndrome)) anyway lets get to it 


// VBR, $MFT 

BOOLEAN ChkInt(VOID)
{
    // Kernel/System thread
    if (PsIsSystemThread(PsGetCurrentThread()))
        return TRUE;

    // Kernel mode caller
    if (ExGetPreviousMode() == KernelMode)
        return TRUE;

    PEPROCESS process = PsGetCurrentProcess();
    if (!process)
        return FALSE;

    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status) || !hProcess)
        return FALSE;

    // PPL / PPL-Light
    PS_PROTECTION protection = { 0 };
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessProtectionInformation,
        &protection,
        sizeof(PS_PROTECTION),
        NULL
    );
    if (NT_SUCCESS(status) && protection.Type != PsProtectedTypeNone)
    {
        ZwClose(hProcess);
        return TRUE;
    }

    // Get image name
    ULONG bufferSize = sizeof(UNICODE_STRING) + (MAX_PATH * sizeof(WCHAR));

    PUNICODE_STRING imageName = (PUNICODE_STRING)POOL_ALLOC(
        bufferSize,
        DRIVER_TAG
    );
    if (!imageName)
    {
        ZwClose(hProcess);
        return FALSE;
    }

    status = ZwQueryInformationProcess(
        hProcess,
        ProcessImageFileName,
        imageName,
        bufferSize,
        NULL
    );
    if (!NT_SUCCESS(status) || !imageName->Buffer || imageName->Length == 0)
    {
        POOL_FREE(imageName, DRIVER_TAG);
        ZwClose(hProcess);
        return FALSE;
    }

    // Must start with \Device\HarddiskVolume
    UNICODE_STRING devicePrefix =
        RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume");

    // Must end with \Windows\System32\services.exe
    UNICODE_STRING servicesExeSuffix =
        RTL_CONSTANT_STRING(L"\\Windows\\System32\\services.exe");

    BOOLEAN isServices = FALSE;

    if (RtlPrefixUnicodeString(&devicePrefix, imageName, TRUE))
    {
        if (imageName->Length >= servicesExeSuffix.Length)
        {
            UNICODE_STRING tail = {
                servicesExeSuffix.Length,
                servicesExeSuffix.Length,
                (PWCH)((PUCHAR)imageName->Buffer +
                       imageName->Length -
                       servicesExeSuffix.Length)
            };
            isServices = RtlEqualUnicodeString(&tail, &servicesExeSuffix, TRUE);
        }
    }

    POOL_FREE(imageName, DRIVER_TAG);

    if (!isServices)
    {
        ZwClose(hProcess);
        return FALSE;
    }

    // Get parent PID
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    ZwClose(hProcess);

    if (!NT_SUCCESS(status))
        return FALSE;

    // Look up parent process
    PEPROCESS parentProcess = NULL;
    status = PsLookupProcessByProcessId(
        (HANDLE)pbi.InheritedFromUniqueProcessId,
        &parentProcess
    );
    if (!NT_SUCCESS(status) || !parentProcess)
        return FALSE;

    HANDLE hParent = NULL;
    status = ObOpenObjectByPointer(
        parentProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hParent
    );
    ObDereferenceObject(parentProcess);

    if (!NT_SUCCESS(status) || !hParent)
        return FALSE;

    // Get parent image name
    PUNICODE_STRING parentName = (PUNICODE_STRING)POOL_ALLOC(
        bufferSize,
        DRIVER_TAG
    );
    if (!parentName)
    {
        ZwClose(hParent);
        return FALSE;
    }

    status = ZwQueryInformationProcess(
        hParent,
        ProcessImageFileName,
        parentName,
        bufferSize,
        NULL
    );
    ZwClose(hParent);

    if (!NT_SUCCESS(status) || !parentName->Buffer || parentName->Length == 0)
    {
        POOL_FREE(parentName, DRIVER_TAG);
        return FALSE;
    }

    // Must start with \Device\HarddiskVolume
    // Must end with \Windows\System32\wininit.exe
    UNICODE_STRING wininitExeSuffix =
        RTL_CONSTANT_STRING(L"\\Windows\\System32\\wininit.exe");

    BOOLEAN isWininit = FALSE;

    if (RtlPrefixUnicodeString(&devicePrefix, parentName, TRUE))
    {
        if (parentName->Length >= wininitExeSuffix.Length)
        {
            UNICODE_STRING tail = {
                wininitExeSuffix.Length,
                wininitExeSuffix.Length,
                (PWCH)((PUCHAR)parentName->Buffer +
                       parentName->Length -
                       wininitExeSuffix.Length)
            };
            isWininit = RtlEqualUnicodeString(&tail, &wininitExeSuffix, TRUE);
        }
    }

    POOL_FREE(parentName, DRIVER_TAG);
    return isWininit;
}














// Enderm@nch

// Get Operation Flags from Notify Class
static ULONG GetOperationFlags(
    _In_ REG_NOTIFY_CLASS NotifyClass)
{
    switch (NotifyClass)
    {
    case RegNtPreOpenKeyEx:
    case RegNtPreOpenKey:
        return PROTECT_FLAG_ACCESS;

    case RegNtPreSetValueKey:
        return PROTECT_FLAG_WRITE;

    case RegNtPreDeleteValueKey:
    case RegNtPreDeleteKey:
        return PROTECT_FLAG_DELETE;

    case RegNtPreRenameKey:
    case RegNtPreRenameValueKey:
    case RegNtPreSetKeySecurity:
        return PROTECT_FLAG_MODIFY;

    case RegNtPreLoadKey:
        return 0;

    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx:
        return PROTECT_FLAG_CREATE;

    case RegNtQueryKey:
    case RegNtQueryValueKey:
    case RegNtPreQueryMultipleValueKey:
    case RegNtPreEnumerateKey:
    case RegNtPreEnumerateValueKey:
        return PROTECT_FLAG_READ;

    default:
        return 0;
    }
}

// 4e6f457363617065
// to CREATE or MODIFY these paths. OS manages them exclusively via CM.



NTSTATUS
ControlHiveAccess(
    _In_ PUNICODE_STRING CallerPathUpper,
    _In_ ULONG OperationFlags,
    _In_ BOOLEAN IsKernelCaller,
    _In_ BOOLEAN IsSystemCaller
)
{
    if (IsKernelCaller || IsSystemCaller)
        return STATUS_SUCCESS;

    if (!(OperationFlags & HIVE_FORBIDDEN_FLAGS))
        return STATUS_SUCCESS;

    for (ULONG i = 0; i < FORBIDDEN_HIVE_COUNT; i++)
    {
        if (RtlPrefixUnicodeString(&g_ForbiddenHivePaths[i], CallerPathUpper, TRUE))
        {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
    }

    return STATUS_SUCCESS;
}
// Recurse

static BOOLEAN IsOperationBlockedRecursive(
    _In_ PUNICODE_STRING Key,
    _In_ ULONG OperationFlags
)
{
    if (!Key || Key->Length == 0)
        return FALSE;

    for (ULONG i = 0; i < UNIFIED_PROTECTION_COUNT; ++i)
    {
        PREGISTRY_PROTECTION_ENTRY e = &g_UnifiedProtections[i];

        if (!e->KeyPathUpper.Buffer)
            continue;

        BOOLEAN match = FALSE;

        if (e->Flags & PROTECT_FLAG_WILDCARD)
        {
            if (RtlPrefixUnicodeString(&e->KeyPathUpper, Key, TRUE))
                match = TRUE;
        }
        else
        {
            if (RtlEqualUnicodeString(&e->KeyPathUpper, Key, TRUE))
                match = TRUE;
        }

        if (!match)
            continue;

        ULONG effectiveFlags = e->Flags & ~(PROTECT_FLAG_WILDCARD | PROTECT_FLAG_SID);

        if ((effectiveFlags & OperationFlags) != 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

// 446, 64, 2 

static BOOLEAN IsOperationBlockedOptimized(
    _In_ PUNICODE_STRING Key,
    _In_opt_ PUNICODE_STRING Value,
    _In_ ULONG Flags
)
{
    if (!Key || Key->Length == 0)
        return FALSE;

    UNICODE_STRING valueUpper = { 0 };
    PUNICODE_STRING valueForHash = NULL;

    if (Value && Value->Buffer)
    {
        if (NT_SUCCESS(FastUnicodeToUpper(Value, &valueUpper)))
            valueForHash = &valueUpper;
    }

    BOOLEAN blocked = FALSE;
    ULONG keyHash = HashEntry(Key, valueForHash);
    ULONG entryIndex = 0;

    if (LookupHashTable(&g_HashTableUnified, keyHash, &entryIndex, Flags, valueForHash))
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[entryIndex];
        ULONG entryEffective = entry->Flags & ~(PROTECT_FLAG_WILDCARD | PROTECT_FLAG_SID);

        if ((entryEffective & Flags) != 0)
        {
            blocked = TRUE;
            goto cleanup;
        }
    }

    // Hash table had no opinion
    blocked = IsOperationBlockedRecursive(Key, Flags);

cleanup:
    if (valueUpper.Buffer)
       POOL_FREE(valueUpper.Buffer, DRIVER_TAG);

    return blocked;
}

extern PULONG InitSafeBootMode;

static NTSTATUS RegistryCallback(
    _In_ PVOID Context,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(Context);

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PVOID registryObject = NULL;
    PCUNICODE_STRING valueName = NULL;
    PCUNICODE_STRING keyPath = NULL;

    switch (notifyClass)
    {
    case RegNtPreOpenKey:
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->RootObject;
        break;
    }
    case RegNtPreSetValueKey:
    case RegNtPreDeleteValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->Object;
        valueName = info->ValueName;
        break;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->Object;
        break;
    }
    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->Object;
        break;
    }
    case RegNtPreRenameValueKey:
    {
        PREG_RENAME_VALUE_KEY_INFORMATION info = (PREG_RENAME_VALUE_KEY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->Object;
        valueName = info->OldName;
        break;
    }
    case RegNtPreSetKeySecurity:
    {
        PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
        if (!info) return STATUS_SUCCESS;
        registryObject = info->Object;
        break;
    }
    case RegNtPreQueryValueKey:
    case RegNtPreQueryMultipleValueKey:
    case RegNtPreEnumerateKey:
    case RegNtPreEnumerateValueKey:
        return STATUS_SUCCESS;
    default:
        return STATUS_SUCCESS;
    }

    if (*InitSafeBootMode > 0)
        return STATUS_SUCCESS;

    if (!registryObject)
        return STATUS_SUCCESS;



    NTSTATUS status = CmCallbackGetKeyObjectID(&g_Cookie, registryObject, NULL, &keyPath);
    if (!NT_SUCCESS(status) || !keyPath || !keyPath->Buffer)
        return STATUS_SUCCESS;

    ULONG opFlags = GetOperationFlags(notifyClass);
    if (opFlags == 0)
        return STATUS_SUCCESS;

    UNICODE_STRING valueUpper = { 0 };
    PUNICODE_STRING valueForHash = NULL;

    if (valueName && valueName->Buffer)
    {
        if (NT_SUCCESS(FastUnicodeToUpper(valueName, &valueUpper)))
            valueForHash = &valueUpper;
    }

    UNICODE_STRING keyPathUpper = { 0 };
    status = FastUnicodeToUpper((PUNICODE_STRING)keyPath, &keyPathUpper);
    if (!NT_SUCCESS(status))
    {
        if (valueUpper.Buffer)
            POOL_FREE(valueUpper.Buffer, DRIVER_TAG);
        return STATUS_SUCCESS;
    }

    ULONG entryIndex = 0;
    NTSTATUS result = STATUS_SUCCESS;



    // 1. Hash table lookup Block regardless of caller if there's a hash match with relevant flags. This is the fastest check and
    // catches exact matches immediately, which is ideal for common policies like DisableTaskMgr or AppInit_DLLs.
    ULONG keyHash = HashEntry(&keyPathUpper, valueForHash);
    BOOLEAN found = LookupHashTable(&g_HashTableUnified, keyHash, &entryIndex, opFlags, valueForHash);

    if (found)
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[entryIndex];
        ULONG entryEffective = entry->Flags & ~(PROTECT_FLAG_WILDCARD | PROTECT_FLAG_SID);

        if ((entryEffective & opFlags) != 0)
        {
            result = STATUS_OBJECT_NAME_NOT_FOUND;
            goto cleanup;
        }
    }

    // 2. Recursive scan Regardless of caller, this catches wildcard matches and any entries that were missed by the hash
    // table due to hash collisions or if they were added without hashes (like during initialization failures).
    // It's more expensive but necessary for comprehensive protection.
    found = IsOperationBlockedRecursive(&keyPathUpper, opFlags);
    if (found)
    {
        result = STATUS_OBJECT_PATH_NOT_FOUND;
        goto cleanup;
    }

    // 3. ControlHiveAccess
    BOOLEAN IsKernelCaller = (ExGetPreviousMode() == KernelMode);
    BOOLEAN IsSystemCaller = ChkInt();

    NTSTATUS hiveStatus = ControlHiveAccess(&keyPathUpper, opFlags, IsKernelCaller, IsSystemCaller);
    if (!NT_SUCCESS(hiveStatus))
    {
        result = hiveStatus;
        goto cleanup;
    }


    // --- HKCU: resolve SID once, then loop ---
    {
        UNICODE_STRING sidString = { 0 };
        status = GetCurrentUserSidString(&sidString, 0);
        if (!NT_SUCCESS(status))
            goto cleanup;

        if (IsSystemSid(&sidString))
        {
            RtlFreeUnicodeString(&sidString);
            goto cleanup;
        }

        for (ULONG i = 0; i < HKCU_PROTECTION_COUNT; i++)
        {
            PREGISTRY_PROTECTION_ENTRY entry = &g_HKCUProtections[i];

            if (!(entry->Flags & opFlags))
                continue;

            UNICODE_STRING hkcuFullPath = { 0 };
            status = BuildHKCUPath(&hkcuFullPath, &sidString, &entry->KeyPathUpper);
            if (!NT_SUCCESS(status))
                continue;

            UNICODE_STRING hkcuFullPathUpper = { 0 };
            status = FastUnicodeToUpper(&hkcuFullPath, &hkcuFullPathUpper);
            RtlFreeUnicodeString(&hkcuFullPath);
            if (!NT_SUCCESS(status))
                continue;

            BOOLEAN pathMatches = FALSE;

            if (entry->Flags & PROTECT_FLAG_WILDCARD)
                pathMatches = RtlPrefixUnicodeString(&hkcuFullPathUpper, &keyPathUpper, TRUE);
            else
                pathMatches = RtlEqualUnicodeString(&hkcuFullPathUpper, &keyPathUpper, TRUE);

            POOL_FREE(hkcuFullPathUpper.Buffer, DRIVER_TAG);

            if (!pathMatches)
                continue;

            // Value check 
            if (entry->ValueNameUpper.Buffer && !(entry->Flags & PROTECT_FLAG_WILDCARD))
            {
                if (!valueForHash || !valueForHash->Buffer)
                    continue;
                if (!RtlEqualUnicodeString(valueForHash, &entry->ValueNameUpper, TRUE))
                    continue;
            }

            ULONG hkcuEffective = entry->Flags & ~(PROTECT_FLAG_WILDCARD | PROTECT_FLAG_SID);
            if ((hkcuEffective & opFlags) != 0)
            {
                result = STATUS_OBJECT_NAME_NOT_FOUND;
            }

            RtlFreeUnicodeString(&sidString);
            goto cleanup;
        }

        RtlFreeUnicodeString(&sidString);
    }

cleanup:
    POOL_FREE(keyPathUpper.Buffer, DRIVER_TAG);
    if (valueUpper.Buffer)
        POOL_FREE(valueUpper.Buffer, DRIVER_TAG);

    return result;
}

// 0x55AA


// Driver Unload Routine
static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{

    UNREFERENCED_PARAMETER(DriverObject);


    if (g_Cookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_Cookie);
        g_Cookie.QuadPart = 0;
    }


    for (ULONG i = 0; i < UNIFIED_PROTECTION_COUNT; i++)
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[i];
        if (entry->KeyPathUpper.Buffer)
        {
            POOL_FREE(entry->KeyPathUpper.Buffer, DRIVER_TAG);
            entry->KeyPathUpper.Buffer = NULL;
        }
        if (entry->ValueNameUpper.Buffer)
        {
            POOL_FREE(entry->ValueNameUpper.Buffer, DRIVER_TAG);
            entry->ValueNameUpper.Buffer = NULL;
        }
    }

    CleanupHashTable(&g_HashTableUnified);

    // Zero the HKCU protections to remove any sensitive data like SIDs from memory
    for (ULONG i = 0; i < HKCU_PROTECTION_COUNT; i++)
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_HKCUProtections[i];
        if (entry->KeyPathUpper.Buffer)
        {
            RtlFreeUnicodeString(&entry->KeyPathUpper);
            entry->KeyPathUpper.Buffer = NULL;
        }
        if (entry->ValueNameUpper.Buffer)
        {
            RtlFreeUnicodeString(&entry->ValueNameUpper);
            entry->ValueNameUpper.Buffer = NULL;
        }
    }

    RtlZeroMemory(g_HKCUProtections, sizeof(g_HKCUProtections));
    RtlZeroMemory(g_ForbiddenHivePaths, sizeof(g_ForbiddenHivePaths));

    // Afterwards We zero the globals
    g_Cookie.QuadPart = 0;





}

// The Entry of the Driver that should Change how the OS behaves for the Good 



// Driver Load Routine
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;

    // Unified protections
    status = InitializeProtections();
    if (!NT_SUCCESS(status))
        return status;

    for (ULONG i = 0; i < HKCU_PROTECTION_COUNT; i++) {

        RtlUpcaseUnicodeString(&g_HKCUProtections[i].KeyPathUpper, &g_HKCUProtections[i].KeyPath, TRUE);

        if (g_HKCUProtections[i].ValueName.Buffer) {

            RtlUpcaseUnicodeString(&g_HKCUProtections[i].ValueNameUpper, &g_HKCUProtections[i].ValueName, TRUE);

        }

    }


    UNICODE_STRING altitude = { 0 };
    RtlInitUnicodeString(&altitude, L"327999");

    status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_Cookie,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        // Free Unified upcased buffers
        for (ULONG i = 0; i < UNIFIED_PROTECTION_COUNT; i++)
        {
            PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[i];
            if (entry->KeyPathUpper.Buffer)
            {
                POOL_FREE(entry->KeyPathUpper.Buffer, DRIVER_TAG);
                entry->KeyPathUpper.Buffer = NULL;
            }
            if (entry->ValueNameUpper.Buffer)
            {
                POOL_FREE(entry->ValueNameUpper.Buffer, DRIVER_TAG);
                entry->ValueNameUpper.Buffer = NULL;
            }
        }

        // Free HKCU upcased buffers
        for (ULONG i = 0; i < HKCU_PROTECTION_COUNT; i++)
        {
            PREGISTRY_PROTECTION_ENTRY entry = &g_HKCUProtections[i];
            if (entry->KeyPathUpper.Buffer)
            {
                RtlFreeUnicodeString(&entry->KeyPathUpper);
                entry->KeyPathUpper.Buffer = NULL;
            }
            if (entry->ValueNameUpper.Buffer)
            {
                RtlFreeUnicodeString(&entry->ValueNameUpper);
                entry->ValueNameUpper.Buffer = NULL;
            }
        }

        // Free hash nodes
        CleanupHashTable(&g_HashTableUnified);

        return status;
    }



    // Register unload last only reachable if everything succeeded
    // This is to prevent Malicious unloads in normal mode 
    // though the Other build RegFilter can be Unloaded Manually
    if (*InitSafeBootMode > 0)
        DriverObject->DriverUnload = DriverUnload;
    else
        DriverObject->DriverUnload = NULL;

    return STATUS_SUCCESS;
}

// Sal -Me
// Was here 
// Stay safe out there.
