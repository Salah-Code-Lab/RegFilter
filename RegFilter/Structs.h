#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>

#define PROTECT_FLAG_WRITE      0x00000001
#define PROTECT_FLAG_DELETE     0x00000002
#define PROTECT_FLAG_READ       0x00000004
#define PROTECT_FLAG_CREATE     0x00000008
#define PROTECT_FLAG_LOAD       0x00000010
#define PROTECT_FLAG_WILDCARD   0x00000020
#define PROTECT_FLAG_SID        0x80000000
#define PROTECT_FLAG_ACCESS 0x00000040
#define PROTECT_FLAG_MODIFY     (PROTECT_FLAG_WRITE | PROTECT_FLAG_DELETE)
#define PROTECT_FLAG_ALL        (PROTECT_FLAG_WRITE | PROTECT_FLAG_DELETE | PROTECT_FLAG_CREATE)



// Silence C4189: local variable is initialized but not referenced
#pragma warning(disable:4189)
#pragma warning(disable: 4996)
#pragma warning(disable: 4201) // nameless struct/union




#ifdef WIN10_BUILD
#define POOL_ALLOC(size, tag) ExAllocatePoolWithTag(NonPagedPoolNx, size, tag)
#define POOL_FREE(ptr, tag) ExFreePoolWithTag(ptr, tag)
#else
#define POOL_ALLOC(size, tag) ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag)
#define POOL_FREE(ptr, tag) ExFreePool2(ptr, tag, 0, 0)
#endif



#define HASH_TABLE_SIZE 8192
#define DRIVER_TAG 'RgSn'

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef RegNtPreRenameValueKey
#define RegNtPreRenameValueKey ((REG_NOTIFY_CLASS)25)
#endif






NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerWinSystem = 7,
    PsProtectedSignerApp = 8
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;



typedef struct _REG_RENAME_VALUE_KEY_INFORMATION {
    PVOID Object;
    PUNICODE_STRING OldName;
    PUNICODE_STRING NewName;
} REG_RENAME_VALUE_KEY_INFORMATION, * PREG_RENAME_VALUE_KEY_INFORMATION;




typedef struct _HASH_NODE {
    ULONG Hash;
    ULONG EntryIndex;
    struct _HASH_NODE* Next;
} HASH_NODE, * PHASH_NODE;

typedef struct _HASH_TABLE {
    PHASH_NODE Buckets[HASH_TABLE_SIZE];
    ULONG Count;
} HASH_TABLE, * PHASH_TABLE;



// Global Variables
static LARGE_INTEGER g_Cookie = { 0 };
HASH_TABLE g_HashTableUnified;



typedef struct _REGISTRY_PROTECTION_ENTRY {
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    UNICODE_STRING KeyPathUpper;
    UNICODE_STRING ValueNameUpper;
    ULONG Flags;
    ULONG Hash;
} REGISTRY_PROTECTION_ENTRY, * PREGISTRY_PROTECTION_ENTRY;


// forward declerations 

NTSTATUS InitializeProtections(void);


NTSTATUS AddToHashTable(
    _Inout_ PHASH_TABLE Table,
    ULONG Hash,
    ULONG EntryIndex
);


ULONG HashEntry(_In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName
);



NTSTATUS InitializeHashTable(
    _Out_ PHASH_TABLE Table,
    ULONG Size
);


NTSTATUS FastUnicodeToUpper(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
);


NTSTATUS BuildHKCUPath(
    _Out_ UNICODE_STRING* FullPath,
    _In_ PCUNICODE_STRING SidString,
    _In_ PCUNICODE_STRING RelativePath
);


BOOLEAN IsSystemSid(
    _In_ PCUNICODE_STRING SidString
);



NTSTATUS GetCurrentUserSidString(
    _Out_ UNICODE_STRING* SidString,
    _In_ ULONG Flags
);


BOOLEAN LookupHashTable(
    _In_ PHASH_TABLE Table,
    _In_ ULONG Hash,
    _Out_ PULONG EntryIndex,
    _In_ ULONG Flags,
    _In_opt_ PUNICODE_STRING Value
);


VOID CleanupHashTable(
    _Inout_ PHASH_TABLE Table
);






static REGISTRY_PROTECTION_ENTRY g_UnifiedProtections[] = {

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
.ValueName = RTL_CONSTANT_STRING(L"Appinit_DLLs"),
.KeyPathUpper = {0},
.ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

{
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RegFilter"),
    .ValueName = RTL_CONSTANT_STRING(L"Altitude"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
},


{
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RegFilter"),
    .ValueName = RTL_CONSTANT_STRING(L"Start"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\RegFilter"),
    .ValueName = RTL_CONSTANT_STRING(L"Altitude"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
},

// Start value 
{
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\RegFilter"),
    .ValueName = RTL_CONSTANT_STRING(L"Start"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"EnableLUA"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
    },

        {
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"ConsentPromptBehaviorUser"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
    .Hash = 0
    },






        {
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"ConsentPromptBehaviorAdmin"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_MODIFY,
    .Hash = 0
    },

            {
    .KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"*"),
    .KeyPathUpper = {0},
    .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD,
    .Hash = 0
    },


    // Keyboard layout scancode hijack
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout"),
.ValueName = RTL_CONSTANT_STRING(L"Scancode Map"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

// exefile handler hijack
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\open\\command"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\runas\\command"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD,
.Hash = 0
},

// Winlogon tampering
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
.ValueName = RTL_CONSTANT_STRING(L"Userinit"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
.ValueName = RTL_CONSTANT_STRING(L"AutoAdminLogon"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
.ValueName = RTL_CONSTANT_STRING(L"AutoRestartShell"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
.ValueName = RTL_CONSTANT_STRING(L"DisableCAD"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Shutdown without logon
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
.ValueName = RTL_CONSTANT_STRING(L"shutdownwithoutlogon"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},


// HKLM Run persistence
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

// HKLM RunOnce
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

// Winlogon Shell hijack
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
.ValueName = RTL_CONSTANT_STRING(L"Shell"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

// Image File Execution Options  debugger hijack
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_WILDCARD,
.Hash = 0
},


// Logon background disable
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"),
.ValueName = RTL_CONSTANT_STRING(L"DisableLogonBackgroundImage"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD,
.Hash = 0
},



// Real-Time Protection
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableRealtimeMonitoring"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableBehaviorMonitoring"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY ,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableOnAccessProtection"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableScanOnRealtimeEnable"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableIOAVProtection"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Spynet / Cloud Protection
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"DisableBlockAtFirstSeen"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"SpynetReporting"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"SubmitSamplesConsent"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Non-policy Defender Exclusions  operational path
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// HVCI  Hypervisor Protected Code Integrity
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"),
.ValueName = RTL_CONSTANT_STRING(L"EnableVirtualizationBasedSecurity"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"),
.ValueName = RTL_CONSTANT_STRING(L"RequirePlatformSecurityFeatures"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"),
.ValueName = RTL_CONSTANT_STRING(L"Enabled"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"),
.ValueName = RTL_CONSTANT_STRING(L"Locked"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// LSA Protection  RunAsPPL
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"),
.ValueName = RTL_CONSTANT_STRING(L"RunAsPPL"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"),
.ValueName = RTL_CONSTANT_STRING(L"RunAsPPLBoot"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// LSA
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"),
.ValueName = RTL_CONSTANT_STRING(L"DisableRestrictedAdmin"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"),
.ValueName = RTL_CONSTANT_STRING(L"LimitBlankPasswordUse"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"),
.ValueName = RTL_CONSTANT_STRING(L"NoLMHash"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},


// MVDB
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config"),
.ValueName = RTL_CONSTANT_STRING(L"VulnerableDriverBlocklistEnable"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"),
.ValueName = RTL_CONSTANT_STRING(L"HVCIMATRequired"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"),
.ValueName = RTL_CONSTANT_STRING(L"EnableVirtualizationBasedSecurity"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"),
.ValueName = RTL_CONSTANT_STRING(L"EnableFirewall"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},



// Cloud delivered protection
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"DisableBlockAtFirstSeen"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\MpEngine"),
.ValueName = RTL_CONSTANT_STRING(L"MpCloudBlockLevel"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\MpEngine"),
.ValueName = RTL_CONSTANT_STRING(L"MpBafsExtendedTimeout"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Non-policy Spynet
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"SubmitSamplesConsent"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet"),
.ValueName = RTL_CONSTANT_STRING(L"SpynetReporting"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Tamper Protection
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Features"),
.ValueName = RTL_CONSTANT_STRING(L"TamperProtection"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

// Reporting
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting"),
.ValueName = RTL_CONSTANT_STRING(L"DisableEnhancedNotifications"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},



// Scan
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"),
.ValueName = RTL_CONSTANT_STRING(L"DisableArchiveScanning"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"),
.ValueName = RTL_CONSTANT_STRING(L"DisableRemovableDriveScanning"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"),
.ValueName = RTL_CONSTANT_STRING(L"DisableEmailScanning"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine"),
.ValueName = RTL_CONSTANT_STRING(L"MpCloudBlockLevel"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions"),
.ValueName = RTL_CONSTANT_STRING(L"*"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY | PROTECT_FLAG_CREATE | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
.Hash = 0
},




{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableRealtimeMonitoring"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableBehaviorMonitoring"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableOnAccessProtection"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},
{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
.ValueName = RTL_CONSTANT_STRING(L"DisableIOAVProtection"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},


{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend"),
.ValueName = RTL_CONSTANT_STRING(L"Start"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"),
.ValueName = RTL_CONSTANT_STRING(L"Start"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdFilter"),
.ValueName = RTL_CONSTANT_STRING(L"Start"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

{
.KeyPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdBoot"),
.ValueName = RTL_CONSTANT_STRING(L"Start"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_MODIFY,
.Hash = 0
},

};




#define UNIFIED_PROTECTION_COUNT (sizeof(g_UnifiedProtections) / sizeof(REGISTRY_PROTECTION_ENTRY))



static REGISTRY_PROTECTION_ENTRY g_HKCUProtections[] = {




    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    .ValueName = RTL_CONSTANT_STRING(L"*"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    .ValueName = RTL_CONSTANT_STRING(L"*"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
    },

{
.KeyPath = RTL_CONSTANT_STRING(L"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"),
.ValueName = RTL_CONSTANT_STRING(L"DisableWindowsUpdateAccess"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
},





{
.KeyPath = RTL_CONSTANT_STRING(L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"),
.ValueName = RTL_CONSTANT_STRING(L"SCRNSAVE.EXE"),
.KeyPathUpper = {0}, .ValueNameUpper = {0},
.Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
},

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableRegistryTools"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoControlPanel"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoRun"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableTaskMgr"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableChangePassword"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableLockWorkstation"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoFileAssociate"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoViewContextMenu"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoFolderOptions"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
    .ValueName = RTL_CONSTANT_STRING(L"NoDrives"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableSafeMode"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Policies\\Microsoft\\Windows\\System"),
    .ValueName = RTL_CONSTANT_STRING(L"DisableCMD"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },


    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
    .ValueName = RTL_CONSTANT_STRING(L"ProxyServer"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
    .ValueName = RTL_CONSTANT_STRING(L"ProxyEnable"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
    .ValueName = RTL_CONSTANT_STRING(L"AutoConfigURL"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },



    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
    .ValueName = RTL_CONSTANT_STRING(L"AppInit_DLLs"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },

    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
    .ValueName = RTL_CONSTANT_STRING(L"Load"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID,
    },


    {
    .KeyPath = RTL_CONSTANT_STRING(L"Software\\Classes\\ms-settings\\Shell\\Open\\command"),
    .ValueName = RTL_CONSTANT_STRING(L"*"),
    .KeyPathUpper = {0}, .ValueNameUpper = {0},
    .Flags = PROTECT_FLAG_ALL | PROTECT_FLAG_SID | PROTECT_FLAG_WILDCARD | PROTECT_FLAG_ACCESS,
    },

};

#define HKCU_PROTECTION_COUNT (sizeof(g_HKCUProtections) / sizeof(REGISTRY_PROTECTION_ENTRY))



static UNICODE_STRING g_ForbiddenHivePaths[] = {
    RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES"),
    RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES")
};

#define FORBIDDEN_HIVE_COUNT (sizeof(g_ForbiddenHivePaths) / sizeof(g_ForbiddenHivePaths[0]))

#define HIVE_FORBIDDEN_FLAGS (PROTECT_FLAG_MODIFY | PROTECT_FLAG_WILDCARD)
