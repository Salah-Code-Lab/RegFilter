#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>



// Silence C4189: local variable is initialized but not referenced
#pragma warning(disable:4189)

#pragma warning(disable: 4201) // nameless struct/union


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

typedef struct _REGISTRY_PROTECTION_ENTRY {
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    UNICODE_STRING KeyPathUpper;
    UNICODE_STRING ValueNameUpper;
    ULONG Flags;
    ULONG Hash;
} REGISTRY_PROTECTION_ENTRY, * PREGISTRY_PROTECTION_ENTRY;


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

// Image File Execution Options — debugger hijack
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

// Non-policy Defender Exclusions — operational path
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

// HVCI — Hypervisor Protected Code Integrity
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

// LSA Protection — RunAsPPL
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






// Get the SID of HKCU (i still have PTITS from this (PTITS: Post Trumatic IT Syndrome)) anyway lets get to it 

static NTSTATUS GetCurrentUserSidString(
    _Out_ UNICODE_STRING* SidString,
    _In_ ULONG Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (!SidString)
        return STATUS_INVALID_PARAMETER;

    SidString->Buffer = NULL;
    SidString->Length = 0;
    SidString->MaximumLength = 0;

    PTOKEN_USER user = NULL;
    PACCESS_TOKEN token = NULL;
    BOOLEAN isImpersonation = FALSE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;

    // Check thread impersonation token first
    // This catches attackers using ImpersonateLoggedOnUser
    // or SeImpersonateClient to bypass HKCU checks
    {
        BOOLEAN copyOnOpen = FALSE;
        BOOLEAN effectiveOnly = FALSE;
        SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityAnonymous;

        token = PsReferenceImpersonationToken(
            PsGetCurrentThread(),
            &copyOnOpen,
            &effectiveOnly,
            &impersonationLevel
        );

        if (token)
        {
            // Only trust impersonation at Impersonation level or above
            // Anonymous and Identification levels cannot act on behalf of user
            if (impersonationLevel < SecurityImpersonation)
            {
                PsDereferenceImpersonationToken(token);
                token = NULL;
            }
            else
            {
                isImpersonation = TRUE;
            }
        }
    }

    // Fall back to process primary token if no valid impersonation
    if (!token)
    {
        token = PsReferencePrimaryToken(PsGetCurrentProcess());
        if (!token)
            return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = SeQueryInformationToken(token, TokenUser, (PVOID*)&user);

    // Dereference correct token type
    if (isImpersonation)
        PsDereferenceImpersonationToken(token);
    else
        PsDereferencePrimaryToken(token);

    if (!NT_SUCCESS(status))
        return status;

    status = RtlConvertSidToUnicodeString(SidString, user->User.Sid, TRUE);

    ExFreePool2(user, DRIVER_TAG, NULL, 0);

    return status;
}

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

    PUNICODE_STRING imageName = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
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
        ExFreePool2(imageName, DRIVER_TAG, NULL, 0);
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

    ExFreePool2(imageName, DRIVER_TAG, NULL, 0);

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
    PUNICODE_STRING parentName = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
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
        ExFreePool2(parentName, DRIVER_TAG, NULL, 0);
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

    ExFreePool2(parentName, DRIVER_TAG, NULL, 0);
    return isWininit;
}

static BOOLEAN IsSystemSid(_In_ PCUNICODE_STRING SidString)
{
    static UNICODE_STRING SystemSid = RTL_CONSTANT_STRING(L"S-1-5-18");
    return RtlEqualUnicodeString(SidString, &SystemSid, TRUE);
}





static NTSTATUS BuildHKCUPath(
    _Out_ UNICODE_STRING* FullPath,
    _In_ PCUNICODE_STRING SidString,
    _In_ PCUNICODE_STRING RelativePath
)
{
    WCHAR buffer[1024]; // more than enough
    NTSTATUS status;

    status = RtlStringCchPrintfW(
        buffer,
        ARRAYSIZE(buffer),
        L"\\REGISTRY\\USER\\%wZ\\%wZ",
        SidString,
        RelativePath
    );

    if (!NT_SUCCESS(status))
        return status;

    return RtlCreateUnicodeString(FullPath, buffer) ?
        STATUS_SUCCESS : STATUS_NO_MEMORY;
}








static NTSTATUS FastUnicodeToUpper(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
)
{
    if (!Source || !Destination || !Source->Buffer || Source->Length == 0)
        return STATUS_INVALID_PARAMETER;

    // If a buffer already exists, scrub and free it before reallocating
    Destination->Length = 0; // Clear length to prevent accidental use during cleanup
    if (Destination->Buffer)
    {
        RtlSecureZeroMemory(Destination->Buffer, Destination->MaximumLength);
        ExFreePool2(Destination->Buffer, DRIVER_TAG, NULL, 0);
        Destination->Buffer = NULL;
        Destination->MaximumLength = 0;
        Destination->Length = 0;
    }

    // Always allocate fresh
    Destination->MaximumLength = Source->Length + sizeof(WCHAR);
    Destination->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Destination->MaximumLength,
        DRIVER_TAG
    );

    if (!Destination->Buffer)
    {
        Destination->MaximumLength = 0;
        Destination->Length = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Zero the entire buffer guarantees null termination and no leftover data
    RtlZeroMemory(Destination->Buffer, Destination->MaximumLength);

    // Upcase char by char
    USHORT charCount = Source->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < charCount; i++)
    {
        Destination->Buffer[i] = RtlUpcaseUnicodeChar(Source->Buffer[i]);
    }

    Destination->Length = Source->Length;

    return STATUS_SUCCESS;
}


static ULONG HashingFunction(_In_ PUNICODE_STRING String)
{
    if (!String || !String->Buffer || String->Length == 0)
        return 0;

    ULONG hash = 5381;
    USHORT charCount = String->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < charCount; ++i)
    {
        WCHAR c = RtlUpcaseUnicodeChar(String->Buffer[i]);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Alex Mercer

static ULONG HashEntry(_In_ PUNICODE_STRING KeyPath, _In_opt_ PUNICODE_STRING ValueName)
{
    ULONG hash = HashingFunction(KeyPath);
    if (ValueName && ValueName->Buffer)
    {
        ULONG valueHash = HashingFunction(ValueName);
        // Mix the two hashes
        hash = ((hash << 5) + hash) ^ valueHash;
    }
    return hash;
}

static NTSTATUS InitializeHashTable(_Out_ PHASH_TABLE Table, ULONG Size)
{
    UNREFERENCED_PARAMETER(Size);
    if (!Table || HASH_TABLE_SIZE == 0)
        return STATUS_INVALID_PARAMETER;

    // Zero the entire structure including all buckets
    RtlZeroMemory(Table, sizeof(HASH_TABLE));
    Table->Count = 0;

    return STATUS_SUCCESS;
}


static NTSTATUS AddToHashTable(_Inout_ PHASH_TABLE Table, ULONG Hash, ULONG EntryIndex)
{
    if (!Table) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate EntryIndex
    if (EntryIndex >= UNIFIED_PROTECTION_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check current IRQL
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG BucketIndex = Hash % HASH_TABLE_SIZE;

    PHASH_NODE NewNode = (PHASH_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HASH_NODE), DRIVER_TAG);
    if (!NewNode) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize the new node
    NewNode->Hash = Hash;
    NewNode->EntryIndex = EntryIndex;
    NewNode->Next = Table->Buckets[BucketIndex];

    // Insert at head of bucket list
    Table->Buckets[BucketIndex] = NewNode;
    Table->Count++;
    return STATUS_SUCCESS;
}

static BOOLEAN LookupHashTable(
    _In_ PHASH_TABLE Table,
    _In_ ULONG Hash,
    _Out_ PULONG EntryIndex,
    _In_ ULONG Flags,
    _In_opt_ PUNICODE_STRING Value
)
{
    if (!Table || !EntryIndex)
        return FALSE;

    *EntryIndex = (ULONG)-1;

    ULONG bucket = Hash % HASH_TABLE_SIZE;
    PHASH_NODE node = Table->Buckets[bucket];

    while (node)
    {
        if (node->EntryIndex >= UNIFIED_PROTECTION_COUNT)
        {
            node = node->Next;
            continue;
        }

        if (node->Hash != Hash)
        {
            node = node->Next;
            continue;
        }

        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[node->EntryIndex];

        if (!(entry->Flags & Flags))
        {
            node = node->Next;
            continue;
        }

        // Value check 
        if (entry->ValueNameUpper.Buffer && !(entry->Flags & PROTECT_FLAG_WILDCARD))
        {
            if (!Value || !Value->Buffer)
            {
                node = node->Next;
                continue;
            }

            if (!RtlEqualUnicodeString(Value, &entry->ValueNameUpper, TRUE))
            {
                node = node->Next;
                continue;
            }
        }

        *EntryIndex = node->EntryIndex;
        return TRUE;
    }

    return FALSE;
}

// Enhanced CleanupHashTable
static VOID CleanupHashTable(_Inout_ PHASH_TABLE Table)
{
    if (!Table) return;


    for (ULONG i = 0; i < HASH_TABLE_SIZE; ++i) {
        PHASH_NODE current = Table->Buckets[i];
        ULONG bucketCount = 0;

        while (current) {
            PHASH_NODE toFree = current;
            current = current->Next;
            ExFreePool2(toFree, DRIVER_TAG, NULL, 0);
            bucketCount++;
        }

        Table->Buckets[i] = NULL;
        if (bucketCount > 0) {
        }
    }

    Table->Count = 0;
}

NTSTATUS InitializeProtections()
{
    NTSTATUS status;

    status = InitializeHashTable(&g_HashTableUnified, HASH_TABLE_SIZE);
    if (!NT_SUCCESS(status))
        return status;

    for (ULONG u = 0; u < UNIFIED_PROTECTION_COUNT; u++)
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[u];

        status = FastUnicodeToUpper(&entry->KeyPath, &entry->KeyPathUpper);
        if (!NT_SUCCESS(status))
            return status;

        if (entry->ValueName.Buffer)
        {
            status = FastUnicodeToUpper(&entry->ValueName, &entry->ValueNameUpper);
            if (!NT_SUCCESS(status))
                return status;
        }

        // Wildcard entries are handled by recursive scan only
        // They cannot be hash matched since the incoming path will be longer
        if (entry->Flags & PROTECT_FLAG_WILDCARD)
            continue;

        entry->Hash = HashEntry(&entry->KeyPathUpper,
            entry->ValueNameUpper.Buffer ? &entry->ValueNameUpper : NULL);

        status = AddToHashTable(&g_HashTableUnified, entry->Hash, u);
        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
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

static UNICODE_STRING g_ForbiddenHivePaths[] = {
    RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES"),
    RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES")
};

#define FORBIDDEN_HIVE_COUNT (sizeof(g_ForbiddenHivePaths) / sizeof(g_ForbiddenHivePaths[0]))

#define HIVE_FORBIDDEN_FLAGS (PROTECT_FLAG_MODIFY | PROTECT_FLAG_WILDCARD)

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
        ExFreePool2(valueUpper.Buffer, DRIVER_TAG, NULL, 0);

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
            ExFreePool2(valueUpper.Buffer, DRIVER_TAG, NULL, 0);
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

            ExFreePool2(hkcuFullPathUpper.Buffer, DRIVER_TAG, NULL, 0);

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
    ExFreePool2(keyPathUpper.Buffer, DRIVER_TAG, NULL, 0);
    if (valueUpper.Buffer)
        ExFreePool2(valueUpper.Buffer, DRIVER_TAG, NULL, 0);

    return result;
}

// 0x55AA



#define RegistryFilterUnloaded 2112010

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
            ExFreePool2(entry->KeyPathUpper.Buffer, DRIVER_TAG, NULL, 0);
            entry->KeyPathUpper.Buffer = NULL;
        }
        if (entry->ValueNameUpper.Buffer)
        {
            ExFreePool2(entry->ValueNameUpper.Buffer, DRIVER_TAG, NULL, 0);
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



    // DbgPrint("Registry Protection Driver Unloaded Code:2010111\n");

}

// The Entry of the Driver that should Change how the OS behaves for the Good 

// Driver Load Routine
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    if (InitSafeBootMode != NULL && *InitSafeBootMode != 0) {
        DriverObject->DriverUnload = DriverUnload;
        return STATUS_SUCCESS;
    }
    
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
                ExFreePool2(entry->KeyPathUpper.Buffer, DRIVER_TAG, NULL, 0);
                entry->KeyPathUpper.Buffer = NULL;
            }
            if (entry->ValueNameUpper.Buffer)
            {
                ExFreePool2(entry->ValueNameUpper.Buffer, DRIVER_TAG, NULL, 0);
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


        DriverObject->DriverUnload = NULL;

    return STATUS_SUCCESS;
}

// Sal -Me
// Was here 
// Stay safe out there.
