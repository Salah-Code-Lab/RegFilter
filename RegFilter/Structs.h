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


typedef struct _REGISTRY_PROTECTION_ENTRY {
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    UNICODE_STRING KeyPathUpper;
    UNICODE_STRING ValueNameUpper;
    ULONG Flags;
    ULONG Hash;
} REGISTRY_PROTECTION_ENTRY, * PREGISTRY_PROTECTION_ENTRY;

// \./ \./ \./ \./ \./ \./ \./ \./ \./
// REGFILTER PROTECTION POLICY 
// /.\ /.\ /.\ /.\ /.\ /.\ /.\ /.\ /.\
// This is a DEMONSTRATION policy. It blocks aggressively.
// if not edited accordingly, it will
// destabilize Windows Explorer and other shell components.
// so
// Before deployment:
//   1. Remove entries that aren't needed by your Environment
//   2. Add entries for the targetted paths
//   3. Test symbolic link paths (WOW6432Node, HKCU aliases, CurrentControlSet, ControlSet001)
//   4. Verify in VM: expect shell breakage if too aggressive
//   5. Do not add System Critical Entries since these will cause (0x7B, 0xEF, etc etc)
//   if you need to add system critical paths but protect them from userland put them in the g_ForbiddenHivePaths array
//   But even then Expect system Destabliziation and other side effects
// Examples: 
// This is completely Safe:
// \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
// may break some installs but wont break them completely they will still be functional 
// NOT SAFE: 
// \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\ (And its symbolic link for it to actually be blocked)
// that way the OS may fail the mount the System hive (0x7B)
// the difference between here and g_ForbiddenHivePaths is:
// This path here doesn't differnate between Kernel callers and User callers it don't care 
// g_ForbiddenHivePaths because it differnates between callers you can absoloutely do it 
// i am already doing it but it may cause some false positives not some but a lot so play your cards right
// if it is a system critical path that you know nothing in Userland touches add it to g_ForbiddenHivePaths but it may still cause 
// Side Effects



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
