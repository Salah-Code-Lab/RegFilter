#include "Structs.h"


NTSTATUS GetCurrentUserSidString(
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

    POOL_FREE(user, DRIVER_TAG);

    return status;
}


BOOLEAN IsSystemSid(_In_ PCUNICODE_STRING SidString)
{
    static UNICODE_STRING SystemSid = RTL_CONSTANT_STRING(L"S-1-5-18");
    return RtlEqualUnicodeString(SidString, &SystemSid, TRUE);
}


NTSTATUS BuildHKCUPath(
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






