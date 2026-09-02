#include "Structs.h"





NTSTATUS FastUnicodeToUpper(
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
        POOL_FREE(Destination->Buffer, DRIVER_TAG);
        Destination->Buffer = NULL;
        Destination->MaximumLength = 0;
        Destination->Length = 0;
    }

    // Always allocate fresh
    Destination->MaximumLength = Source->Length + sizeof(WCHAR);
    Destination->Buffer = (PWCH)POOL_ALLOC(
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

ULONG HashEntry(_In_ PUNICODE_STRING KeyPath, _In_opt_ PUNICODE_STRING ValueName)
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

NTSTATUS InitializeHashTable(_Out_ PHASH_TABLE Table, ULONG Size)
{
    UNREFERENCED_PARAMETER(Size);
    if (!Table || HASH_TABLE_SIZE == 0)
        return STATUS_INVALID_PARAMETER;

    // Zero the entire structure including all buckets
    RtlZeroMemory(Table, sizeof(HASH_TABLE));
    Table->Count = 0;

    return STATUS_SUCCESS;
}






NTSTATUS AddToHashTable(_Inout_ PHASH_TABLE Table, ULONG Hash, ULONG EntryIndex)
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

    PHASH_NODE NewNode = (PHASH_NODE)POOL_ALLOC(sizeof(HASH_NODE), DRIVER_TAG);
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






NTSTATUS InitializeProtections()
{
    NTSTATUS status;

    status = InitializeHashTable(&g_HashTableUnified, HASH_TABLE_SIZE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[RegF] InitializeProtections failed: 0x%08X\n", status);
        return status;
    }

    for (ULONG u = 0; u < UNIFIED_PROTECTION_COUNT; u++)
    {
        PREGISTRY_PROTECTION_ENTRY entry = &g_UnifiedProtections[u];
        DbgPrint("[RegF] INIT[%lu]: keypath=%wZ valname=%wZ flags=%X\n",
            u, &entry->KeyPath, &entry->ValueName, entry->Flags);


        status = FastUnicodeToUpper(&entry->KeyPath, &entry->KeyPathUpper);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[RegF] FastUnicodeToUpper(KeyPath) failed: 0x%08X\n", status);
            return status;
        }


        if (entry->ValueName.Buffer)
        {
            status = FastUnicodeToUpper(&entry->ValueName, &entry->ValueNameUpper);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[RegF] FastUnicodeToUpper(Value) failed: 0x%08X\n", status);
                return status;
            }
        }
        if (entry->Flags & PROTECT_FLAG_WILDCARD) {
            entry->Hash = HashEntry(&entry->KeyPathUpper, NULL);
        }
        else {
            entry->Hash = HashEntry(&entry->KeyPathUpper,
                entry->ValueNameUpper.Buffer ? &entry->ValueNameUpper : NULL);
        }

        status = AddToHashTable(&g_HashTableUnified, entry->Hash, u);
        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
}




BOOLEAN LookupHashTable(
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

        // In LookupHashTable, replace the value check block with:
        if (entry->ValueNameUpper.Buffer)
        {
            // Entry has a value name requirement
            if (entry->Flags & PROTECT_FLAG_WILDCARD)
            {
                // Wildcard entry: matches any value, skip value check
            }
            else
            {
                // Exact value match required
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
        }
        // If entry has no ValueNameUpper.Buffer, no value check needed

        *EntryIndex = node->EntryIndex;
        return TRUE;
    }

    return FALSE;
}

// Enhanced CleanupHashTable
VOID CleanupHashTable(_Inout_ PHASH_TABLE Table)
{
    if (!Table) return;


    for (ULONG i = 0; i < HASH_TABLE_SIZE; ++i) {
        PHASH_NODE current = Table->Buckets[i];
        ULONG bucketCount = 0;

        while (current) {
            PHASH_NODE toFree = current;
            current = current->Next;
            POOL_FREE(toFree, DRIVER_TAG);
            bucketCount++;
        }

        Table->Buckets[i] = NULL;
    }

    Table->Count = 0;
}
