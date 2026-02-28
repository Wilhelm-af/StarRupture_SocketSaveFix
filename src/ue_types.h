#pragma once
#include <cstdint>
#include <cstddef>

// ---------------------------------------------------------------------------
// Offset-based access helpers — no full UE headers needed
// ---------------------------------------------------------------------------

template<typename T>
inline T ReadAt(uintptr_t base, size_t off) {
    return *reinterpret_cast<T*>(base + off);
}

template<typename T>
inline void WriteAt(uintptr_t base, size_t off, T val) {
    *reinterpret_cast<T*>(base + off) = val;
}

// ---------------------------------------------------------------------------
// UObjectBase  (total size 0x28)
//   +0x10  UClass*  ClassPrivate
//   +0x18  FName    NamePrivate   (8 bytes)
// ---------------------------------------------------------------------------
namespace UObjOff {
    constexpr size_t ClassPrivate  = 0x10;
    constexpr size_t NamePrivate   = 0x18;
    constexpr size_t OuterPrivate  = 0x20;
}

// ---------------------------------------------------------------------------
// UStruct  (total size 0xB0)
//   +0x30  uintptr_t*  InheritanceChain   (precomputed ancestor array for fast IsChildOf)
//   +0x38  int32       HierarchyDepth     (index of self in InheritanceChain, 0-based)
//   +0x40  UStruct*    SuperStruct
//   +0x50  FField*     ChildProperties
//   +0x58  int32       PropertiesSize
//
// The InheritanceChain stores (ancestorPtr + 0x30) for each ancestor plus self.
// IsChildOf(target) checks: this->InheritanceChain[target->HierarchyDepth] == (target + 0x30)
// ---------------------------------------------------------------------------
namespace UStructOff {
    constexpr size_t InheritanceChain = 0x30;
    constexpr size_t HierarchyDepth  = 0x38;
    constexpr size_t SuperStruct     = 0x40;
    constexpr size_t ChildProperties = 0x50;
    constexpr size_t PropertiesSize  = 0x58;
}

// ---------------------------------------------------------------------------
// UScriptStruct  (total size 0xC0)
//   +0xB0  EStructFlags   StructFlags
//   +0xB8  ICppStructOps* CppStructOps
// ---------------------------------------------------------------------------
namespace UScriptStructOff {
    constexpr size_t StructFlags  = 0xB0;
    constexpr size_t CppStructOps = 0xB8;
}

// ---------------------------------------------------------------------------
// FUObjectItem  (0x18 per item)
//   +0x00  UObjectBase*  Object
// ---------------------------------------------------------------------------
namespace ItemOff {
    constexpr size_t Object = 0x00;
    constexpr size_t Size   = 0x18;
}

// ---------------------------------------------------------------------------
// FUObjectArray
//   +0x10  TUObjectArray  ObjObjects
//
// TUObjectArray (inside FUObjectArray, starting at +0x10)
//   +0x00  FUObjectItem**  Objects      (array of chunk pointers)
//   +0x14  int32           NumElements
//   +0x1C  int32           NumChunks
//   Elements-per-chunk = 64 * 1024 = 65536
// ---------------------------------------------------------------------------
namespace GUObjOff {
    constexpr size_t ObjObjects = 0x10;
}
namespace TObjOff {
    constexpr size_t Objects     = 0x00;
    constexpr size_t NumElements = 0x14;
    constexpr size_t NumChunks   = 0x1C;
    constexpr int    ChunkSize   = 64 * 1024;
}

// ---------------------------------------------------------------------------
// FName  (8 bytes)
// ---------------------------------------------------------------------------
struct FName {
    uint32_t ComparisonIndex;
    uint32_t Number;
};

// ---------------------------------------------------------------------------
// FString  (TArray<wchar_t>, 16 bytes)
// ---------------------------------------------------------------------------
struct FString {
    wchar_t* Data;
    int32_t  Num;
    int32_t  Max;
};

// ---------------------------------------------------------------------------
// FMassEntityHandle  (8 bytes)
// ---------------------------------------------------------------------------
struct FMassEntityHandle {
    int32_t Index;
    int32_t SerialNumber;
};

// ---------------------------------------------------------------------------
// FName::ToString  —  void __fastcall (const FName* this, FString* out)
// ---------------------------------------------------------------------------
// On x64 Windows there is only one calling convention (MS x64 ABI).
// __fastcall is ignored on x64, so we omit it to avoid MinGW warnings.
using FNameToStringFn = void (*)(const void* namePtr, FString* out);

// ---------------------------------------------------------------------------
// UMassSignalSubsystem::SignalEntity
//   void (UMassSignalSubsystem* this, FName signalName, FMassEntityHandle handle)
// ---------------------------------------------------------------------------
using SignalEntityFn = void (*)(void* signalSubsystem, FName signalName, FMassEntityHandle handle);
