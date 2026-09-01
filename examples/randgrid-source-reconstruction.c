/*
 * Best-effort source-like examples for the pinned Randgrid.sys static map.
 * This is NOT original source and deliberately contains no operational driver logic.
 * Input SHA-256: 4150290a810ebebe9f9e6b5bd32c60299f9f34c3d2b6f02b89590ed49a6b895e
 */

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define RG_UNUSED __attribute__((unused))
#else
#define RG_UNUSED
#endif

static RG_UNUSED void example_MbaBlock_14015CF58_0x14015CF58(void) { /* 0x14015CF58 known_static_label confidence=high */
    /* 0x14015CF58 68edc49f7f | push 0x7f9fc4ed */
    /* 0x14015CF5D 4883ec08 | sub rsp, 8 */
    /* 0x14015CF61 68aa41e56f | push 0x6fe541aa */
    /* 0x14015CF66 48891424 | mov qword ptr [rsp], rdx */
    /* 0x14015CF6A 8f0424 | pop qword ptr [rsp] */
    /* 0x14015CF6D 8f0424 | pop qword ptr [rsp] */
    /* 0x14015CF70 4883ec08 | sub rsp, 8 */
    /* 0x14015CF74 4881ec08000000 | sub rsp, 8 */
    /* 0x14015CF7B 53 | push rbx */
    /* 0x14015CF7C 8f0424 | pop qword ptr [rsp] */
    /* 0x14015CF7F 8f0424 | pop qword ptr [rsp] */
    /* 0x14015CF82 68c044ab4f | push 0x4fab44c0 */
    /* 0x14015CF87 6813335f2e | push 0x2e5f3313 */
    /* 0x14015CF8C 4883ec08 | sub rsp, 8 */
    /* 0x14015CF90 48891c24 | mov qword ptr [rsp], rbx */
    /* 0x14015CF94 8f0424 | pop qword ptr [rsp] */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_DriverEntry_ObfuscatedBody_0x14059A14C(void) { /* 0x14059A14C known_static_label confidence=high */
    /* 0x14059A14C 9c | pushfq */
    /* 0x14059A14D 685b74d37c | push 0x7cd3745b */
    /* 0x14059A152 48890c24 | mov qword ptr [rsp], rcx */
    /* 0x14059A156 4889c9 | mov rcx, rcx */
    /* 0x14059A159 50 | push rax */
    /* 0x14059A15A 52 | push rdx */
    /* 0x14059A15B 48ba0b01000000000000 | movabs rdx, 0x10b */
    /* 0x14059A165 4889d0 | mov rax, rdx */
    /* 0x14059A168 5a | pop rdx */
    /* 0x14059A169 50 | push rax */
    /* 0x14059A16A 8f442408 | pop qword ptr [rsp + 8] */
    /* 0x14059A16E 58 | pop rax */
    /* 0x14059A16F 682a5ebf6f | push 0x6fbf5e2a */
    /* 0x14059A174 4c891c24 | mov qword ptr [rsp], r11 */
    /* 0x14059A178 4d89db | mov r11, r11 */
    /* 0x14059A17B 52 | push rdx */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ProcessNotifyThunk_0x140A294E0(void) { /* 0x140A294E0 known_static_label confidence=high */
    /* 0x140A294E0 e941460600 | jmp 0x140a8db26 */
    /* 0x140A294E5 4d33c2 | xor r8, r10 */
    /* 0x140A294E8 4c33c1 | xor r8, rcx */
    /* 0x140A294EB 4d8bcb | mov r9, r11 */
    /* 0x140A294EE 49c1c913 | ror r9, 0x13 */
    /* 0x140A294F2 4c894c2430 | mov qword ptr [rsp + 0x30], r9 */
    /* 0x140A294F7 498bc4 | mov rax, r12 */
    /* 0x140A294FA 48c1c822 | ror rax, 0x22 */
    /* 0x140A294FE 4833c7 | xor rax, rdi */
    /* 0x140A29501 4c33e0 | xor r12, rax */
    /* 0x140A29504 498bc1 | mov rax, r9 */
    /* 0x140A29507 e96e592400 | jmp 0x140c6ee7a */
    /* 0x140A2950C 48895c2430 | mov qword ptr [rsp + 0x30], rbx */
    /* 0x140A29511 4c8bde | mov r11, rsi */
    /* 0x140A29514 49f7d3 | not r11 */
    /* 0x140A29517 e99c96ffff | jmp 0x140a22bb8 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ThreadNotifyThunk_0x140A2AC70(void) { /* 0x140A2AC70 known_static_label confidence=high */
    /* 0x140A2AC70 e940410600 | jmp 0x140a8edb5 */
    /* 0x140A2AC75 cc | int3 */
    /* 0x140A2AC76 c505694933 | vpunpckhwd ymm9, ymm15, ymmword ptr [rcx + 0x33] */
    /* 0x140A2AC7B c04c33f048 | ror byte ptr [rbx + rsi - 0x10], 0x48 */
    /* 0x140A2AC80 8bc1 | mov eax, ecx */
    /* 0x140A2AC82 4833c2 | xor rax, rdx */
    /* 0x140A2AC85 48c1c909 | ror rcx, 9 */
    /* 0x140A2AC89 48894c2420 | mov qword ptr [rsp + 0x20], rcx */
    /* 0x140A2AC8E 4833c8 | xor rcx, rax */
    /* 0x140A2AC91 48894c2420 | mov qword ptr [rsp + 0x20], rcx */
    /* 0x140A2AC96 498bd6 | mov rdx, r14 */
    /* 0x140A2AC99 e9d5102400 | jmp 0x140c6bd73 */
    /* 0x140A2AC9E cc | int3 */
    /* 0x140A2AC9F e65b | out 0x5b, al */
    /* 0x140A2ACA1 ff1591070900 | call qword ptr [rip + 0x90791] */
    /* 0x140A2ACA7 90 | nop */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example__guard_dispatch_icall_0x140A8CD84(void) { /* 0x140A8CD84 known_static_label confidence=high */
    /* 0x140A8CD84 ff254ee80200 | jmp qword ptr [rip + 0x2e84e] */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ProcessNotifyBody_0x140A8DB26(void) { /* 0x140A8DB26 known_static_label confidence=high */
    /* 0x140A8DB26 48895c2408 | mov qword ptr [rsp + 8], rbx */
    /* 0x140A8DB2B 4889742410 | mov qword ptr [rsp + 0x10], rsi */
    /* 0x140A8DB30 48897c2420 | mov qword ptr [rsp + 0x20], rdi */
    /* 0x140A8DB35 55 | push rbp */
    /* 0x140A8DB36 4154 | push r12 */
    /* 0x140A8DB38 e96a650000 | jmp 0x140a940a7 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ThreadNotifyBody_0x140A8EDB5(void) { /* 0x140A8EDB5 known_static_label confidence=high */
    /* 0x140A8EDB5 4584c0 | test r8b, r8b */
    /* 0x140A8EDB8 0f8477c6f9ff | je 0x140a2b435 */
    /* 0x140A8EDBE e9b2ed1d00 | jmp 0x140c6db75 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ProcessNotify_RegisterPath_0x140AA11D6(void) { /* 0x140AA11D6 known_static_label confidence=high */
    /* 0x140AA11D6 33d2 | xor edx, edx */
    /* 0x140AA11D8 488d0d0183f8ff | lea rcx, [rip - 0x77cff] */
    /* 0x140AA11DF e90e010000 | jmp 0x140aa12f2 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_iat_wrapper_PsSetCreateProcessNotifyRoutineEx_0x140AA12F2(void) { /* 0x140AA12F2 ghidra_function confidence=medium */
    /* 0x140AA12F2 ff15d8a10100 | call qword ptr [rip + 0x1a1d8] */
    /* 0x140AA12F8 90 | nop */
    /* 0x140AA12F9 eb80 | jmp 0x140aa127b */
    /* exact IAT call 0x140AA12F2: PsSetCreateProcessNotifyRoutineEx via direct_iat */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_iat_wrapper_PsSetCreateThreadNotifyRoutine_0x140AA130F(void) { /* 0x140AA130F ghidra_function confidence=medium */
    /* 0x140AA130F ff15fb9e0100 | call qword ptr [rip + 0x19efb] */
    /* 0x140AA1315 90 | nop */
    /* 0x140AA1316 eb80 | jmp 0x140aa1298 */
    /* exact IAT call 0x140AA130F: PsSetCreateThreadNotifyRoutine via direct_iat */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_ObRegisterCallbacks_Setup_0x140AB2C18(void) { /* 0x140AB2C18 known_static_label confidence=high */
    /* 0x140AB2C18 e951f9fdff | jmp 0x140a9256e */
    /* 0x140AB2C1D 44897c2450 | mov dword ptr [rsp + 0x50], r15d */
    /* 0x140AB2C22 4c8d8dc8000000 | lea r9, [rbp + 0xc8] */
    /* 0x140AB2C29 4c897c2448 | mov qword ptr [rsp + 0x48], r15 */
    /* 0x140AB2C2E 4c8d8590010000 | lea r8, [rbp + 0x190] */
    /* 0x140AB2C35 897c2440 | mov dword ptr [rsp + 0x40], edi */
    /* 0x140AB2C39 488d4d00 | lea rcx, [rbp] */
    /* 0x140AB2C3D 4489642438 | mov dword ptr [rsp + 0x38], r12d */
    /* 0x140AB2C42 ba89001200 | mov edx, 0x120089 */
    /* 0x140AB2C47 4489642430 | mov dword ptr [rsp + 0x30], r12d */
    /* 0x140AB2C4C c744242880000000 | mov dword ptr [rsp + 0x28], 0x80 */
    /* 0x140AB2C54 4c897c2420 | mov qword ptr [rsp + 0x20], r15 */
    /* 0x140AB2C59 4c897d00 | mov qword ptr [rbp], r15 */
    /* 0x140AB2C5D 0f1185c8000000 | movups xmmword ptr [rbp + 0xc8], xmm0 */
    /* 0x140AB2C64 c7859001000030000000 | mov dword ptr [rbp + 0x190], 0x30 */
    /* 0x140AB2C6E 4c89bd98010000 | mov qword ptr [rbp + 0x198], r15 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_iat_wrapper_ObRegisterCallbacks_0x140AB309D(void) { /* 0x140AB309D ghidra_function confidence=medium */
    /* 0x140AB309D ff15d57c0000 | call qword ptr [rip + 0x7cd5] */
    /* 0x140AB30A3 90 | nop */
    /* 0x140AB30A4 e9fd00feff | jmp 0x140a931a6 */
    /* exact IAT call 0x140AB309D: ObRegisterCallbacks via direct_iat */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example__guard_check_icall_0x140AB7BF0(void) { /* 0x140AB7BF0 known_static_label confidence=high */
    /* 0x140AB7BF0 ebdf | jmp 0x140ab7bd1 */
    /* Opaque MBA/control flow remains unresolved. */
}

static RG_UNUSED void example_DriverEntry_0x140C61000(void) { /* 0x140C61000 pe_entry confidence=high */
    /* 0x140C61000 e9479193ff | jmp 0x14059a14c */
    /* 0x140C61005 50 | push rax */
    /* 0x140C61006 e93d3a0213 | jmp 0x153c84a48 */
    /* 0x140C6100B d0b200ae5869 | sal byte ptr [rdx + 0x6958ae00], 1 */
    /* 0x140C61011 8eef | mov gs, edi */
    /* 0x140C61013 e861641bab | call 0xebe17479 */
    /* 0x140C61018 a1a43fd4966c5d629d | movabs eax, dword ptr [0x9d625d6c96d43fa4] */
    /* 0x140C61021 09de | or esi, ebx */
    /* Opaque MBA/control flow remains unresolved. */
}
