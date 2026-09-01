# Randgrid.sys — static entry and call-site map

- SHA-256: `4150290a810ebebe9f9e6b5bd32c60299f9f34c3d2b6f02b89590ed49a6b895e`
- Size: `13130616` bytes
- Image base: `0x140000000`
- PE entry: `0x140C61000`
- Entry follows: `0x14059A14C`
- Unique entry candidates: `8764`
- `.pdata` ranges: `2191`
- IAT stubs: `656`
- Relative-call targets: `8959`
- Linear instructions: `3478904`
- Decoded executable bytes: `10983063` / `11381760` (`0.9650`)
- Recognized executable-byte coverage: `1.0000`
- Labeled executable-byte coverage: `1.0000`
- Exact IAT call sites: `550` (`550` owned, `0` unresolved)
- Entries owning exact IAT calls: `543`

## Authority inputs

- Pinned input enforced: `True`
- Ghidra catalog SHA-256: `57500f54c76753380a820481b4a94fe8b65624a35aa3f0ef322e63edfc7356cd`
- Ghidra version: `12.1.3`
- Ghidra internal functions: `8105`

## Section coverage

| Section | RVA | Virtual size | Instructions | Decoded | Gaps | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| `.text` | `0x1000` | `11240448` | 3432753 | 10846698 | 393750 | 0.9650 |
| `INIT` | `0xC61000` | `23552` | 8808 | 22747 | 805 | 0.9658 |
| `.text` | `0xC69000` | `117760` | 37343 | 113618 | 4142 | 0.9648 |

## Skipdata remainder (former 3.5%)

- Gap bytes: `398697` in `319626` runs
- Labeled: `398697`
- Semantically recognized: `398697`
- Unknown fallback: `0`
- Run lengths: `{'1': 255938, '2-4': 63181, '5-16': 507, '17+': 0}`

These bytes are in the file. They are not missing code. Linear x64 decode refuses to start an instruction here (legacy 16/32-bit opcodes, invalid VEX/LOCK/REX prefixes, rejected ModR/M groups). The next instruction in the sweep begins immediately after each run.

| Gap class | Bytes |
|---|---:|
| `invalid_escape` | 1502 |
| `invalid_fe` | 17826 |
| `invalid_ff` | 58091 |
| `invalid_modrm` | 31099 |
| `invalid_prefix` | 22252 |
| `invalid_vex` | 17335 |
| `invalid_x87` | 9754 |
| `legacy_ud` | 221038 |
| `orphan_rex` | 19798 |
| `truncated_instruction` | 2 |

| Fine name | Bytes |
|---|---:|
| `group5_/7` | 56539 |
| `AAD` | 25397 |
| `MOV_imm` | 15766 |
| `AAM` | 15293 |
| `group4_/7` | 12246 |
| `PUSHA` | 10571 |
| `JMPF` | 10005 |
| `PUSH_CS` | 9889 |
| `POP_ES` | 9634 |
| `PUSH_ES` | 9631 |
| `PUSH_DS` | 9616 |
| `DAS` | 9607 |
| `POPA` | 9591 |
| `AAA` | 9351 |
| `AAS` | 9325 |
| `BOUND_or_EVEX` | 9321 |
| `POP_SS` | 9300 |
| `PUSH_SS` | 9274 |
| `DAA` | 9272 |
| `POP_DS` | 9254 |
| `CALLF` | 9233 |
| `ALU_imm8_alias` | 9231 |
| `INTO` | 9172 |
| `SALC` | 9071 |
| `C4` | 9070 |

## Entry classification

| Class | Count |
|---|---:|
| `clear` | 73 |
| `clear_msvc` | 49 |
| `clear_wrapper_to_obfuscated` | 27 |
| `iat_call_wrapper` | 192 |
| `iat_stub` | 657 |
| `import_bearing` | 111 |
| `mba_epilogue` | 876 |
| `mba_obfuscated` | 1722 |
| `obfuscated_blob` | 1 |
| `padding` | 5 |
| `thunk` | 980 |
| `undecodable` | 111 |
| `unknown` | 3960 |

## Known labels recovered

| Name | VA | Class | Size |
|---|---|---|---:|
| `MbaBlock_14015CF58` | `0x14015CF58` | `mba_obfuscated` | 3412 |
| `DriverEntry_ObfuscatedBody` | `0x14059A14C` | `mba_obfuscated` | 345 |
| `ProcessNotifyThunk` | `0x140A294E0` | `thunk` | 6021 |
| `ThreadNotifyThunk` | `0x140A2AC70` | `thunk` | 1990 |
| `_guard_dispatch_icall` | `0x140A8CD84` | `iat_stub` | 6 |
| `ProcessNotifyBody` | `0x140A8DB26` | `unknown` | 23 |
| `ThreadNotifyBody` | `0x140A8EDB5` | `unknown` | 14 |
| `ProcessNotify_RegisterPath` | `0x140AA11D6` | `unknown` | 14 |
| `ObRegisterCallbacks_Setup` | `0x140AB2C18` | `thunk` | 1623 |
| `_guard_check_icall` | `0x140AB7BF0` | `thunk` | 2 |
| `DriverEntry` | `0x140C61000` | `thunk` | 44 |

## Largest mapped ranges

| Name | VA | Size | Class | Source |
|---|---|---:|---|---|
| `thunk_FUN_140001005` | `0x140001000` | 2862537 | `obfuscated_blob` | `pdata+ghidra` |
| `thunk_FUN_14051bf55` | `0x140A7A638` | 70692 | `thunk` | `pdata+rel_call_target+ghidra` |
| `thunk_FUN_140a915ab` | `0x140A8D670` | 38755 | `thunk` | `pdata+ghidra` |
| `thunk_FUN_1405a9bbf` | `0x140A5A9C0` | 37296 | `thunk` | `pdata+rel_call_target+ghidra` |
| `thunk_FUN_140a2ad0c` | `0x140A21020` | 33972 | `thunk` | `pdata+ghidra` |
| `thunk_FUN_140668d76` | `0x140AA6E24` | 30173 | `thunk` | `pdata+rel_call_target+ghidra` |
| `wrapper_0x140A6AD60` | `0x140A6AD60` | 27248 | `clear_wrapper_to_obfuscated` | `pdata+ghidra` |
| `wrapper_0x140A63B70` | `0x140A63B70` | 25987 | `clear_wrapper_to_obfuscated` | `pdata+ghidra` |
| `wrapper_0x140A717D0` | `0x140A717D0` | 24554 | `clear_wrapper_to_obfuscated` | `pdata+ghidra` |
| `wrapper___chkstk` | `0x140A3E038` | 24212 | `clear_msvc` | `pdata+rel_call_target+ghidra` |
| `wrapper___chkstk` | `0x140A4A294` | 24119 | `clear_msvc` | `pdata+rel_call_target+ghidra` |
| `thunk_FUN_140655f1d` | `0x140AA1534` | 22766 | `thunk` | `pdata+ghidra` |
| `thunk_FUN_1405c22b4` | `0x140A9BC84` | 21666 | `thunk` | `pdata+ghidra` |
| `clear_msvc_0x140A34BD0` | `0x140A34BD0` | 21437 | `clear_msvc` | `pdata+rel_call_target+ghidra` |
| `thunk_FUN_1405aff78` | `0x140AAE678` | 17824 | `thunk` | `pdata+rel_call_target+ghidra` |
| `clear_msvc_0x140A2EDF8` | `0x140A2EDF8` | 17186 | `clear_msvc` | `pdata+rel_call_target+ghidra` |
| `thunk_FUN_1405b8682` | `0x140A96DD4` | 11726 | `thunk` | `pdata+rel_call_target+ghidra` |
| `wrapper_ExFreePoolWithTag` | `0x140A5242C` | 8875 | `clear_msvc` | `pdata+ghidra` |
| `wrapper_ExFreePoolWithTag` | `0x140A546D8` | 8492 | `clear_msvc` | `pdata+rel_call_target+ghidra` |
| `wrapper_ExFreePoolWithTag` | `0x140A50344` | 8423 | `clear_msvc` | `pdata+rel_call_target+ghidra` |

## Top mnemonics (linear sweep)

| Mnemonic | Count |
|---|---:|
| `add` | 838315 |
| `mov` | 431050 |
| `push` | 173636 |
| `pop` | 129271 |
| `cmp` | 123002 |
| `sub` | 118409 |
| `xor` | 104343 |
| `or` | 90200 |
| `and` | 86932 |
| `xchg` | 86276 |
| `sbb` | 77181 |
| `adc` | 66565 |
| `jmp` | 52654 |
| `movabs` | 46682 |
| `test` | 43257 |
| `in` | 41229 |
| `out` | 39710 |
| `dec` | 38475 |
| `call` | 34082 |
| `imul` | 22413 |

## Interpretation boundary

Instruction coverage is a linear Capstone sweep of every executable section. Recognized skipdata bytes are classified individually as 64-bit #UD encodings, invalid prefixes/VEX/ModR/M, truncated instructions, or other rejected opcodes. Unknown fallback labels are excluded from semantic classified coverage.
A skipdata byte is present in the file. It is not a missing region. Capstone refused to start a 64-bit instruction there; the next linear instruction begins immediately after the skipped run. The taxonomy names the reason.
Exception-directory ranges are loader-consumed unwind facts. In this binary many are MBA epilogue fragments or obfuscated blocks, not conventional compiler functions.
The validated Ghidra catalog contributes 8105 internal entry candidates and is hash-pinned in authority metadata. Entries can overlap because Ghidra bodies, unwind ranges, and linkage stubs are distinct authority surfaces.
IAT call instructions are call sites, never function seeds. Each call receives at most one primary owner: the smallest exact Ghidra body first, otherwise the smallest containing .pdata range, otherwise unresolved.
A mapped instruction or named wrapper is static recovery, not runtime policy, bypass guidance, or a complete deobfuscation of MBA control flow.

The JSON companion lists every entry candidate and exact IAT call site with deterministic primary ownership. The Git-ignored analysis dump contains the full linear instruction stream.
