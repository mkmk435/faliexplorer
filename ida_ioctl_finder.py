"""
IDAPython IOCTL handler discovery for Windows kernel drivers.

Run headless with IDA/idat, for example:

    idat64 -A -S"ida_ioctl_finder.py --json ioctl_handler.json" driver.sys

Or load this file in IDA and call:

    find_ioctl_handler_ida()

The finder covers:
  - WDM dispatch table writes to DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]
  - KMDF/WDF WDF_IO_QUEUE_CONFIG.EvtIoDeviceControl callback registration
"""

from __future__ import annotations

import json
import os
import re
import sys
import traceback
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_idp
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError:
    ida_auto = None
    ida_bytes = None
    ida_entry = None
    ida_funcs = None
    ida_ida = None
    ida_idaapi = None
    ida_idp = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_ua = None
    idautils = None
    idc = None


IRP_MJ_DEVICE_CONTROL = 0x0E

X64_ARG_REGS = ("rcx", "rdx", "r8", "r9")
STACK_BASE_REGS = {"rsp", "esp", "rbp", "ebp"}


@dataclass(frozen=True)
class MemRef:
    base: str
    offset: int


@dataclass
class IoctlHandlerCandidate:
    handler_ea: int
    kind: str
    confidence: int
    registration_ea: int
    registration_func_ea: int
    framework: str
    details: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "handler_ea": self.handler_ea,
            "handler": _fmt_ea(self.handler_ea),
            "handler_name": _name_or_empty(self.handler_ea),
            "kind": self.kind,
            "confidence": self.confidence,
            "registration_ea": self.registration_ea,
            "registration": _fmt_ea(self.registration_ea),
            "registration_function_ea": self.registration_func_ea,
            "registration_function": _fmt_ea(self.registration_func_ea),
            "registration_function_name": _name_or_empty(self.registration_func_ea),
            "framework": self.framework,
            "details": self.details,
        }


def _require_ida() -> None:
    if ida_auto is None:
        raise RuntimeError("ida_ioctl_finder.py must run inside IDA/idat IDAPython")


def _badaddr() -> int:
    return getattr(ida_idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)


def _is_64bit() -> bool:
    if hasattr(ida_ida, "inf_is_64bit"):
        return bool(ida_ida.inf_is_64bit())
    return bool(ida_idaapi.get_inf_structure().is_64bit())


def _ptr_size() -> int:
    return 8 if _is_64bit() else 4


def _wdm_major_function_base_offset() -> int:
    return 0x70 if _is_64bit() else 0x38


def _wdm_device_control_offset() -> int:
    return _wdm_major_function_base_offset() + IRP_MJ_DEVICE_CONTROL * _ptr_size()


def _wdf_evt_io_device_control_offset() -> int:
    # WDF_IO_QUEUE_CONFIG starts callbacks at 0x10:
    # EvtIoDefault, EvtIoRead, EvtIoWrite, EvtIoDeviceControl.
    return 0x10 + (3 * _ptr_size())


def _fmt_ea(ea: Optional[int]) -> Optional[str]:
    if ea is None or ea == _badaddr():
        return None
    return "0x%x" % ea


def _name_or_empty(ea: int) -> str:
    if ea is None or ea == _badaddr():
        return ""
    try:
        return idc.get_name(ea, idc.GN_VISIBLE) or ""
    except Exception:
        return ""


def _canonical_register_name(reg_name: str) -> str:
    reg_name = reg_name.lower().strip()
    reg_name = reg_name.replace("rword", "").replace("dword", "")

    aliases = {
        "rax": {"rax", "eax", "ax", "al", "ah"},
        "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
        "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},
        "rsp": {"rsp", "esp", "sp", "spl"},
    }
    for i in range(8, 16):
        aliases["r%d" % i] = {"r%d" % i, "r%dd" % i, "r%dw" % i, "r%db" % i}

    for canonical, names in aliases.items():
        if reg_name in names:
            return canonical
    return reg_name


def _operand_text(ea: int, operand_index: int) -> str:
    try:
        return (idc.print_operand(ea, operand_index) or "").strip()
    except Exception:
        return ""


def _mnemonic(ea: int) -> str:
    return (idc.print_insn_mnem(ea) or "").lower()


def _split_operands(ea: int) -> List[str]:
    text = idc.generate_disasm_line(ea, 0) or ""
    if ";" in text:
        text = text.split(";", 1)[0]
    mnem = _mnemonic(ea)
    text = text.strip()
    if text.lower().startswith(mnem):
        text = text[len(mnem):].strip()

    parts = []
    depth = 0
    current = []
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def _decode_insn(ea: int):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return None
    return insn


def _operand_type(ea: int, operand_index: int) -> int:
    insn = _decode_insn(ea)
    if insn is None:
        return -1
    return insn.ops[operand_index].type


def _operand_value(ea: int, operand_index: int) -> int:
    try:
        return int(idc.get_operand_value(ea, operand_index))
    except Exception:
        return _badaddr()


def _reg_from_operand(ea: int, operand_index: int) -> Optional[str]:
    insn = _decode_insn(ea)
    if insn is None:
        return None
    op = insn.ops[operand_index]
    if op.type != ida_ua.o_reg:
        reg_name = _operand_text(ea, operand_index)
        if not re.fullmatch(r"[a-z][a-z0-9]*", reg_name.lower()):
            return None
    else:
        # Operand text is more portable across IDA versions than get_reg_name,
        # whose width argument changed in older Python bindings.
        reg_name = _operand_text(ea, operand_index)

    if not reg_name:
        return None
    return _canonical_register_name(reg_name)


def _segment_is_executable(ea: int) -> bool:
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return bool(seg.perm & ida_segment.SEGPERM_EXEC)


def _addr_in_database(ea: int) -> bool:
    return ida_segment.getseg(ea) is not None


def _is_code_ea(ea: int) -> bool:
    if ea is None or ea == _badaddr() or not _addr_in_database(ea):
        return False
    if ida_funcs.get_func(ea) is not None:
        return True
    try:
        if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            return True
    except Exception:
        pass
    return _segment_is_executable(ea)


def _normalize_ea(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    mask = (1 << (_ptr_size() * 8)) - 1
    value = int(value) & mask
    if _addr_in_database(value):
        return value
    return None


def _read_ptr(ea: int) -> Optional[int]:
    try:
        value = ida_bytes.get_qword(ea) if _ptr_size() == 8 else ida_bytes.get_dword(ea)
    except Exception:
        return None
    return _normalize_ea(value)


def _function_start(ea: int) -> int:
    func = ida_funcs.get_func(ea)
    if not func:
        return _badaddr()
    return int(func.start_ea)


def _iter_function_items(func_ea: int) -> Iterable[int]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    return idautils.FuncItems(func.start_ea)


def _iter_functions() -> Iterable[int]:
    return idautils.Functions()


def _entry_ea() -> int:
    try:
        entry_qty = ida_entry.get_entry_qty()
        if entry_qty:
            return ida_entry.get_entry(0)
    except Exception:
        pass
    if hasattr(ida_ida, "inf_get_start_ea"):
        return ida_ida.inf_get_start_ea()
    return ida_idaapi.get_inf_structure().start_ea


def _entry_function_start() -> int:
    entry = _entry_ea()
    if entry == _badaddr():
        return _badaddr()
    return _function_start(entry)


def _parse_ida_int_token(token: str) -> Optional[int]:
    token = token.strip().lower()
    if not token:
        return None
    token = token.replace("offset ", "")
    token = token.replace("ptr ", "")
    token = token.replace("short ", "")
    token = token.replace("near ", "")

    var_match = re.fullmatch(r"var_([0-9a-f]+)", token)
    if var_match:
        return -int(var_match.group(1), 16)

    arg_match = re.fullmatch(r"arg_([0-9a-f]+)", token)
    if arg_match:
        return int(arg_match.group(1), 16)

    if re.fullmatch(r"[0-9a-f]+h", token):
        return int(token[:-1], 16)

    if re.fullmatch(r"0x[0-9a-f]+", token):
        return int(token, 16)

    if re.fullmatch(r"\d+", token):
        return int(token, 10)

    return None


def _extract_mem_ref(operand_text: str) -> Optional[MemRef]:
    text = operand_text.lower()
    text = text.replace("qword ptr", "")
    text = text.replace("dword ptr", "")
    text = text.replace("word ptr", "")
    text = text.replace("byte ptr", "")
    text = text.replace("ds:", "")
    text = text.replace("cs:", "")
    text = text.replace("ss:", "")

    match = re.search(r"\[([^\]]+)\]", text)
    if not match:
        return None

    expr = match.group(1).replace(" ", "")
    reg_matches = re.findall(r"\b(?:r1[0-5]|r[8-9]|[re]?[abcd]x|[re]?[sd]i|[re]?[bs]p)\b", expr)
    base = _canonical_register_name(reg_matches[0]) if reg_matches else ""

    offset = 0
    for sign, token in re.findall(r"([+-]?)([a-z_][a-z0-9_]*|0x[0-9a-f]+|[0-9a-f]+h|\d+)", expr):
        if re.fullmatch(r"(?:r1[0-5]|r[8-9]|[re]?[abcd]x|[re]?[sd]i|[re]?[bs]p)", token):
            continue
        value = _parse_ida_int_token(token)
        if value is None:
            continue
        if sign == "-":
            value = -value
        offset += value

    if not base:
        return None
    return MemRef(base, offset)


def _same_stack_base(a: MemRef, b: MemRef) -> bool:
    return _canonical_register_name(a.base) == _canonical_register_name(b.base)


def _add_mem_offset(mem: MemRef, offset: int) -> MemRef:
    return MemRef(_canonical_register_name(mem.base), mem.offset + offset)


def _resolve_memory_operand(func_ea: int, ea: int, operand_index: int, depth: int = 0) -> Optional[MemRef]:
    raw = _extract_mem_ref(_operand_text(ea, operand_index))
    if raw is None:
        return None

    if raw.base in STACK_BASE_REGS:
        return raw

    if depth >= 4:
        return raw

    base_value = _resolve_register_as_memref(func_ea, ea, raw.base, depth + 1)
    if base_value:
        return _add_mem_offset(base_value, raw.offset)
    return raw


def _instruction_writes_register(ea: int, reg: str) -> bool:
    dst_reg = _reg_from_operand(ea, 0)
    if dst_reg != reg:
        return False

    mnem = _mnemonic(ea)
    return (
        mnem.startswith("mov")
        or mnem in {"lea", "xor", "sub", "add", "and", "or", "pop"}
        or mnem.startswith("cmov")
    )


def _prev_heads(func_ea: int, ea: int, limit: int = 80) -> Iterable[int]:
    cur = ea
    for _ in range(limit):
        cur = idc.prev_head(cur, func_ea)
        if cur == _badaddr() or cur < func_ea:
            return
        yield cur


def _resolve_register_as_memref(func_ea: int, ea: int, reg: str, depth: int = 0) -> Optional[MemRef]:
    if depth >= 5:
        return None

    reg = _canonical_register_name(reg)
    for prev in _prev_heads(func_ea, ea):
        if not _instruction_writes_register(prev, reg):
            continue

        mnem = _mnemonic(prev)
        if mnem == "lea":
            return _resolve_memory_operand(func_ea, prev, 1, depth + 1)

        if mnem.startswith("mov"):
            src_reg = _reg_from_operand(prev, 1)
            if src_reg:
                return _resolve_register_as_memref(func_ea, prev, src_reg, depth + 1)
            return None

        return None

    return None


def _resolve_operand_as_code(func_ea: int, ea: int, operand_index: int, depth: int = 0) -> Optional[int]:
    if depth >= 6:
        return None

    op_type = _operand_type(ea, operand_index)
    value = _normalize_ea(_operand_value(ea, operand_index))
    text = _operand_text(ea, operand_index).lower()

    if value is not None and _is_code_ea(value):
        return value

    if value is not None and op_type in {ida_ua.o_mem, ida_ua.o_displ}:
        pointed = _read_ptr(value)
        if pointed is not None and _is_code_ea(pointed):
            return pointed

    reg = _reg_from_operand(ea, operand_index)
    if reg:
        return _resolve_register_as_code(func_ea, ea, reg, depth + 1)

    name_match = re.search(r"(?:offset\s+)?([A-Za-z_][A-Za-z0-9_$@?]*)", text)
    if name_match:
        ea_by_name = idc.get_name_ea_simple(name_match.group(1))
        ea_by_name = _normalize_ea(ea_by_name)
        if ea_by_name is not None and _is_code_ea(ea_by_name):
            return ea_by_name

    return None


def _resolve_register_as_code(func_ea: int, ea: int, reg: str, depth: int = 0) -> Optional[int]:
    if depth >= 6:
        return None

    reg = _canonical_register_name(reg)
    for prev in _prev_heads(func_ea, ea):
        if not _instruction_writes_register(prev, reg):
            continue

        mnem = _mnemonic(prev)
        if mnem == "lea":
            value = _normalize_ea(_operand_value(prev, 1))
            if value is not None and _is_code_ea(value):
                return value
            return None

        if mnem.startswith("mov"):
            src_reg = _reg_from_operand(prev, 1)
            if src_reg:
                return _resolve_register_as_code(func_ea, prev, src_reg, depth + 1)
            return _resolve_operand_as_code(func_ea, prev, 1, depth + 1)

        return None

    return None


def _reg_derives_from_driver_object_arg(func_ea: int, ea: int, reg: str) -> bool:
    reg = _canonical_register_name(reg)
    entry_func = _entry_function_start()

    if _is_64bit():
        if func_ea == entry_func and reg == "rcx":
            return True
        for prev in _prev_heads(func_ea, ea):
            if not _instruction_writes_register(prev, reg):
                continue
            src_reg = _reg_from_operand(prev, 1)
            if src_reg:
                src_reg = _canonical_register_name(src_reg)
                if func_ea == entry_func and src_reg == "rcx":
                    return True
                return _reg_derives_from_driver_object_arg(func_ea, prev, src_reg)
            return False
        return False

    for prev in _prev_heads(func_ea, ea):
        if not _instruction_writes_register(prev, reg):
            continue
        src_text = _operand_text(prev, 1).lower()
        if "arg_0" in src_text or "[esp+4" in src_text.replace(" ", ""):
            return True
        src_reg = _reg_from_operand(prev, 1)
        if src_reg:
            return _reg_derives_from_driver_object_arg(func_ea, prev, src_reg)
        return False
    return False


def _normalize_import_name(name: str) -> str:
    name = (name or "").strip()
    name = name.replace("__imp_", "").replace("_imp_", "")
    name = name.lstrip("_")
    name = name.split("@@", 1)[0]
    name = re.sub(r"@\d+$", "", name)
    return name.lower()


def _collect_imports() -> Tuple[Dict[str, List[int]], Dict[str, List[str]]]:
    imports: Dict[str, List[int]] = {}
    modules: Dict[str, List[str]] = {}
    qty = ida_nalt.get_import_module_qty()

    for index in range(qty):
        module_name = ida_nalt.get_import_module_name(index) or ""
        modules.setdefault(module_name.lower(), [])

        def _cb(ea, name, ordinal):
            normalized = _normalize_import_name(name or "")
            if normalized:
                imports.setdefault(normalized, []).append(ea)
                modules.setdefault(module_name.lower(), []).append(normalized)
            return True

        ida_nalt.enum_import_names(index, _cb)

    return imports, modules


def detect_driver_framework_ida() -> str:
    _require_ida()
    imports, modules = _collect_imports()
    if "wdf01000.sys" in modules or "wdfldr.sys" in modules:
        return "kmdf/wdf"
    if any(name.startswith("wdf") for name in imports):
        return "kmdf/wdf"

    wdm_markers = {
        "iocreatedevice",
        "iocreatedevicesecure",
        "iocreatesymboliclink",
        "iodeletedevice",
        "iodeletesymboliclink",
    }
    if imports.keys() & wdm_markers:
        return "wdm"
    return "unknown"


def _call_operand_mentions(ea: int, import_name: str) -> bool:
    needle = import_name.lower()
    op_text = _operand_text(ea, 0).lower()
    if needle in op_text:
        return True

    op_value = _normalize_ea(_operand_value(ea, 0))
    if op_value is None:
        return False

    names = [idc.get_name(op_value, idc.GN_VISIBLE) or ""]
    pointed = _read_ptr(op_value)
    if pointed is not None:
        names.append(idc.get_name(pointed, idc.GN_VISIBLE) or "")

    return any(needle in name.lower() for name in names)


def _calls_known_import(ea: int, import_name: str, imports: Dict[str, List[int]]) -> bool:
    if _mnemonic(ea) != "call":
        return False

    normalized = _normalize_import_name(import_name)
    if _call_operand_mentions(ea, import_name):
        return True

    op_value = _normalize_ea(_operand_value(ea, 0))
    if op_value is None:
        return False

    import_eas = set(imports.get(normalized, []))
    if op_value in import_eas:
        return True

    pointed = _read_ptr(op_value)
    return pointed in import_eas


def _nearby_major_function_writes(func_ea: int, ea: int, base_reg: str) -> int:
    base_reg = _canonical_register_name(base_reg)
    score = 0
    start = max(func_ea, ea - 0x120)
    end = min(idc.get_func_attr(func_ea, idc.FUNCATTR_END), ea + 0x120)
    cur = start
    major_base = _wdm_major_function_base_offset()
    interesting = {major_base + i * _ptr_size() for i in range(0, 28)}
    while cur != _badaddr() and cur < end:
        if _mnemonic(cur).startswith("mov"):
            dst = _extract_mem_ref(_operand_text(cur, 0))
            if dst and _canonical_register_name(dst.base) == base_reg and dst.offset in interesting:
                score += 2
        cur = idc.next_head(cur, end)
    return min(score, 12)


def find_wdm_ioctl_handlers_ida() -> List[IoctlHandlerCandidate]:
    _require_ida()
    candidates: List[IoctlHandlerCandidate] = []
    target_offset = _wdm_device_control_offset()
    entry_func = _entry_function_start()

    for func_ea in _iter_functions():
        for ea in _iter_function_items(func_ea):
            mnem = _mnemonic(ea)
            if not (mnem.startswith("mov") or mnem == "lea"):
                continue

            dst_text = _operand_text(ea, 0)
            dst_mem = _extract_mem_ref(dst_text)
            if not dst_mem:
                continue

            normalized_dst = dst_text.lower().replace(" ", "")
            field_hint = "majorfunction" in dst_text.lower() and (
                "device" in dst_text.lower() or "control" in dst_text.lower()
            )
            loop_table_hint = (
                dst_mem.offset == _wdm_major_function_base_offset()
                and ("*%d" % _ptr_size()) in normalized_dst
            )
            if dst_mem.offset != target_offset and not field_hint and not loop_table_hint:
                continue

            handler = _resolve_operand_as_code(func_ea, ea, 1)
            if handler is None or not _is_code_ea(handler):
                continue

            confidence = 35
            details = ["DriverObject MajorFunction write"]
            if loop_table_hint:
                confidence -= 10
                details.append("loop/table write covers MajorFunction[]")
            if func_ea == entry_func:
                confidence += 20
                details.append("inside DriverEntry")
            if _reg_derives_from_driver_object_arg(func_ea, ea, dst_mem.base):
                confidence += 20
                details.append("base register derives from DriverEntry DriverObject")
            if field_hint:
                confidence += 10
                details.append("IDA operand has MajorFunction/device-control field hint")
            confidence += _nearby_major_function_writes(func_ea, ea, dst_mem.base)

            handler_name = _name_or_empty(handler).lower()
            if any(token in handler_name for token in ("ioctl", "devicecontrol", "device_control", "dispatch")):
                confidence += 8

            candidates.append(
                IoctlHandlerCandidate(
                    handler_ea=handler,
                    kind="wdm",
                    confidence=confidence,
                    registration_ea=ea,
                    registration_func_ea=func_ea,
                    framework="wdm",
                    details="; ".join(details),
                )
            )

    candidates.sort(key=lambda c: (c.confidence, c.registration_func_ea == entry_func), reverse=True)
    return candidates


def _trace_x64_arg_memref(func_ea: int, call_ea: int, reg: str) -> Optional[MemRef]:
    reg = _canonical_register_name(reg)
    return _resolve_register_as_memref(func_ea, call_ea, reg)


def _trace_x86_push_arg_memrefs(func_ea: int, call_ea: int) -> List[Optional[MemRef]]:
    pushes: List[Optional[MemRef]] = []
    for prev in _prev_heads(func_ea, call_ea, limit=60):
        mnem = _mnemonic(prev)
        if mnem == "call":
            break
        if mnem != "push":
            continue

        reg = _reg_from_operand(prev, 0)
        if reg:
            pushes.append(_resolve_register_as_memref(func_ea, prev, reg))
        else:
            pushes.append(_resolve_memory_operand(func_ea, prev, 0))

        if len(pushes) >= 6:
            break

    return pushes


def _iter_wdf_queue_call_contexts(func_ea: int, imports: Dict[str, List[int]]) -> Iterable[Tuple[int, MemRef, int, bool]]:
    for ea in _iter_function_items(func_ea):
        if _mnemonic(ea) != "call":
            continue

        known_wdf_call = _calls_known_import(ea, "WdfIoQueueCreate", imports)

        if _is_64bit():
            # Direct API: Config is arg1/RDX. Inline WdfFunctions call: Config is arg2/R8.
            for arg_index, reg in ((1, "rdx"), (2, "r8")):
                mem = _trace_x64_arg_memref(func_ea, ea, reg)
                if mem:
                    yield ea, mem, arg_index, known_wdf_call
        else:
            pushes = _trace_x86_push_arg_memrefs(func_ea, ea)
            # pushes[0] is arg0, because it is the nearest push before call.
            for arg_index in (1, 2):
                if arg_index < len(pushes) and pushes[arg_index]:
                    yield ea, pushes[arg_index], arg_index, known_wdf_call


def _nearby_wdf_config_init_score(func_ea: int, assign_ea: int, config_ref: MemRef) -> int:
    score = 0
    func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    start = max(func_ea, assign_ea - 0x180)
    end = min(func_end, assign_ea + 0x80)
    cur = start
    while cur != _badaddr() and cur < end:
        mnem = _mnemonic(cur)
        if mnem.startswith("mov"):
            dst = _resolve_memory_operand(func_ea, cur, 0)
            if dst and _same_stack_base(dst, config_ref):
                diff = dst.offset - config_ref.offset
                imm = _operand_value(cur, 1)
                if diff == 0 and 0x10 <= imm <= 0x300:
                    score += 8
                elif diff in {4, 8, 0x0C}:
                    score += 2
        cur = idc.next_head(cur, end)
    return min(score, 16)


def find_wdf_ioctl_handlers_ida() -> List[IoctlHandlerCandidate]:
    _require_ida()
    imports, modules = _collect_imports()
    has_wdf_import = (
        "wdf01000.sys" in modules
        or "wdfldr.sys" in modules
        or any(name.startswith("wdf") for name in imports)
    )
    if not has_wdf_import:
        return []

    candidates: List[IoctlHandlerCandidate] = []
    evt_offset = _wdf_evt_io_device_control_offset()

    for func_ea in _iter_functions():
        call_contexts = list(_iter_wdf_queue_call_contexts(func_ea, imports))
        has_known_wdf_queue_call = any(ctx[3] for ctx in call_contexts)

        for ea in _iter_function_items(func_ea):
            if not _mnemonic(ea).startswith("mov"):
                continue

            dst_text = _operand_text(ea, 0)
            dst = _resolve_memory_operand(func_ea, ea, 0)
            if not dst:
                continue

            handler = _resolve_operand_as_code(func_ea, ea, 1)
            if handler is None or not _is_code_ea(handler):
                continue

            field_hint = "evtiodevicecontrol" in dst_text.lower()
            best_score = 0
            best_call_ea = _badaddr()
            best_arg_index = -1
            best_details: List[str] = []

            if field_hint:
                best_score += 60
                best_details.append("IDA operand has EvtIoDeviceControl field hint")

            for call_ea, config_ref, arg_index, known_wdf_call in call_contexts:
                if call_ea < ea:
                    continue
                if call_ea - ea > 0x300:
                    continue
                if not _same_stack_base(dst, config_ref):
                    continue

                diff = dst.offset - config_ref.offset
                if diff != evt_offset:
                    continue

                init_score = _nearby_wdf_config_init_score(func_ea, ea, config_ref)
                if not known_wdf_call and not field_hint and init_score == 0:
                    continue

                score = 50
                details = ["store is Config+0x%x before queue creation call" % evt_offset]
                if known_wdf_call:
                    score += 25
                    details.append("call resolves to WdfIoQueueCreate")
                else:
                    score += 8
                    details.append("call uses Config as a WDF-style argument")
                if arg_index == 2:
                    score += 5
                    details.append("Config position matches inline WdfFunctions wrapper")
                score += init_score

                if score > best_score:
                    best_score = score
                    best_call_ea = call_ea
                    best_arg_index = arg_index
                    best_details = details

            if not best_score:
                if not field_hint or not has_known_wdf_queue_call:
                    continue
                best_score = 45
                best_details = ["field hint in function with WdfIoQueueCreate call"]

            confidence = 30 + best_score
            handler_name = _name_or_empty(handler).lower()
            if any(token in handler_name for token in ("ioctl", "devicecontrol", "device_control")):
                confidence += 8
            if has_known_wdf_queue_call:
                confidence += 5

            details = best_details[:]
            if best_arg_index >= 0:
                details.append("config_arg_index=%d" % best_arg_index)

            candidates.append(
                IoctlHandlerCandidate(
                    handler_ea=handler,
                    kind="wdf_evt_io_device_control",
                    confidence=confidence,
                    registration_ea=ea,
                    registration_func_ea=func_ea,
                    framework="kmdf/wdf",
                    details="; ".join(details),
                )
            )

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


def find_ioctl_handler_candidates_ida() -> List[IoctlHandlerCandidate]:
    _require_ida()
    ida_auto.auto_wait()

    candidates = []
    candidates.extend(find_wdf_ioctl_handlers_ida())
    candidates.extend(find_wdm_ioctl_handlers_ida())
    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


def find_ioctl_handler_ida(return_all: bool = False):
    """
    Return the best IOCTL handler candidate found by IDAPython.

    By default this returns ``(handler_ea, metadata_dict)`` so callers can use
    it as a static analogue of utils.find_ioctl_handler(...). There is no angr
    state in IDA, so metadata describes how the handler was registered.

    If ``return_all`` is True, return a list of IoctlHandlerCandidate objects.
    """
    candidates = find_ioctl_handler_candidates_ida()
    if return_all:
        return candidates
    if not candidates:
        return None, None
    best = candidates[0]
    return best.handler_ea, best.to_dict()


def _print_candidates(candidates: Sequence[IoctlHandlerCandidate]) -> None:
    if not candidates:
        print("ERROR: unable to find IOCTL handler")
        return

    best = candidates[0]
    print(
        "IOCTL handler: %s (%s, confidence=%d, kind=%s)"
        % (_fmt_ea(best.handler_ea), _name_or_empty(best.handler_ea), best.confidence, best.kind)
    )
    print(
        "Registered at %s in %s (%s)"
        % (
            _fmt_ea(best.registration_ea),
            _fmt_ea(best.registration_func_ea),
            _name_or_empty(best.registration_func_ea),
        )
    )
    print("Details: %s" % best.details)


def _write_json(path: str, candidates: Sequence[IoctlHandlerCandidate]) -> None:
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.abspath(path)

    data = {
        "handler": candidates[0].to_dict() if candidates else None,
        "candidates": [candidate.to_dict() for candidate in candidates],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print("Wrote %s" % path)


def _ida_is_batch() -> bool:
    try:
        return bool(getattr(ida_kernwin.cvar, "batch", 0))
    except Exception:
        return False


def _script_args() -> List[str]:
    raw = list(getattr(idc, "ARGV", []) or [])
    if not raw:
        return list(sys.argv[1:])

    first = os.path.basename(str(raw[0])).lower()
    if first.endswith(".py"):
        return [str(arg) for arg in raw[1:]]
    return [str(arg) for arg in raw]


def main(argv: Optional[Sequence[str]] = None) -> int:
    _require_ida()
    if argv is None:
        argv = _script_args()

    json_path = None
    print_all = False
    no_exit = not _ida_is_batch()
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--json" and idx + 1 < len(argv):
            json_path = argv[idx + 1]
            idx += 2
        elif arg == "--all":
            print_all = True
            idx += 1
        elif arg == "--no-exit":
            no_exit = True
            idx += 1
        else:
            idx += 1

    candidates = find_ioctl_handler_candidates_ida()
    _print_candidates(candidates)

    if print_all:
        for candidate in candidates[1:]:
            print(
                "candidate: %s kind=%s confidence=%d registration=%s details=%s"
                % (
                    _fmt_ea(candidate.handler_ea),
                    candidate.kind,
                    candidate.confidence,
                    _fmt_ea(candidate.registration_ea),
                    candidate.details,
                )
            )

    if json_path:
        _write_json(json_path, candidates)

    if not no_exit:
        idc.qexit(0 if candidates else 1)
    return 0 if candidates else 1


def _ida_script_entry_requested() -> bool:
    if ida_auto is None:
        return False

    argv = [str(arg) for arg in list(getattr(idc, "ARGV", []) or [])]
    if not argv:
        return False

    if any(os.path.basename(arg).lower() == "ida_ioctl_finder.py" for arg in argv):
        return True
    return any(arg in {"--json", "--all", "--no-exit"} for arg in argv)


def _write_error_log() -> str:
    path = os.path.abspath("ida_ioctl_finder_error.txt")
    with open(path, "w") as f:
        traceback.print_exc(file=f)
    return path


def _run_script_entrypoint() -> int:
    try:
        return main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        try:
            print("Wrote %s" % _write_error_log())
        except Exception:
            pass
        if ida_auto is not None and _ida_is_batch():
            idc.qexit(2)
        return 2


if __name__ == "__main__":
    _run_script_entrypoint()
elif _ida_script_entry_requested():
    _run_script_entrypoint()
