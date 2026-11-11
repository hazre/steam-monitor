"""Zero-seed IPC resolver: steamclient64.dll in, ipc/steamclient/<sha>.toml out.

Emits the IPC TOML schema the client parses in IPCLoader.cpp:
per-interface [Name] (interface_id, vtable_rva) plus per-method
[Name.Method] (method_index, funcHash, wrapper_rva, fencepost, argc).

funcHash / fencepost values are wire constants the wrapper writes into the
outgoing IPC buffer (4-byte appends). They are NOT build-stable: the
1792192922 beta re-rolled five of six methods. Re-derive on failure:
disassemble the slot's wrapper, find each `mov dword ptr [..], imm32`
followed by the 4-byte append helper call; first immediate = funcHash,
second = fencepost. Only the two RVAs resolve per build. Resolution chain
per interface, all asserted unique (FAIL loudly):

  RTTI TypeDescriptor name (pinned, e.g. .?AVIClientUserMap@@)
    -> Complete Object Locator (sig == 1, pTD == TD)
      -> vtable: the address X whose qword at X-8 == COL VA
        -> wrapper: qword at X + method_index * 8, must be a pdata entry
           whose first HASH_WINDOW bytes contain the method's funcHash.

Usage:
    python3 tools/resolve_ipc.py resolve --dll <dll>
        --out-dir ipc/ [--verify <ground-truth.toml>]
"""

import argparse
import struct
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / "resolve_patterns.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)

HASH_WINDOW = 0x400

# iface -> interface_id, RTTI TypeDescriptor name, and wire-stable methods:
# (method, method_index, funcHash, fencepost, argc).
IPC_IFACES = {
    "IClientUser": {
        "id": 1,
        "td": b".?AVIClientUserMap@@",
        "methods": [
            ("GetSteamID", 10, "D6FC3200", "D7058CA5", 0),
            ("GetAppOwnershipTicketExtendedData", 105, "5578709F",
             "55D3418F", 2),
            ("RequestEncryptedAppTicket", 120, "BBB80477", "BC2703B9", 2),
            ("GetEncryptedAppTicket", 121, "25D6BB1C", "2646F563", 1),
        ],
    },
    "IClientUtils": {
        "id": 4,
        "td": b".?AVIClientUtilsMap@@",
        "methods": [
            ("GetAppID", 19, "09607EC2", "0AFEF352", 0),
            ("GetAPICallResult", 24, "2D3D3979", "2EDFDD1A", 3),
        ],
    },
}


def image_base(buf) -> int:
    e = struct.unpack_from("<I", buf, 0x3C)[0]
    return struct.unpack_from("<Q", buf, e + 48)[0]


def data_spans(img):
    """(rva, size) of data sections that can host RTTI (order-stable)."""
    return [(va, max(vsz, rawsz)) for name, va, vsz, _raw, rawsz in img.secs
            if name in (b".rdata", b".data")]


def span_bytes(img, rva, size):
    """Contiguous bytes for [rva, rva+size), crossing sections if needed."""
    out = bytearray()
    cur = rva
    while len(out) < size:
        o = img.rva2off(cur)
        if o is None:
            return None
        end = cur + 1
        while end < rva + size and img.rva2off(end) == o + (end - cur):
            end += 1
        out += bytes(img.buf[o:o + (end - cur)])
        cur = end
    return bytes(out)


def _u32(img, rva):
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<I", img.buf, o)[0]


def _u64(img, rva):
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<Q", img.buf, o)[0]


def find_td(img, spans, name: bytes):
    """RVA of the TypeDescriptor whose mangled name matches (name at +16)."""
    cands = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        off = 0
        key = bytes(name) + b"\x00"
        while True:
            i = blob.find(key, off)
            if i < 0:
                break
            cands.add(rva + i - 16)
            off = i + 1
    if len(cands) != 1:
        return None
    return next(iter(cands))


def find_vtable(img, spans, td_rva, base):
    """The one address X whose qword at X-8 is the VA of a COL for td."""
    cols = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 4, 4):
            if struct.unpack_from("<I", blob, i)[0] != td_rva:
                continue
            col = rva + i - 12
            if _u32(img, col) == 1:
                cols.add(col)
    if not cols:
        return None, "0 COL cands"
    want = {base + c for c in cols}
    match = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 8, 8):
            if struct.unpack_from("<Q", blob, i)[0] in want:
                match.add(rva + i + 8)
    if len(match) != 1:
        return None, f"{len(match)} vtable cands"
    return next(iter(match)), None


def check_wrapper(img, func_rva, funchash: str, pdata) -> bool:
    if func_rva not in pdata:
        return False
    o = img.rva2off(func_rva)
    if o is None:
        return False
    return bytes.fromhex(funchash)[::-1] in bytes(img.buf[o:o + HASH_WINDOW])


def extract_wire_constants(img, func_rva, allow_different_slot=False):
    """Derive two 4-byte IPC constants from validated append-helper calls.

    Accept exactly two immediate writes through the same append-helper
    target. Require a shared stack slot except for methods that explicitly
    permit different parameter slots. Ambiguous layouts fail closed.
    """
    o = img.rva2off(func_rva)
    if o is None:
        return None
    code = bytes(img.buf[o:o + 0x180])
    hits = []
    for i in range(len(code) - 40):
        if code[i:i + 6] != b"\x41\xb8\x04\x00\x00\x00":
            continue
        j = i + 6
        if code[j:j + 2] == b"\xc7\x45":
            slot = code[j + 2:j + 3]
            imm_off = j + 3
            lea = b"\x48\x8d\x55" + slot
        elif code[j:j + 3] == b"\xc7\x84\x24":
            slot = code[j + 3:j + 7]
            imm_off = j + 7
            lea = b"\x48\x8d\x94\x24" + slot
        elif code[j:j + 3] == b"\xc7\x44\x24":
            slot = code[j + 3:j + 4]
            imm_off = j + 4
            lea = b"\x48\x8d\x54\x24" + slot
        else:
            continue
        val = struct.unpack_from("<I", code, imm_off)[0]
        end = imm_off + 4
        if code[end:end + len(lea)] != lea:
            continue
        k = end + len(lea)
        if code[k:k + 3] == b"\x48\x8d\x4d":
            call = k + 4
        elif code[k:k + 4] == b"\x48\x8d\x4c\x24":
            call = k + 5
        else:
            continue
        if call + 5 > len(code) or code[call] != 0xE8:
            continue
        target = func_rva + call + 5 + struct.unpack_from(
            "<i", code, call + 1)[0]
        hits.append((val, slot, target))
    if (len(hits) != 2 or hits[0][2] != hits[1][2]
            or (not allow_different_slot and hits[0][1] != hits[1][1])
            or hits[0][0] == hits[1][0]):
        return None
    return tuple(f"{item[0]:08X}" for item in hits)


def resolve_iface(spec, img, spans, base, pdata):
    td = find_td(img, spans, spec["td"])
    if td is None:
        return None, None, f'no TD {spec["td"]!r}'
    vt, err = find_vtable(img, spans, td, base)
    if err is not None:
        return None, None, err
    methods = {}
    for n, (name, idx, funchash, fence, argc) in enumerate(spec["methods"]):
        f = _u64(img, vt + idx * 8)
        if f is None:
            return None, None, f"slot {idx} unreadable"
        f -= base
        if not check_wrapper(img, f, funchash, pdata):
            # Re-derive only known wire-method layouts. Keep the existing
            # vtable/pdata assertions, unique constant pair and helper check.
            if name not in {"GetAppOwnershipTicketExtendedData",
                            "RequestEncryptedAppTicket", "GetEncryptedAppTicket",
                            "GetAppID", "GetAPICallResult"}:
                return None, None, f"{name}: wrapper {f:#x} fails hash check"
            pair = extract_wire_constants(
                img, f, allow_different_slot=(name == "GetAPICallResult"))
            if pair is None or not check_wrapper(img, f, pair[0], pdata):
                return None, None, f"{name}: wrapper {f:#x} fails hash check"
            spec["methods"][n] = (name, idx, pair[0], pair[1], argc)
        methods[name] = f
    return vt, methods, None


def render_toml(resolved) -> str:
    parts = []
    for iface, spec, vt, methods in resolved:
        parts.append("\n".join(
            [f"[{iface}]", f'interface_id = {spec["id"]}',
             f'vtable_rva = "0x{vt:X}"']))
        for name, idx, funchash, fence, argc in spec["methods"]:
            parts.append("\n".join(
                [f"[{iface}.{name}]", f"method_index = {idx}",
                 f'funcHash = "0x{funchash.upper()}"',
                 f'wrapper_rva = "0x{methods[name]:X}"',
                 f'fencepost = "0x{fence.upper()}"', f"argc = {argc}"]))
    head = "# MACHINE-GENERATED by tools/resolve_ipc.py - do not hand-edit"
    return head + "\n" + "\n\n".join(parts) + "\n"


def cmd_resolve(args):
    dll = Path(args.dll)
    img = rp.mp.Image(dll)
    spans = data_spans(img)
    if not spans:
        print("FAIL: no data sections")
        return 1
    base = image_base(img.buf)
    entries = sorted(img.pdata_entries())
    pdata = set(entries)
    resolved, failed = [], []
    for iface, original_spec in IPC_IFACES.items():
        # Keep build-specific wire constants local to this resolution run.
        spec = {**original_spec, "methods": list(original_spec["methods"])}
        vt, methods, err = resolve_iface(spec, img, spans, base, pdata)
        if err is not None:
            failed.append((iface, err))
            print(f"FAIL {iface}: {err}")
        else:
            resolved.append((iface, spec, vt, methods))
            print(f"{iface}: vtable=0x{vt:X} " +
                  " ".join(f"{m}=0x{w:X}" for m, w in methods.items()))
    if args.verify:
        truth = tomllib.load(open(args.verify, "rb"))
        for iface, spec, vt, methods in resolved:
            t = truth.get(iface, {})
            mark = "OK" if t.get("vtable_rva") == f"0x{vt:X}" else \
                f'MISMATCH truth={t.get("vtable_rva")}'
            print(f"{mark} {iface}.vtable_rva")
            for name, idx, funchash, _fence, _argc in spec["methods"]:
                tm = truth.get(iface, {}).get(name, {})
                mark = "OK" if tm.get("wrapper_rva") == \
                    f'0x{methods[name]:X}' else \
                    f'MISMATCH truth={tm.get("wrapper_rva")}'
                print(f"{mark} {iface}.{name}.wrapper_rva")
    if args.out_dir and not failed:
        from hashlib import sha256
        text = render_toml(resolved)
        out = Path(args.out_dir) / "steamclient" / f"{sha256(dll.read_bytes()).hexdigest()}.toml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, newline="\n")
        print(f"wrote {out}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--dll", required=True)
    r.add_argument("--out-dir", default=None)
    r.add_argument("--verify", default=None)
    args = ap.parse_args()
    if args.cmd == "resolve":
        return cmd_resolve(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
