"""Zero-seed hook resolver: DLLs in, Pattern TOMLs out, no prior TOMLs.

Phase 1: string anchors (one distinctive .rdata string per hook, .pdata
entry = hook RVA, sig synthesized from bytes at RVA, cap 80). Phase 2:
call-graph rules off phase-1 funcs. Every rule must yield exactly one
candidate or the hook FAILs loudly (exit 1) - never guess.

Usage:
    python3 tools/resolve_patterns.py survey --dll <dll>
    python3 tools/resolve_patterns.py resolve --dll <dll> --side steamclient
        --out-dir pattern/ [--verify <ground-truth.toml>]
"""

import argparse
import bisect
import struct
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "mp", Path(__file__).parent / "migrate_patterns.py")
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)

SIG_CAP = 80

# hook name -> anchor string (referenced from exactly one func on every build).
ANCHORS = {
    "steamclient": {
        "BuildSpawnEnvBlock": "STEAM_OVERLAY_WINDOW_BLACKLIST",
        "CloseAppCloud": "hidecloudui",
        "CUtlBufferEnsureCapacity": "num >= 0",
        "GetAppDataFromAppInfo": "name_localized/%s",
        "IPCProcessMessage": "Unknown IPC command code /+/ %u.  %s",
        "OptedInMask": "GSteamEngine().IsEngineThreadRunning()",
        "PchMsgNameFromEMsg": "GetMessageFlags",
        "SpawnProcess": "SpawnProcessInternal",
    },
    "steamui": {
        "AddProtobufAsBinary": "CJSMethodArgs::AddProtobufAsBinary",
        "BuildCompleteAppOverviewChange": "BuildCompleteAppOverviewChange",
        "FillInAppOverview": "CSteamUIAppController::FillInAppOverview",
    },
}

CS = "C:\\buildworker\\steam_rel_client_win64\\build\\src\\"
EXACT_ANCHORS = {
    # hook -> full string-ref set (exactly one func matches).
    "steamclient": {
    },
}
MULTI_ANCHORS = {
    # hook name -> strings ALL referenced by the hook (intersection is one func).
    "steamclient": {
        "OptedInMask": [CS + "clientdll\\controller.cpp",
                        "GSteamEngine().IsEngineThreadRunning()"],
    },
}


CALLEE_ANCHORS = {
    # hook -> (outer, require, forbid). outer: string or list (intersection).
    # require: callee-string prefix, None (stringless callee), or
    # ("only", [...]) (callee's whole ref set). forbid: prefix or None.
    "steamclient": {
        "PchMsgNameFromEMsg": ("GetMessageFlags", None, None),
        "CUtlBufferEnsureCapacity": (
            ("exact", [CS + "public\\tier1\\utlmemory.h", "num >= 0"]),
            ("only", [CS + "public\\tier1\\utlmemory.h"]),
            None),
    },
}

# Phase 2: call-graph rules. Each picker returns (rva, None) or (None, reason).

COLDWANT = sorted([CS + "public\\tier1\\utlrbtree.h", "IsValidIndex( elem )"])
WS_NAME = "CWebSocketConnection::BBuildAndAsyncSendFrame"
WS_MODE = "Web socket client mode not supported"
HUB_REFS = ["( &src < m_Memory.Base() ) || ( &src >= ( m_Memory.Base() + m_Size ) )",
            "CPICSJobRequestProductInfoUpdate::BParseResponseMessage"]
BD_STR = "CUserAppManager::BuildDepotDependency"
UR_STR = "User().RunFrame()"
SCB_STR = "( hSteamPipeChatDestinationNew == 0 ) || ( hSteamPipeChatDestinationNew != hSteamPipeChatDestinationPrev )"
MRU_STR = "CUpdateManager::GetMRUApps - Regenerate"
CC_STR = "CCMInterface::ConnectCompleted()"
# CUtlMemory::Grow prologue (28B, disp-free).
GROW_PREFIX = bytes.fromhex(
    "48 89 5C 24 10 57 48 83 EC 30 8B FA 48 8B D9 8B 51 08 8B 49 10 "
    "8D 04 39 3B C2 0F 8E")
# GetPackageInfo prologue (20B, disp-free).
GPI_PREFIX = bytes.fromhex(
    "48 89 5C 24 18 89 54 24 10 55 56 57 48 83 EC 20 44 8B 49 20")
# CUtlBufferEnsureCapacity prologue (identical in every published build; the
# 6980e1cd beta gained a second exact-ref-set twin with a different prologue).
CUBEC_PREFIX = bytes.fromhex(
    "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 8D 7A 01 0F B6 49 1F")


# Prologue byte pin per side/hook, applied after candidate selection.
PROLOGUE_PINS = {"steamclient": {"CUtlBufferEnsureCapacity": CUBEC_PREFIX}}


def filter_prologue(ctx, funcs, pin):
    """Candidates whose first bytes don't match the pin stay excluded."""
    ok = set()
    for f in funcs:
        o = ctx.img.rva2off(f)
        if o is not None and bytes(ctx.img.buf[o:o + len(pin)]) == pin:
            ok.add(f)
    return ok


def _only(cands, what):
    cands = list(cands)
    if len(cands) == 1:
        return cands[0], None
    return None, f"{len(cands)} {what}"


def _min_unique(scored, what):
    scored = sorted(scored, key=lambda kv: kv[1])
    if not scored:
        return None, f"0 {what}"
    if len(scored) > 1 and scored[0][1] == scored[1][1]:
        return None, f"tie {what}"
    return scored[0][0], None


def _max_unique(scored, what):
    scored = sorted(scored, key=lambda kv: kv[1], reverse=True)
    if not scored:
        return None, f"0 {what}"
    if len(scored) > 1 and scored[0][1] == scored[1][1]:
        return None, f"tie {what}"
    return scored[0][0], None


# --- steamui ---

def p2_shouldshow(ctx, F, B, cm):
    tiny = {t for t in ctx.callees(F)
            if not ctx.refs_by_func().get(t) and ctx.func_size(t) <= 0x20}
    return _only({f for f in set(ctx.callees(B)) - {F}
                  if set(ctx.callees(f)) & tiny}, "ShouldShow cands")


def p2_getappid(ctx, F, cm):
    rbf = ctx.refs_by_func()
    G = {t for t in ctx.callees(F)
         if not rbf.get(t) and not ctx.callees(t)
         and len(cm.get(t, ())) >= 100}
    cold = {f for f, strs in rbf.items() if sorted(set(strs)) == COLDWANT}
    return _only({g for g in G
                  if any(g in ctx.callees(f) for f in cold)},
                 "GetAppByID cands")


def p2_runframe(ctx, appid):
    rbf = ctx.refs_by_func()
    cold = [f for f, strs in rbf.items()
            if sorted(set(strs)) == COLDWANT and appid in ctx.callees(f)]
    if len(cold) != 1:
        return None, f"{len(cold)} RunFrameCold cands"
    i = ctx.entries.index(cold[0])
    prev = ctx.entries[i - 1]
    if ctx.func_size(prev) > 0x20:
        return None, f"RunFrame prev too big {prev:#x}"
    return prev, None


def p2_rf32(ctx, F):
    img = ctx.img
    pref = ctx.prefix_index(27)
    out = set()
    for t in ctx.callees(F):
        o = img.rva2off(t)
        if not o:
            continue
        key = bytes(img.buf[o:o + 27])
        for s in pref.get(key, []):
            if s == t:
                continue
            o2 = img.rva2off(s)
            if o2 and ((img.buf[o + 27] >> 6) & 3) != \
                    ((img.buf[o2 + 27] >> 6) & 3):
                out.add(t)
                break
    return _only(out, "rf32 cands")


def p2_markapp(ctx):
    mru = ctx.referencing_funcs(MRU_STR)
    if len(mru) != 1:
        return None, f"{len(mru)} MRU referrers"
    return _only(set(ctx.callees(next(iter(mru)))), "MarkAppChange cands")


def p2_lmwp(ctx):
    slots = set(ctx.iat_slots("vstdlib", "V_IsAbsolutePath"))
    if not slots:
        return None, "no V_IsAbsolutePath slot"
    refs = set()
    for s, fs in ctx.ff15_refs(slots).items():
        refs |= fs
    rbf = ctx.refs_by_func()
    out = set()
    for f in refs:
        i = ctx.entries.index(f)
        p = ctx.entries[i - 1]
        if ctx.func_size(p) <= 0x10 and not rbf.get(f):
            out.add(p)
    return _only(out, "LoadModuleWithPath cands")


def p2_gettopmgr(ctx):
    img = ctx.img
    rbf = ctx.refs_by_func()
    cands = []
    for idx, en in enumerate(ctx.entries):
        nxt = ctx.entries[idx + 1] if idx + 1 < len(ctx.entries) else en
        if nxt - en > 0x40 or rbf.get(en):
            continue
        o = img.rva2off(en + 0x20)
        if not o:
            continue
        b = img.buf[o:o + 8]
        if len(b) == 8 and b[0] == 0x48 and b[1] == 0x8B \
                and b[2] == 0x05 and b[7] == 0xC3:
            cands.append(en)
    counts = ctx.e8_count_many({c + 0x20 for c in cands})
    hot = [c + 0x20 for c in cands if counts[c + 0x20] >= 100]
    return _only(hot, "GetTopManager cands")


# --- steamclient ---

def p2_configstore(ctx):
    rbf = ctx.refs_by_func()
    outer = ctx.referencing_funcs("unhandled EConfigStore (%u)")
    cands = set()
    for f in outer:
        csets = [rbf.get(t, []) for t in ctx.callees(f)]
        req = any(any(s.startswith("RGBA: ") for s in strs) for strs in csets)
        ban = any(s.startswith("num >= 0") for strs in csets for s in strs)
        if req and not ban:
            cands.add(f)
    if len(cands) != 2:
        return None, f"{len(cands)} ConfigStore cands"
    a, b = sorted(cands)
    sa, sb = set(ctx.callees(a)), set(ctx.callees(b))
    if sa > sb:
        return a, None
    if sb > sa:
        return b, None
    return None, "ConfigStore no superset"


def p2_bbuild(ctx):
    reff = ctx.referencing_funcs(WS_NAME)
    if len(reff) != 3:
        return None, f"{len(reff)} NAME referrers"
    tiny = set()
    for t in reff:
        p = ctx.entries[ctx.entries.index(t) - 1]
        if ctx.func_size(p) <= 0x10:
            tiny.add(p)
    return _only(tiny, "BBuild cands")


def p2_hub(ctx):
    rbf = ctx.refs_by_func()
    hubs = {f for f, strs in rbf.items()
            if HUB_REFS[0] in strs and HUB_REFS[1] in strs}
    return _only(hubs, "hub cands")


def p2_grow(ctx, hub):
    img = ctx.img
    n = len(GROW_PREFIX)
    hc = set(ctx.callees(hub))
    match = [en for en in ctx.entries
             if en in hc and img.rva2off(en)
             and bytes(img.buf[img.rva2off(en):img.rva2off(en) + n]) == GROW_PREFIX]
    return _only(match, "Grow cands")


def p2_loadpackage(ctx, hub):
    hc = sorted(ctx.callees(hub))
    if not hc:
        return None, "hub has no callees"
    return _max_unique([(c, len(ctx.callees(c))) for c in hc],
                       "LoadPackage cands")


def p2_marklicense(ctx, hub, cm):
    rbf = ctx.refs_by_func()
    return _only({c for c in ctx.callees(hub)
                  if not ctx.callees(c) and not rbf.get(c)
                  and 2 <= len(cm.get(c, ())) <= 10}, "MarkLicense cands")


def p2_readasbin(ctx, lp, cm):
    rbf = ctx.refs_by_func()
    leaves = [c for c in ctx.callees(lp)
              if not ctx.callees(c) and not rbf.get(c)]
    return _min_unique([(c, len(cm.get(c, ()))) for c in leaves],
                       "ReadAsBinary cands")


def p2_findcreate(ctx, rb, cm):
    rbf = ctx.refs_by_func()
    base = rb & ~0xFFFF
    leaves = [t for t in ctx.entries
              if base <= t < base + 0x10000 and not rbf.get(t)
              and not ctx.callees(t) and len(cm.get(t, ())) >= 100]
    if not leaves:
        # Hotfix builds can move the leaf just before ReadAsBinary's
        # 64 KiB window. Keep the same unique maximum and caller threshold.
        leaves = [t for t in ctx.entries
                  if base - 0x10000 <= t < base and not rbf.get(t)
                  and not ctx.callees(t) and len(cm.get(t, ())) >= 100]
    return _max_unique([(t, len(cm.get(t, ()))) for t in leaves],
                       "FindOrCreate cands")


def p2_pplu(ctx):
    ur = ctx.referencing_funcs(UR_STR)
    if len(ur) != 1:
        return None, f"{len(ur)} UR referrers"
    img = ctx.img
    hits = []
    for c in ctx.callees(next(iter(ur))):
        o = img.rva2off(c)
        nxt = next((x for x in ctx.entries if x > c), None)
        if o is not None and nxt is not None \
                and b"\x83\xb9" in img.buf[o:img.rva2off(nxt)]:
            hits.append(c)
    return _min_unique([(c, ctx.func_size(c)) for c in hits], "PPLU cands")


def p2_recvpkt(ctx):
    runs = [m for _, m in ctx.vtable_runs()
            if any(CC_STR in ctx.refs_by_func().get(x, []) for x in m)]
    if len(runs) != 1:
        return None, f"{len(runs)} CC arrays"
    tiny = [x for x in runs[0]
            if not ctx.refs_by_func().get(x) and ctx.func_size(x) <= 0x20]
    return _only(tiny, "RecvPkt cands")


def p2_appid(ctx):
    cands = [t for t in ctx.entries
             if not ctx.refs_by_func().get(t) and ctx.func_size(t) == 0x174]
    counts = ctx.e8_count_many({t + 0xA4 for t in cands})
    hot = [t + 0xA4 for t in cands if counts[t + 0xA4] >= 200]
    return _only(hot, "GetAppIDPipe cands")


def p2_pipeclient(ctx):
    cands = [t for t in ctx.entries
             if not ctx.refs_by_func().get(t) and ctx.func_size(t) == 0x150]
    counts = ctx.e8_count_many({t + 0xA0 for t in cands})
    hot = [t + 0xA0 for t in cands if counts[t + 0xA0] >= 5]
    return _only(hot, "GetPipeClient cands")


def p2_getoradd(ctx, ga, cm):
    return _only({c for c in ctx.callees(ga)
                  if ctx.func_size(c) <= 0x10 and len(cm.get(c, ())) >= 10},
                 "GetOrAdd cands")


def p2_builddepot(ctx):
    refs = ctx.referencing_funcs(BD_STR)
    if len(refs) != 1:
        return None, f"{len(refs)} BuildDepot referrers"
    return ctx.entries[ctx.entries.index(next(iter(refs))) - 1], None


def p2_checkapp(ctx, cm):
    refs = ctx.referencing_funcs(BD_STR)
    if len(refs) != 1:
        return None, f"{len(refs)} BuildDepot referrers"
    return _min_unique(
        [(c, len(cm.get(c, ()))) for c in ctx.callees(next(iter(refs)))],
        "CheckApp cands")


def p2_scb(ctx):
    refs = ctx.referencing_funcs(SCB_STR)
    if len(refs) != 1:
        return None, f"{len(refs)} SCB referrers"
    return _only(set(ctx.callees(next(iter(refs)))), "SendCallback cands")


def p2_getpackageinfo(ctx):
    img = ctx.img
    n = len(GPI_PREFIX)
    match = [en for en in ctx.entries
             if img.rva2off(en)
             and bytes(img.buf[img.rva2off(en):img.rva2off(en) + n]) == GPI_PREFIX]
    return _only(match, "GetPackageInfo cands")


def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode():
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def canonical_source_path(s: str) -> str:
    """Map the known hotfix buildworker root to the normal source root."""
    hotfix = CS.replace("steam_rel_client_win64", "steam_rel_client_hotfix_win64")
    return CS + s[len(hotfix):] if s.startswith(hotfix) else s


class Ctx:
    def __init__(self, dll: Path):
        self.img = mp.Image(dll)
        self.entries = sorted(self.img.pdata_entries())
        self.strings = {}
        for name, va, vsz, raw, rawsz in self.img.secs:
            if name != b".rdata":
                continue
            blob = self.img.buf[raw:raw + rawsz]
            i = 0
            while i < len(blob):
                if 32 <= blob[i] < 127:
                    j = i
                    while j < len(blob) and 32 <= blob[j] < 127:
                        j += 1
                    if j - i >= 5 and (j >= len(blob) or blob[j] == 0):
                        # Steam hotfix builds retain source paths but rename the
                        # buildworker root. Canonicalize that known root only;
                        # candidate uniqueness and byte checks remain mandatory.
                        self.strings[va + i] = canonical_source_path(
                            blob[i:j].decode())
                    i = max(j, i + 1)
                else:
                    i += 1
        self.by_text = {}
        for rva, s in self.strings.items():
            self.by_text.setdefault(s, []).append(rva)
        self._eset = set(self.entries)
        self._sizes = {en: nxt - en for en, nxt in
                       zip(self.entries, self.entries[1:] + [self.entries[-1]])}

    def func_of(self, rva: int) -> int | None:
        i = bisect.bisect_right(self.entries, rva) - 1
        return self.entries[i] if i >= 0 else None

    def xref_map(self) -> dict[int, set[int]]:
        if hasattr(self, "_xrefs"):
            return self._xrefs
        img = self.img
        buf = img.buf
        lo, hi = img.traw, img.traw + img.trawsz
        tva = img.tva
        str_rvas = set(self.strings)
        hits: dict[int, set[int]] = {}
        i = lo
        n = len(buf)
        while i < hi - 7:
            b = buf[i]
            if b in (0x48, 0x4C, 0x4D) and buf[i + 1] in (0x8D, 0x8B):
                if buf[i + 2] & 0xC7 == 0x05:
                    disp = struct.unpack_from("<i", buf, i + 3)[0]
                    tgt = tva + (i - img.traw) + 7 + disp
                    if tgt in str_rvas:
                        f = self.func_of(tva + (i - img.traw))
                        if f is not None:
                            hits.setdefault(tgt, set()).add(f)
            i += 1
        self._xrefs = hits
        return hits

    def xrefs_to(self, target: int) -> list[int]:
        img = self.img
        lo, hi = img.traw, img.traw + img.trawsz
        buf = img.buf
        out = []
        for opc in (0x8D, 0x8B):
            i = lo
            while True:
                i = buf.find(bytes([opc]), i, hi)
                if i < 0:
                    break
                if i - 1 >= lo and buf[i - 1] in (0x48, 0x4C, 0x4D):
                    modrm = buf[i + 1]
                    if modrm & 0xC7 == 0x05:
                        disp = struct.unpack_from("<i", buf, i + 2)[0]
                        base = img.tva + (i - 1 - img.traw)
                        if base + 7 + disp == target:
                            out.append(base)
                i += 1
        return out

    def callees(self, func: int) -> dict[int, int]:
        img = self.img
        eset = self._eset
        start = img.rva2off(func)
        j = bisect.bisect_right(self.entries, func)
        nxt = self.entries[j] if j < len(self.entries) else None
        end = img.rva2off(nxt) if nxt else start + 0x2000
        code = img.buf[start:end]
        out: dict[int, int] = {}
        for i in range(len(code) - 5):
            if code[i] in (0xE8, 0xE9):
                tgt = func + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt in eset:
                    out[tgt] = out.get(tgt, 0) + 1
        return out

    def callers_map(self) -> dict[int, set[int]]:
        if hasattr(self, "_callers"):
            return self._callers
        img = self.img
        eset = set(self.entries)
        buf = img.buf
        lo, hi = img.traw, img.traw + img.trawsz
        out: dict[int, set[int]] = {}
        for opc in (0xE8, 0xE9):
            i = lo
            while True:
                i = buf.find(bytes([opc]), i, hi - 5)
                if i < 0:
                    break
                src = img.tva + (i - img.traw)
                tgt = src + 5 + struct.unpack_from("<i", buf, i + 1)[0]
                if tgt in eset:
                    out.setdefault(tgt, set()).add(self.func_of(src))
                i += 1
        self._callers = out
        return out

    def referencing_funcs(self, s: str) -> set[int]:
        xm = self.xref_map()
        funcs = set()
        for rva in self.by_text.get(s, []):
            funcs |= xm.get(rva, set())
        return funcs

    def func_size(self, f: int) -> int:
        return self._sizes.get(f, 0)

    def e8_srcs(self, target: int) -> set[int]:
        # Verified E8s only: re-checks each hit against the source func's
        # slice (filters stray E8 bytes in immediates/padding).
        img = self.img
        buf = img.buf
        lo, hi = img.traw, img.traw + img.trawsz
        out = set()
        i = lo
        while True:
            i = buf.find(b"\xe8", i, hi - 5)
            if i < 0:
                break
            src = img.tva + (i - img.traw)
            if src + 5 + struct.unpack_from("<i", buf, i + 1)[0] == target:
                f = self.func_of(src)
                if f is not None:
                    start = img.rva2off(f)
                    nxt = next((x for x in self.entries if x > f), None)
                    end = img.rva2off(nxt) if nxt else start + 0x2000
                    if start is not None and end is not None \
                            and start <= i < end:
                        out.add(f)
            i += 1
        return out

    def e8_count_many(self, targets: set[int]) -> dict[int, int]:
        img = self.img
        buf = img.buf
        lo, hi = img.traw, img.traw + img.trawsz
        out = {t: 0 for t in targets}
        i = lo
        while True:
            i = buf.find(b"\xe8", i, hi - 5)
            if i < 0:
                break
            src = img.tva + (i - img.traw)
            tgt = src + 5 + struct.unpack_from("<i", buf, i + 1)[0]
            if tgt in out:
                out[tgt] += 1
            i += 1
        return out

    def e8_count(self, target: int) -> int:
        return self.e8_count_many({target})[target]

    def iat_slots(self, dll_sub: str, name: str) -> list[int]:
        img = self.img
        buf = img.buf
        e = struct.unpack_from("<I", buf, 0x3C)[0]
        dd = e + 24 + 112
        imp_rva, imp_sz = struct.unpack_from("<II", buf, dd + 8 * 1)
        imp_off = img.rva2off(imp_rva)
        out = []
        for k in range(imp_sz // 20):
            oft, _, _, name_r, ft = struct.unpack_from(
                "<IIIII", buf, imp_off + k * 20)
            if name_r == 0:
                break
            dll = buf[img.rva2off(name_r):img.rva2off(name_r) + 40] \
                .split(b"\0")[0].decode()
            if dll_sub.lower() not in dll.lower():
                continue
            thunks = oft if oft else ft
            t = img.rva2off(thunks)
            idx = 0
            while True:
                (th,) = struct.unpack_from("<Q", buf, t + idx * 8)
                if th == 0:
                    break
                if not th & 0x8000000000000000:
                    a = img.rva2off(th & 0xFFFFFFFF)
                    nm = buf[a + 2:a + 60].split(b"\0")[0] \
                        .decode(errors="replace")
                    if nm == name:
                        out.append(ft + idx * 8)
                idx += 1
                if idx > 4000:
                    break
        return out

    def ff15_refs(self, slots: set[int]) -> dict[int, set[int]]:
        img = self.img
        buf = img.buf
        lo, hi = img.traw, img.traw + img.trawsz
        out: dict[int, set[int]] = {}
        i = lo
        while True:
            i = buf.find(b"\xff\x15", i, hi - 6)
            if i < 0:
                break
            disp = struct.unpack_from("<i", buf, i + 2)[0]
            tgt = img.tva + (i - img.traw) + 6 + disp
            if tgt in slots:
                f = self.func_of(img.tva + (i - img.traw))
                if f is not None:
                    out.setdefault(tgt, set()).add(f)
            i += 1
        return out

    def vtable_runs(self, minlen: int = 4) -> list[tuple[int, list[int]]]:
        if hasattr(self, "_vtruns"):
            return self._vtruns
        img = self.img
        e = struct.unpack_from("<I", img.buf, 0x3C)[0]
        ib = struct.unpack_from("<Q", img.buf, e + 24 + 24)[0]
        eset = set(self.entries)
        out = []
        for name, va, _, raw, rawsz in img.secs:
            if name != b".rdata":
                continue
            blob = img.buf[raw:raw + rawsz]
            n = len(blob) // 8
            vals = struct.unpack("<%dQ" % n, blob[:n * 8])
            i = 0
            while i < n:
                if vals[i] - ib in eset:
                    j = i
                    while j < n and vals[j] - ib in eset:
                        j += 1
                    if j - i >= minlen:
                        out.append(
                            (va + i * 8, [vals[k] - ib for k in range(i, j)]))
                    i = j
                else:
                    i += 1
        self._vtruns = out
        return out

    def prefix_index(self, n: int = 27) -> dict[bytes, list[int]]:
        key = f"_prefix{n}"
        if hasattr(self, key):
            return getattr(self, key)
        img = self.img
        out: dict[bytes, list[int]] = {}
        for en in self.entries:
            o = img.rva2off(en)
            if o:
                out.setdefault(bytes(img.buf[o:o + n]), []).append(en)
        setattr(self, key, out)
        return out

    def refs_by_func(self) -> dict[int, list[str]]:
        if hasattr(self, "_rbf"):
            return self._rbf
        xm = self.xref_map()
        out: dict[int, list[str]] = {}
        for rva, s in self.strings.items():
            for f in xm.get(rva, set()):
                out.setdefault(f, []).append(s)
        self._rbf = out
        return out


def synth_sig(ctx: Ctx, rva: int) -> str | None:
    img = ctx.img
    off = img.rva2off(rva)
    if off is None:
        return None
    raw = img.buf[off:off + SIG_CAP]
    toks = [f"{b:02X}" for b in raw[:24]]
    while len(toks) < SIG_CAP:
        hits = img.scan(mp.parse_sig(" ".join(toks)))
        if len(hits) == 1 and hits[0] == rva:
            return " ".join(toks)
        toks.append(f"{raw[len(toks)]:02X}")
    return None


def resolve(ctx: Ctx, side: str):
    found, failed = {}, []
    multi = MULTI_ANCHORS.get(side, {})
    callee = CALLEE_ANCHORS.get(side, {})
    exact = EXACT_ANCHORS.get(side, {})
    rbf = ctx.refs_by_func()
    for name, anchor in ANCHORS[side].items():
        if name in exact:
            want = sorted(exact[name])
            funcs = {f for f, strs in rbf.items()
                     if sorted(set(strs)) == want}
        elif name in multi:
            funcs = None
            for s in multi[name]:
                f = ctx.referencing_funcs(s)
                funcs = f if funcs is None else funcs & f
        elif name in callee:
            outer, require, forbid = callee[name]
            if isinstance(outer, list):
                cands = None
                for s in outer:
                    f = ctx.referencing_funcs(s)
                    cands = f if cands is None else cands & f
            elif isinstance(outer, tuple) and outer[0] == "exact":
                want = sorted(outer[1])
                cands = {f for f, strs in rbf.items()
                         if sorted(set(strs)) == want}
            else:
                cands = ctx.referencing_funcs(outer)
            ok = set()
            for f in cands:
                callee_sets = [rbf.get(tgt, []) for tgt in ctx.callees(f)]

                def req_met(strs):
                    if isinstance(require, tuple) and require[0] == "only":
                        return sorted(strs) == sorted(require[1])
                    if require is None:
                        return not strs
                    return any(s.startswith(require) for s in strs)

                req = any(req_met(strs) for strs in callee_sets)
                ban = (any(s.startswith(forbid)
                           for strs in callee_sets for s in strs)
                       if forbid is not None else False)
                if req and not ban:
                    ok.add(f)
            funcs = ok
        else:
            funcs = ctx.referencing_funcs(anchor)
        pin = PROLOGUE_PINS.get(side, {}).get(name)
        if pin is not None:
            funcs = filter_prologue(ctx, funcs, pin)
        if len(funcs) != 1:
            failed.append((name, f"{len(funcs)} referencing funcs"))
            continue
        rva = next(iter(funcs))
        sig = synth_sig(ctx, rva)
        if sig is None:
            failed.append((name, "sig not unique within cap"))
            continue
        found[name] = (rva, sig)

    def emit(name, rva, err):
        if err is not None or rva is None:
            failed.append((name, err or "no candidate"))
            return
        sig = synth_sig(ctx, rva)
        if sig is None:
            failed.append((name, "sig not unique within cap"))
            return
        found[name] = (rva, sig)

    if side == "steamui":
        F = found.get("FillInAppOverview", (None,))[0]
        B = found.get("BuildCompleteAppOverviewChange", (None,))[0]
        cm = ctx.callers_map()
        if F is not None and B is not None:
            emit("ShouldShowAppInLibrary", *p2_shouldshow(ctx, F, B, cm))
            rva, err = p2_getappid(ctx, F, cm)
            emit("GetAppByID", rva, err)
            if rva is not None:
                emit("CSteamUIAppControllerRunFrame", *p2_runframe(ctx, rva))
            emit("RepeatedFieldUint32_Add", *p2_rf32(ctx, F))
        else:
            failed.append(("phase2-sui", "FillIn/BuildComplete unresolved"))
        emit("MarkAppChange", *p2_markapp(ctx))
        emit("LoadModuleWithPath", *p2_lmwp(ctx))
        emit("GetTopManager", *p2_gettopmgr(ctx))
    elif side == "steamclient":
        cm = ctx.callers_map()
        rva, err = p2_configstore(ctx)
        emit("ConfigStoreGetBinary", rva, err)
        emit("LoadDepotDecryptionKey", rva, err)
        emit("BBuildAndAsyncSendFrame", *p2_bbuild(ctx))
        hub, err = p2_hub(ctx)
        if hub is None:
            failed.append(("LoadPackage", f"hub: {err}"))
            failed.append(("MarkLicenseAsChanged", f"hub: {err}"))
        else:
            emit("CUtlMemoryGrow", *p2_grow(ctx, hub))
            lp, lperr = p2_loadpackage(ctx, hub)
            emit("LoadPackage", lp, lperr)
            emit("MarkLicenseAsChanged", *p2_marklicense(ctx, hub, cm))
            if lp is not None:
                rb, rberr = p2_readasbin(ctx, lp, cm)
                emit("KeyValues_ReadAsBinary", rb, rberr)
                if rb is not None:
                    emit("KeyValues_FindOrCreateKey",
                         *p2_findcreate(ctx, rb, cm))
        emit("ProcessPendingLicenseUpdates", *p2_pplu(ctx))
        emit("RecvPkt", *p2_recvpkt(ctx))
        emit("GetAppIDForCurrentPipe", *p2_appid(ctx))
        emit("GetPipeClient", *p2_pipeclient(ctx))
        ga = found.get("GetAppDataFromAppInfo", (None,))[0]
        if ga is None:
            failed.append(("GetOrAddAppData", "GetAppData anchor unresolved"))
        else:
            emit("GetOrAddAppData", *p2_getoradd(ctx, ga, cm))
        bd, bderr = p2_builddepot(ctx)
        if bd is None:
            failed.append(("BuildDepotDependency", bderr))
            failed.append(("CheckAppOwnership", f"bd: {bderr}"))
        else:
            emit("BuildDepotDependency", bd, None)
            emit("CheckAppOwnership", *p2_checkapp(ctx, cm))
        emit("SendCallbackToPipe", *p2_scb(ctx))
        emit("GetPackageInfo", *p2_getpackageinfo(ctx))
    return found, failed


def cmd_survey(args):
    ctx = Ctx(Path(args.dll))
    xm = ctx.xref_map()
    refs_by_func: dict[int, list[str]] = {}
    refcount: dict[str, int] = {}
    for rva, s in ctx.strings.items():
        funcs = xm.get(rva, set())
        for f in funcs:
            refs_by_func.setdefault(f, []).append(s)
        refcount[s] = len(funcs)
    want = None
    if args.func:
        want = {int(x, 16) for x in args.func.split(",")}
    for f in sorted(refs_by_func):
        if want is not None and f not in want:
            continue
        print(f"0x{f:X}: {len(refs_by_func[f])} refs")
        for s in sorted(refs_by_func[f]):
            print(f"    [{refcount[s]}] {s[:100]}")
        if args.callees:
            print(f"  callees of 0x{f:X}:")
            for tgt, n in sorted(ctx.callees(f).items()):
                tag = ",".join(sorted(
                    s[:40] for s in refs_by_func.get(tgt, []))[:3])
                print(f"    0x{tgt:X} x{n} [{tag}]")


def cmd_resolve(args):
    from hashlib import sha256
    dll = Path(args.dll)
    ctx = Ctx(dll)
    found, failed = resolve(ctx, args.side)
    truth = {}
    if args.verify:
        truth = {e["name"]: int(e["rva"], 16)
                 for e in tomllib.load(open(args.verify, "rb")).values()}
    for name, (rva, sig) in sorted(found.items()):
        mark = ""
        if truth:
            mark = "OK " if truth.get(name) == rva else \
                f"MISMATCH truth={truth.get(name):#x} " if truth.get(name) else "EXTRA "
        print(f"{mark}{name}: 0x{rva:X} siglen={len(sig.split())}")
    for name, why in failed:
        print(f"FAIL {name}: {why}")
    if args.out_dir and not failed:
        sha = sha256(dll.read_bytes()).hexdigest()
        lines = ["# MACHINE-GENERATED by tools/resolve_patterns.py - do not hand-edit\n"]
        for name, (rva, sig) in sorted(found.items()):
            lines += [f"[0x{fnv1a(name):08X}]", f'name = "{name}"',
                      f'rva = "0x{rva:X}"', f'sig = "{sig}"', ""]
        out = Path(args.out_dir) / args.side / f"{sha}.toml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines))
        print(f"wrote {out}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("survey")
    s.add_argument("--dll", required=True)
    s.add_argument("--func", default=None,
                   help="comma-separated func RVAs to dump (default: all)")
    s.add_argument("--callees", action="store_true",
                   help="also dump E8 callees of dumped funcs")
    r = sub.add_parser("resolve")
    r.add_argument("--dll", required=True)
    r.add_argument("--side", required=True, choices=["steamclient", "steamui"])
    r.add_argument("--out-dir", default=None)
    r.add_argument("--verify", default=None)
    args = ap.parse_args()
    if args.cmd == "survey":
        cmd_survey(args)
        return 0
    return cmd_resolve(args)


if __name__ == "__main__":
    sys.exit(main())
