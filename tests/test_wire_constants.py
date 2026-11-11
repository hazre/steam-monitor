"""Verify fail-closed extraction of IPC wire constants from synthetic wrappers."""
import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "ri", Path(__file__).parent / ".." / "tools" / "resolve_ipc.py")
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)

START = 0x1000


class Image:
    def __init__(self, code):
        self.buf = bytearray(b"\x00" + code + b"\x90" * 64)

    def rva2off(self, _rva):
        return 1


def emit(buf, kind, slot, value, helper=0x5000):
    prefix = b"\x41\xb8\x04\x00\x00\x00"
    if kind == "rbp":
        mov = b"\xc7\x45" + bytes([slot]) + struct.pack("<I", value)
        lea = b"\x48\x8d\x55" + bytes([slot])
        rcx = b"\x48\x8d\x4d\xd0"
    elif kind == "rsp8":
        mov = b"\xc7\x44\x24" + bytes([slot]) + struct.pack("<I", value)
        lea = b"\x48\x8d\x54\x24" + bytes([slot])
        rcx = b"\x48\x8d\x4c\x24\x30"
    else:
        disp = struct.pack("<I", slot)
        mov = b"\xc7\x84\x24" + disp + struct.pack("<I", value)
        lea = b"\x48\x8d\x94\x24" + disp
        rcx = b"\x48\x8d\x4c\x24\x30"
    call = len(buf) + len(prefix) + len(mov) + len(lea) + len(rcx)
    disp = helper - (START + call + 5)
    buf.extend(prefix + mov + lea + rcx + b"\xe8" + struct.pack("<i", disp))


def pair(kind="rbp", slots=(0x38, 0x38), helpers=(0x5000, 0x5000)):
    b = bytearray(b"\x90" * 8)
    emit(b, kind, slots[0], 0x12345678, helpers[0])
    b.extend(b"\x90" * 3)
    emit(b, kind, slots[1], 0x87654321, helpers[1])
    return b


class TestWireConstants(unittest.TestCase):
    def test_rbp_disp8(self):
        self.assertEqual(ri.extract_wire_constants(Image(pair()), START),
                         ("12345678", "87654321"))

    def test_rsp_disp8(self):
        self.assertEqual(ri.extract_wire_constants(Image(pair("rsp8")), START),
                         ("12345678", "87654321"))

    def test_rsp_disp32(self):
        self.assertEqual(ri.extract_wire_constants(
            Image(pair("rsp32", (0x88, 0x88))), START),
            ("12345678", "87654321"))

    def test_changed_slot_refused_by_default(self):
        self.assertIsNone(ri.extract_wire_constants(
            Image(pair("rbp", (0x38, 0x50))), START))

    def test_explicit_different_slot_supported(self):
        self.assertEqual(ri.extract_wire_constants(
            Image(pair("rbp", (0x38, 0x50))), START,
            allow_different_slot=True), ("12345678", "87654321"))

    def test_different_helper_refused(self):
        self.assertIsNone(ri.extract_wire_constants(
            Image(pair(helpers=(0x5000, 0x6000))), START))

    def test_ambiguous_third_constant_refused(self):
        b = pair()
        emit(b, "rbp", 0x38, 0xABCDEF01)
        self.assertIsNone(ri.extract_wire_constants(Image(b), START))


if __name__ == "__main__":
    unittest.main()
