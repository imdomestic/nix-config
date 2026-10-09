"""Read guest PCI/OpRegion state through QEMU; never write guest registers."""

import argparse
import json
import re
import subprocess


def monitor(command):
    result = subprocess.run(
        [
            "virsh", "-c", "qemu:///system", "qemu-monitor-command", args.domain,
            json.dumps({"execute": "human-monitor-command", "arguments": {
                "command-line": command,
            }}),
        ],
        check=True, capture_output=True, text=True, timeout=5,
    )
    response = json.loads(result.stdout)
    if "error" in response:
        raise RuntimeError(response["error"])
    return response["return"]


def read_words(address, count):
    dump = monitor(f"xp /{count}wx 0x{address:x}")
    words = []
    for line in dump.splitlines():
        if ":" in line:
            words.extend(int(value, 16) for value in re.findall(
                r"0x[0-9a-fA-F]+", line.split(":", 1)[1],
            ))
    if len(words) != count:
        raise RuntimeError(f"Incomplete memory read: {dump}")
    return words


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--domain", default="windows11")
parser.add_argument("--bdf", default="00:02.0")
args = parser.parse_args()
match = re.fullmatch(r"([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", args.bdf)
if not match:
    parser.error("BDF must be bb:ss.f")
bus, slot, function = (int(value, 16) for value in match.groups())
if slot > 31:
    parser.error("PCI slot must be <= 31")

tree = monitor("info mtree")
bases = set(int(value, 16) for value in re.findall(
    r"^\s*([0-9a-fA-F]+)-[0-9a-fA-F]+ .*: pcie-mmcfg-mmio\s*$",
    tree, re.MULTILINE,
))
if len(bases) != 1:
    raise RuntimeError(f"Expected one Q35 ECAM base, found {bases}")
base = bases.pop()
config_address = base + (bus << 20) + (slot << 15) + (function << 12)
config = read_words(config_address, 64)
report = {
    "bdf": args.bdf,
    "ecam_base": hex(base),
    "pci_config_address": hex(config_address),
    "pci_config_dwords": [f"{word:08x}" for word in config],
    "vendor_device": f"{config[0] & 0xffff:04x}:{config[0] >> 16:04x}",
    "pci": monitor("info pci"),
}
if config[0] == 0x64A08086:
    asls = config[0xFC // 4]
    report["asls"] = hex(asls)
    if asls and asls % 4096 == 0 and asls + 0x420 < 2**32:
        header = b"".join(word.to_bytes(4, "little") for word in read_words(asls, 8))
        report["opregion_header_hex"] = header.hex()
        report["opregion_signature_valid"] = header[:16] == b"IntelGraphicsMem"
        if report["opregion_signature_valid"]:
            report["opregion_size_kib"] = int.from_bytes(header[16:20], "little")
            report["opregion_version"] = hex(int.from_bytes(header[20:24], "little"))
            vbt = b"".join(word.to_bytes(4, "little") for word in read_words(asls + 0x400, 8))
            report["inline_vbt_header_hex"] = vbt.hex()
            report["inline_vbt_signature_valid"] = vbt[:4] == b"$VBT"
            # Linux intel_opregion.c: 2.0 uses a physical RVDA; 2.1+ uses an offset.
            asle = b"".join(word.to_bytes(4, "little") for word in read_words(asls + 0x3B8, 4))
            rvda = int.from_bytes(asle[2:10], "little")
            rvds = int.from_bytes(asle[10:14], "little")
            version = int.from_bytes(header[20:24], "little")
            report["rvda"] = hex(rvda)
            report["rvds"] = rvds
            if version >= 0x02000000 and rvda and rvds:
                address = rvda if version < 0x02010000 else asls + rvda
                # Bound diagnostics to a small nearby region for relative RVDA.
                if (version < 0x02010000 or 8192 <= rvda <= 1048576) and 32 <= rvds <= 1048576 and address + 32 < 2**32:
                    vbt = b"".join(word.to_bytes(4, "little") for word in read_words(address, 8))
                    report["extended_vbt_address"] = hex(address)
                    report["extended_vbt_header_hex"] = vbt.hex()
                    report["extended_vbt_signature_valid"] = vbt[:4] == b"$VBT"
                else:
                    report["extended_vbt_error"] = "RVDA/RVDS outside diagnostic bounds"
    else:
        report["opregion_signature_valid"] = False
        report["opregion_error"] = "ASLS unset, unaligned, or outside 32-bit guest memory"
else:
    report["opregion_skipped"] = "Selected PCI function is not 8086:64a0"
print(json.dumps(report, indent=2))
