"""Fill the guest's identity into OSX-KVM's OpenCore config.plist.

Runs at every start of macos-vm.service, so the SMBIOS (from sops) only ever
exists in /run/macos-vm, never in the store.
"""

import argparse
import plistlib
import re
import sys
import uuid

NVRAM_GUID = "7C436110-AB2A-4BBB-A880-FE41995C9F82"


def read(path: str, pattern: str, what: str) -> str:
    with open(path) as f:
        value = f.read().strip()
    if not re.fullmatch(pattern, value):
        sys.exit(f"opencore.py: {what} in {path} doesn't look like one")
    return value


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("config")
    p.add_argument("--product", required=True)
    p.add_argument("--csr", required=True, help="csr-active-config, as hex bytes")
    p.add_argument("--serial", required=True)
    p.add_argument("--mlb", required=True)
    p.add_argument("--rom", required=True)
    p.add_argument("--uuid", required=True)
    args = p.parse_args()

    with open(args.config, "rb") as f:
        config = plistlib.load(f)

    generic = config["PlatformInfo"]["Generic"]
    generic["SystemProductName"] = args.product
    generic["SystemSerialNumber"] = read(args.serial, r"[A-Z0-9]{12}", "a serial")
    generic["MLB"] = read(args.mlb, r"[A-Z0-9]{17}", "an MLB")
    rom = read(args.rom, r"[0-9A-Fa-f]{12}", "a ROM (12 hex digits)")
    generic["ROM"] = bytes.fromhex(rom)
    generic["SystemUUID"] = str(
        uuid.UUID(read(args.uuid, r"[0-9A-Fa-f-]{36}", "a UUID"))
    ).upper()

    # Nobody watches the picker, and OpenCanopy's timeout never fires here:
    # boot macOS's default straight away. Holding Option over VNC shows it.
    config["Misc"]["Boot"]["ShowPicker"] = False

    nvram = config["NVRAM"]
    nvram["Add"][NVRAM_GUID]["csr-active-config"] = bytes.fromhex(args.csr)
    # Without the delete, a value already in the guest's NVRAM wins over Add.
    delete = nvram["Delete"].setdefault(NVRAM_GUID, [])
    if "csr-active-config" not in delete:
        delete.append("csr-active-config")

    with open(args.config, "wb") as f:
        plistlib.dump(config, f)


if __name__ == "__main__":
    main()
