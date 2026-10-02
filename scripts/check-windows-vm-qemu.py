"""Validate VFIO XML overrides against the pinned QEMU property API, without a GPU."""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

qemu, *definitions = sys.argv[1:]
help_text = subprocess.check_output([qemu, '-device', 'vfio-pci,help'], text=True)
properties = dict(re.findall(r'^\s+(\S+)=<([^>]+)>', help_text, re.MULTILINE))
namespace = {'qemu': 'http://libvirt.org/schemas/domain/qemu/1.0'}
for definition in definitions:
    root = ET.parse(definition).getroot()
    for device in root.findall('qemu:override/qemu:device', namespace):
        if device.get('alias') != 'hostdev0':
            continue
        for prop in device.findall('qemu:frontend/qemu:property', namespace):
            name, kind, value = (prop.get(key) for key in ('name', 'type', 'value'))
            actual = properties.get(name)
            if actual == 'bool':
                valid = kind == 'bool' and value in ('true', 'false')
            elif actual == 'OnOffAuto':
                valid = kind == 'string' and value in ('on', 'off', 'auto')
            else:
                raise ValueError(f'{definition}: unchecked QEMU property {name}: {actual}')
            if not valid:
                raise ValueError(f'{definition}: {name} is QEMU {actual}, XML has {kind}={value}')
    print(f'{definition}: QEMU VFIO property types checked')
