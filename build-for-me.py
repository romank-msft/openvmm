#!/usr/bin/env python3

import subprocess
import sys
import os
import json
from pathlib import Path

def run(cmd, **kwargs):
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)

def main():
    # --- What runs in VTL2 ---

    # OpenHCL Boot
    openhcl_boot_build = 'release'
    openhcl_boot = Path('target/x86_64-unknown-none') / openhcl_boot_build / 'openhcl_boot'

    run([
        'cargo', 'build',
        '-p', 'openhcl_boot',
        '--config', 'openhcl/minimal_rt/x86_64-config.toml',
        f'--{openhcl_boot_build}'
    ])

    run(['objcopy', '--only-keep-debug', str(openhcl_boot), f'{openhcl_boot}.dbg'])
    run([
        'objcopy',
        '--strip-all',
        '--keep-section=.build_info',
        f'--add-gnu-debuglink={openhcl_boot}.dbg',
        str(openhcl_boot)
    ])

    # OpenVMM HCL
    openhcl_build = 'debug'
    openhcl = Path('target/x86_64-unknown-linux-musl') / openhcl_build / 'openvmm_hcl'

    run([
        'cargo', 'build',
        '-p', 'openvmm_hcl',
        '--target', 'x86_64-unknown-linux-musl'
    ])

    run(['objcopy', '--only-keep-debug', str(openhcl), f'{openhcl}.dbg'])
    run([
        'objcopy',
        '--strip-all',
        '--keep-section=.build_info',
        f'--add-gnu-debuglink={openhcl}.dbg',
        str(openhcl)
    ])

    # OpenVMM HCL Initrd
    shell_initd = Path(
        'flowey-persist/flowey_lib_hvlite__download_openvmm_deps'
        '/extracted/openvmm-deps.x86_64.0.1.0-20250403.3.tar.bz2/initrd'
    )
    openhcl_initrd = Path('target/openvmm_hcl-initrd')
    openhcl_rootfs_config = Path('openhcl/rootfs.config')
    openhcl_kernel_modules = Path('../OHCL-Linux-Kernel/out')
    openhcl_kernel_build_info = Path(
        '../OHCL-Linux-Kernel/out/build/native/bin/kernel_build_metadata.json'
    )

    # ensure the metadata file exists
    openhcl_kernel_build_info.parent.mkdir(parents=True, exist_ok=True)
    openhcl_kernel_build_info.touch()

    run([
        sys.executable, 'openhcl/update-rootfs.py',
        '--arch', 'x86_64',
        '--kernel-modules', str(openhcl_kernel_modules),
        '--build_info', str(openhcl_kernel_build_info),
        '--rootfs-config', str(openhcl_rootfs_config),
        '--layer', str(shell_initd),
        str(openhcl),
        str(openhcl_initrd)
    ])

    # --- What runs in VTL0 ---

    # A simple bare metal test kernel
    vtl0_kernel_build = 'release'
    vtl0_kernel = Path('target/x86_64-unknown-none') / vtl0_kernel_build / 'vtl0_playground'

    run([
        'cargo', 'build',
        '-p', 'vtl0_playground',
        '--config', 'openhcl/minimal_rt/x86_64-config.toml',
        f'--{vtl0_kernel_build}'
    ])

    # --- Generate the JSON files ---

    # Resources file
    resources_file = Path('openhcl-x64-direct-resources.json')
    opengl_kernel = Path('../OHCL-Linux-Kernel/out/build/native/bin/x64/vmlinux')
    uefi = Path(
        'flowey-persist/flowey_lib_hvlite__download_uefi_mu_msvm'
        '/extracted/RELEASE-X64-artifacts.zip/FV/MSVM.fd'
    )

    resources = {
        "resources": {
            "underhill_kernel":   str(opengl_kernel.resolve()),
            "underhill_initrd":   str(openhcl_initrd.resolve()),
            "openhcl_boot":       str(openhcl_boot.resolve()),
            "uefi":               str(uefi.resolve()),
            "static_elf":         str(vtl0_kernel.resolve())
        }
    }
    resources_file.write_text(json.dumps(resources, indent=4))

    # Helper to write manifest JSON
    def write_manifest(path: Path, obj: dict):
        path.write_text(json.dumps(obj, indent=4))

    # IGVM manifests
    manifest_common = {
        "guest_arch": "x64",
        "guest_configs": [
            {
                "guest_svn": 1,
                "max_vtl": 2,
                "isolation_type": {
                    "snp": {
                        "shared_gpa_boundary_bits": 46,
                        "policy": 196639,
                        "enable_debug": True,
                        "injection_type": "normal",
                        # placeholder for secure_avic
                    }
                },
                "image": {
                    "openhcl": {
                        # placeholders for command_line, uefi/static_elf
                        "memory_page_count": 163840,
                        "memory_page_base": 32768
                    }
                }
            }
        ]
    }

    # SNP direct + secure_avic enabled + static ELF
    m = manifest_common.copy()
    m["guest_configs"][0]["isolation_type"]["snp"]["secure_avic"] = "enabled"
    img = m["guest_configs"][0]["image"]["openhcl"]
    img["command_line"] = (
        "OPENHCL_FORCE_LOAD_VTL0_IMAGE=static_elf "
        "OPENHCL_BOOT_LOG=com3 OPENHCL_SIGNAL_VTL0_STARTED=1"
    )
    img["uefi"] = False
    img["static_elf"] = {
        "start_address": 8388608,
        "load_offset": 0,
        "assume_pic": True
    }
    write_manifest(Path('openhcl-x64-snp-dev-direct-savic.json'), m)

    # SNP direct + secure_avic disabled + static ELF
    m2 = json.loads(json.dumps(m))  # deep copy
    m2["guest_configs"][0]["isolation_type"]["snp"]["secure_avic"] = "disabled"
    write_manifest(Path('openhcl-x64-snp-dev-direct.json'), m2)

    # SNP + secure_avic enabled + UEFI
    m3 = manifest_common.copy()
    m3["guest_configs"][0]["isolation_type"]["snp"]["secure_avic"] = "enabled"
    img3 = m3["guest_configs"][0]["image"]["openhcl"]
    img3["command_line"] = "OPENHCL_BOOT_LOG=com3 OPENHCL_SIGNAL_VTL0_STARTED=1"
    img3["uefi"] = True
    write_manifest(Path('openhcl-x64-snp-dev-savic.json'), m3)

    # SNP + secure_avic disabled + UEFI
    m4 = json.loads(json.dumps(m3))
    m4["guest_configs"][0]["isolation_type"]["snp"]["secure_avic"] = "disabled"
    write_manifest(Path('openhcl-x64-snp-dev.json'), m4)

    # Direct ELF boot, no isolation
    mdirect = {
        "guest_arch": "x64",
        "guest_configs": [
            {
                "guest_svn": 1,
                "max_vtl": 2,
                "isolation_type": "none",
                "image": {
                    "openhcl": {
                        "command_line": (
                            "OPENHCL_FORCE_LOAD_VTL0_IMAGE=static_elf "
                            "OPENHCL_BOOT_LOG=com3 OPENHCL_SIGNAL_VTL0_STARTED=1"
                        ),
                        "memory_page_count": 163840,
                        "uefi": False,
                        "static_elf": {
                            "start_address": 8388608,
                            "load_offset": 0,
                            "assume_pic": True
                        }
                    }
                }
            }
        ]
    }
    write_manifest(Path('openhcl-x64-direct.json'), mdirect)

    # --- Combine everything into IGVM images ---
    igvm_cmds = [
        ('openhcl-x64-snp-dev-direct-savic.json', 'openhcl-x64-snp-dev-direct-savic.igvm'),
        ('openhcl-x64-snp-dev-direct.json',       'openhcl-x64-snp-dev-direct.igvm'),
        ('openhcl-x64-snp-dev-savic.json',        'openhcl-x64-snp-dev-savic.igvm'),
        ('openhcl-x64-snp-dev.json',              'openhcl-x64-snp-dev.igvm'),
        ('openhcl-x64-direct.json',               'openhcl-x64-dev-direct.igvm')
    ]
    for manifest, out in igvm_cmds:
        run([
            'cargo', 'run', '-p', 'igvmfilegen', '--',
            'manifest', '-m', manifest,
            '-r', str(resources_file),
            '-o', out
        ])

if __name__ == '__main__':
    main()
