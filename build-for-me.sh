#!/bin/bash

set -e
set -o pipefail

# What runs in VTL2

## OpenHCL Boot
OPENHCL_BOOT_BUILD=release
OPENHCL_BOOT="target/x86_64-unknown-none/${OPENHCL_BOOT_BUILD}/openhcl_boot"
cargo build -p openhcl_boot --config openhcl/minimal_rt/x86_64-config.toml "--${OPENHCL_BOOT_BUILD}"
objcopy --only-keep-debug ${OPENHCL_BOOT} "${OPENHCL_BOOT}.dbg"
objcopy --strip-all --keep-section=.build_info --add-gnu-debuglink="${OPENHCL_BOOT}.dbg" ${OPENHCL_BOOT}

## OpenVMM HCL
OPENHCL_BUILD=debug
OPENHCL="target/x86_64-unknown-linux-musl/${OPENHCL_BUILD}/openvmm_hcl"
cargo build -p openvmm_hcl --target x86_64-unknown-linux-musl
objcopy --only-keep-debug ${OPENHCL} "${OPENHCL}.dbg"
objcopy --strip-all --keep-section=.build_info --add-gnu-debuglink="${OPENHCL}.dbg" ${OPENHCL}

## OpenVMM HCL Initrd
SHELL_INITD="flowey-persist/flowey_lib_hvlite__download_openvmm_deps/extracted/openvmm-deps.x86_64.0.1.0-20250403.3.tar.bz2/initrd"
OPENHCL_INITRD="target/openvmm_hcl-initrd"
OPENHCL_ROOTFS_CONFIG="openhcl/rootfs.config"
OPENHCL_KERNEL_MODULES="../OHCL-Linux-Kernel/out"
OPENHCL_KERNEL_BUILD_INFO="../OHCL-Linux-Kernel/out/build/native/bin/kernel_build_metadata.json"
touch ${OPENHCL_KERNEL_BUILD_INFO}
./openhcl/update-rootfs.py \
        --arch x86_64 \
        --kernel-modules ${OPENHCL_KERNEL_MODULES} \
        --build_info ${OPENHCL_KERNEL_BUILD_INFO} \
        --rootfs-config ${OPENHCL_ROOTFS_CONFIG} \
        --layer ${SHELL_INITD} \
        ${OPENHCL} \
        ${OPENHCL_INITRD}


# What runs in VTL0

## A simple bare metal test kernel
VTL0_KERNEL_BUILD=release
VTL0_KERNEL="target/x86_64-unknown-none/${VTL0_KERNEL_BUILD}/vtl0_playground"
cargo build -p vtl0_playground --config openhcl/minimal_rt/x86_64-config.toml --${VTL0_KERNEL_BUILD}
# cargo run -p tmk_vmm -- --tmk ${VTL0_KERNEL} --list

# Generate the JSON files

## Generate the resource file
RESOURCES_FILE="openhcl-x64-direct-resources.json"
OPENHCL_KERNEL="../OHCL-Linux-Kernel/out/build/native/bin/x64/vmlinux"
UEFI="./flowey-persist/flowey_lib_hvlite__download_uefi_mu_msvm/extracted/RELEASE-X64-artifacts.zip/FV/MSVM.fd"
RESOURCES="{
    \"resources\":
        {
            \"underhill_kernel\":   \"$(realpath ${OPENHCL_KERNEL})\",
            \"underhill_initrd\":   \"$(realpath ${OPENHCL_INITRD})\",
            \"openhcl_boot\":       \"$(realpath ${OPENHCL_BOOT})\",
            \"uefi\":               \"$(realpath ${UEFI})\",
            \"static_elf\":         \"$(realpath ${VTL0_KERNEL})\"
        }
}"
echo ${RESOURCES} | jq . > ${RESOURCES_FILE}

## Generate the IGVM manifest file for SNP
SNP_MANIFEST_FILE="openhcl-x64-snp-dev-direct.json"
cat <<EOF > ${SNP_MANIFEST_FILE}
{
    "guest_arch": "x64",
    "guest_configs": [
        {
            "guest_svn": 1,
            "max_vtl": 2,
            "isolation_type": {
                "snp": {
                    "shared_gpa_boundary_bits": 46,
                    "policy": 196639,
                    "enable_debug": true,
                    "injection_type": "normal",
                    "secure_avic": "enabled"
                }
            },
            "image": {
                "openhcl": {
                    "command_line": "OPENHCL_FORCE_LOAD_VTL0_IMAGE=static_elf OPENHCL_BOOT_LOG=com3 OPENHCL_SIGNAL_VTL0_STARTED=1",
                    "memory_page_count": 163840,
                    "memory_page_base": 32768,
                    "uefi": false,
                    "static_elf": {
                        "start_address": 8388608,
                        "load_offset": 0,
                        "assume_pic": true
                    }
                }
            }
        }
   ]
}
EOF

# Generate the IGVM manifest file for direct ELF boot
DIRECT_MANIFEST_FILE="openhcl-x64-direct.json"
cat <<EOF > ${DIRECT_MANIFEST_FILE}
{
    "guest_arch": "x64",
    "guest_configs": [
        {
            "guest_svn": 1,
            "max_vtl": 2,
            "isolation_type": "none",
            "image": {
                "openhcl": {
                    "command_line": "OPENHCL_FORCE_LOAD_VTL0_IMAGE=static_elf OPENHCL_BOOT_LOG=com3 OPENHCL_SIGNAL_VTL0_STARTED=1",
                    "memory_page_count": 163840,
                    "uefi": false,
                    "static_elf": {
                        "start_address": 8388608,
                        "load_offset": 0,
                        "assume_pic": true
                    }
                }
            }
        }
   ]
}
EOF

# Combine everything into a IGVM images

cargo run -p igvmfilegen -- manifest -m ${SNP_MANIFEST_FILE} -r ${RESOURCES_FILE} -o openhcl-x64-snp-dev-direct.igvm
cargo run -p igvmfilegen -- manifest -m ${DIRECT_MANIFEST_FILE} -r ${RESOURCES_FILE} -o openhcl-x64-dev-direct.igvm
