// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Creates the VMRS file from the Underhill.

use anyhow::Context;
use clap::Parser;
use guid::Guid;
use host_file_access::HostFileStorage;
use host_file_access::WriteLimit;
use std::fs::OpenOptions;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Requests to create a VMRS file from the Underhill.
#[derive(Parser, Debug)]
struct CliOptions {
    /// The name of the VM to get the VMRS for.
    vm_name: String,
    /// The path to the VMRS file to create.
    vmrs_path: String,
    /// The vsock port to connect to the Underhill.
    #[clap(long, default_value = "4242")]
    vsock_port: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let options = CliOptions::parse();
    get_vmrs(options.vm_name, options.vmrs_path, options.vsock_port)?;

    Ok(())
}

/// Function to convert VM name to VM ID.
fn vm_id_from_name(name: &str) -> anyhow::Result<Guid> {
    let output = std::process::Command::new("hvc.exe")
        .arg("id")
        .arg(name)
        .output()
        .context("failed to launch hvc")?;

    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)
            .context("failed to parse hvc output")?
            .trim();
        Ok(stdout.parse()?)
    } else {
        anyhow::bail!(
            "{}",
            std::str::from_utf8(&output.stderr).context("failed to parse hvc error output")?
        )
    }
}

/// Function to get the VMRS file from the Underhill.
fn get_vmrs(vm_name: String, vmrs_path: String, vm_port: u32) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&vmrs_path)?;

    let mut storage = HostFileStorage::new(&mut file, WriteLimit::None);

    tracing::info!("Getting VMRS for VM: {}", vm_name);
    tracing::info!("VMRS file will be created at: {}", vmrs_path);

    let vm_id = vm_id_from_name(&vm_name)?;
    tracing::info!("VM ID for {}: {}", vm_name, vm_id);

    tracing::info!("Connecting to the Underhill to get VMRS...");

    let socket = vmsocket::VmSocket::new()?;
    socket.set_connect_timeout(std::time::Duration::from_secs(1))?;
    socket.set_high_vtl(true)?;
    let mut vm_stream = socket.connect(vmsocket::VmAddress::hyperv_vsock(vm_id, vm_port))?;

    storage.run(&mut vm_stream)?;

    Ok(())
}
