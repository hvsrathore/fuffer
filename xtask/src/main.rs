use std::path::PathBuf;
use std::process::Command;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about = "Build tasks for fuffer workspace", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /* build the ebpf bytecode program targeting bpfel-unknown-none */
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
    /* build the entire workspace including ebpf and host cli */
    Build {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
        Commands::Build { release } => {
            build_ebpf(release)?;
            build_cli(release)?;
        }
    }

    Ok(())
}

/* compile kernel-space ebpf bytecode using nightly rust and bpf-linker */
fn build_ebpf(release: bool) -> Result<()> {
    println!("/* building fuffer-ebpf bytecode for bpfel-unknown-none */");

    let mut args = vec![
        "+nightly",
        "build",
        "--package",
        "fuffer-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];

    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("failed to invoke cargo to compile ebpf bytecode")?;

    if !status.success() {
        bail!("cargo build for fuffer-ebpf failed with exit code: {:?}", status.code());
    }

    /* ensure target artifact exists and display path */
    let profile = if release { "release" } else { "debug" };
    let artifact_path = PathBuf::from("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("fuffer-ebpf");

    println!("/* ebpf bytecode compiled successfully: {} */", artifact_path.display());
    Ok(())
}

/* compile host cli binary */
fn build_cli(release: bool) -> Result<()> {
    println!("/* building fuffer-cli host application */");

    let mut args = vec!["build", "--package", "fuffer-cli"];

    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("failed to invoke cargo to compile fuffer-cli")?;

    if !status.success() {
        bail!("cargo build for fuffer-cli failed with exit code: {:?}", status.code());
    }

    println!("/* fuffer-cli built successfully */");
    Ok(())
}
