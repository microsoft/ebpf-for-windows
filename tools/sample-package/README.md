# eBPF for Windows Samples

This package contains pre-compiled eBPF sample programs (.o files) from the [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows) project.

These samples can be used as reference programs or for testing eBPF functionality on Windows.

## Usage

The `.o` files in the `samples/` directory are ELF object files containing eBPF bytecode. They can be loaded using the eBPF for Windows runtime via `bpftool` or the libbpf API.

## License

MIT License. See [LICENSE](https://github.com/microsoft/ebpf-for-windows/blob/main/LICENSE.txt) for details.
