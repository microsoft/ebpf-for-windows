# Pin path design

On Linux, objects can be pinned to a filesystem path.  As a result:
* Pins can be enumerated or removed via normal filesystem APIs/utilities
* Pin paths are case-sensitive
* The path component separator is a forward slash ('/')
* Pin paths begin with "/sys/fs/bpf/" and relative paths like "mymap" are relative to that prefix.
* ".." and "." components are resolved.

On Windows, pin paths are not currently part of the filesystem.  As a result,
pins cannot be removed via normal filesystem deletion APIs/utilities and instead
ebpf_get_next_pinned_object_path() and ebpf_object_unpin() are exposed
for enumeration and unpinning, respectively.

This leaves open the question of what syntax(es) we support on Windows for pin paths.

## Criteria for Evaluation

The following are criteria for evaluating each option:

1. Slashes: Paths must be accepted using either '/' or '\\' and be canonicalized.

1. Kernel: Canonicalization must be the same in kernel-mode (for native) and user-mode (for JIT).

1. LocalFile: A pin path should not collide with the path of another file in the Windows filesystem.

1. RemoteFile: Avoid confusion with remote paths.

1. FileAPIs: Paths should work with Windows file APIs in the future once a BPF filesystem is implemented.

1. CaseSensitive: Paths should be case-sensitive.

## Options

### Native (Actual file system path)

Example: C:\ebpf\global\my\pin\path

In this option, querying the path of a pinned object would give an actual file system path.
This might be confusing if the path conflicts with an actual path where there may be files,
so additional care would be needed to fail such a pin.

Furthermore, an actual file system path would be case-insensitive rather than case-sensitive.
Another implementation challenge is that the logic for forming pin paths for native programs
is in the kernel (to minimize security concerns), and there isn't an easy way to get the
system drive, and picking "C:" would be fairly arbitrary.

### Mnt (Actual file system path in Linux-style syntax)

Example: /mnt/c/ebpf/global/my/pin/path

Like the previous option, the current or system drive letter is still needed, so this has
the same issues as the previous option.

### Virtual (Windows file system path with another virtual drive for BPF)

Example: BPF:\my\pin\path

In this option, there would be no collisions with actual files, and the path can be case
sensitive if the "BPF:" driver declares such.  Similarly, ".." resolution would work if
the driver implements it as such.

As for portability, canonicalization could ensure that Linux style paths like
"/sys/fs/bpf/my/pin/path" would be canonicalized to "BPF:\my\pin\path" allowing
portability in that respect.  But querying the pin path on an object


### Linux (Linux-like file system path)

Example: /sys/fs/bpf/my/pin/path

In this option, the path would look the same as on Linux where
the canonical form uses forward slash rather than backslash.
It cannot be used with other Windows file system APIs in the future.

### UNC (UNC path)

Example: \\BPF\my\pin\path

In this option, "BPF" would be a special "host" like "localhost" or "?".
However, it may be confusing if there is another host with the name "bpf",
or at least lead people to believe there might be.

## Evaluation Matrix

The matrix below shows how each option evaluates using the
criteria discussed above.  "Y" means the option is good,
"N" means the option is bad, and "-" means it would be somewhere
in between good and bad.

| Criteria      | Native | Mnt | Virtual | Linux | UNC |
| ------------- | ------ | --- | ------- | ----- | --- |
| Slashes       | Y      | Y   | Y       | Y     | Y   |
| Kernel        | -      | -   | Y       | Y     | Y   |
| LocalFile     | -      | -   | Y       | Y     | Y   |
| RemoteFile    | Y      | Y   | Y       | Y     | N   |
| FileAPIs      | Y      | N   | Y       | N     | Y   |
| CaseSensitive | N      | N   | Y       | Y     | Y   |

## Decision

Based on the evaluation matrix, the Virtual form
("BPF:\my\pin\path") will be the canonical form.

In addition, for portability, the Linux form ("/sys/fs/bpf/my/pin/path")
will be accepted as valid, as will the older eBPF for Windows
path ("/ebpf/global/my/pin/path").  These will be canonicalized
to "BPF:\my\pin\path" internally.
