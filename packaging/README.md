# Packaging instructions

## Prerequisites

The [WiX toolset](https://wixtoolset.org/) should be installed and reachable via PATH.

## Configure the main project with `-DEBPFFORWINDOWS_ENABLE_INSTALL=true`

```
cmake -S . -B build -DEBPFFORWINDOWS_ENABLE_INSTALL=true
```

## Build and install the project

Note that this will install ebpf-for-windows to the `/Program Files/ebpf-for-windows` directory. You can use the `DESTDIR` environment variable to override this.

```
cmake --build . --config Debug --target install
```

## Configure the packaging project

The generator can either be:
 * WIX
 * NuGet

```
cmake -S packaging -B package -DEBPFFORWINDOWS_PROGRAM_DATA="C:\Program Files\ebpf-for-windows" -DEBPFFORWINDOWS_VERSION=1.0.0 -DCPACK_GENERATOR=WIX
```

## Build the package

```
cmake --build package --target package
```
