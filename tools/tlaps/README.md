# TLAPS (tlapm) in Docker

This folder provides a Docker image you can use to run TLAPS locally in a Linux environment.

## Build

From the repo root:

```bash
docker build -t ebpfw-tlaps -f tools/tlaps/Dockerfile .
```

Or use the helper script, which builds once (if needed) and then runs:

```powershell
./tools/tlaps/run.ps1
```

## Run proofs

From the repo root (mounts your working tree into the container at `/repo`):

```bash
docker run --rm -t -v "${PWD}:/repo" -w /repo ebpfw-tlaps
```

Recommended (does not rebuild unless the image is missing, or you pass `-Rebuild`):

```powershell
./tools/tlaps/run.ps1
```

This runs `scripts/run_tlaps.sh`, which by convention checks any proof modules matching `models/**/*Proof*.tla`.

## Run a single module

```bash
docker run --rm -t -v "${PWD}:/repo" -w /repo ebpfw-tlaps tlapm --cleanfp models/epoch/EpochModelProofs.tla
```

Or via the helper script:

```powershell
./tools/tlaps/run.ps1 -- tlapm --cleanfp models/epoch/EpochModelProofs.tla
```
