# Docker container for building native BPF drivers

This docker image provides a simplified method for building native BPF drivers from ELF files.

## Building the container
docker build -t build_native:latest -m 2GB .

## Usage
docker run -it --rm -v "d:\data:c:\data" build_native \build.ps1 my_program.o

The folder "d:\data" is where the ELF file to be processed is and "my_program.o" is the name of the ELF file.

Once this completes the container produces the following:

1) my_program.cer
2) my_program.pdb
3) my_program.sys
