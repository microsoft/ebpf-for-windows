# How to build the demo project

1. git clone https://msazure.visualstudio.com/DefaultCollection/One/_git/EdgeOS-CoreNetworking-WindowsEbpf
2. git submodule init
3. git submodule update
4. cd external\ebpf-verifier
5. cmake -B build
6. cd ..\..
7. Open ebpf-demo.sln
8. Modify ebpfverifier to use static CRT
	- Properties
	- C/C++
	- Code Generation
	- Runtime Library -> "Multi-threaded Debug (/MTd)"
9. Build ebpfverifier
10. Build solution