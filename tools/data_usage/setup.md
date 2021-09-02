# Setting up eBPF for Data Usage

## Step 1: eBPF Installation
Follow the [instructions](https://github.com/microsoft/ebpf-for-windows/blob/master/docs/GettingStarted.md#Prerequisites) for Prerequisites, How to clone and build the project and Installing eBPF for Windows sections. 
For the How to clone and build the project section instead of:
> 1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git```
Run the following:
> ```git clone --recurse-submodules https://github.com/trishms/ebpf-for-windows.git```

## Step 2: VM Installation Instructions
Follow the [instructions](https://github.com/microsoft/ebpf-for-windows/blob/master/docs/vm-setup.md) for the One-Time Setup & Installing eBPF into a VM. You'll need this VM to load eBPF, the necessary eBPF programs and run the user mode application.

## Step 3: Prep and demo

1. Set up the VM (Refer to Step 2)
3. Click View on the toolbar and turn on Enhanced Mode
4. Copy and paste the folder x64/Debug from the repo you built to your VM's C:\Temp folder or in any other place you want. If the repo is built in the VM, you do not need to do this. As long as the binaries are in the VM.
5. In an elevated command prompt, go to the x64/Debug folder you just pasted in your VM and run ```console.exe load``` to load the associatetoflow and countbytes programs.
6. Then run ```console.exe query``` to start querying for the data usage.
7. Once you are done querying, CTRL-C and run ```console.exe unload``` to unload and disable the programs.

## How to create your own traffic and have data usage outputted:
1. Visit [ctstraffic](https://github.com/microsoft/ctsTraffic) and downloaded the binary on both your host and VM machine.
2. Then after you have ran install-ebpf.bat (Refer to Step 2) on your VM, run ```ctstraffic.exe -listen:* -consoleverbosity:1```.
3. Copy and paste your eBPF programs and run your console app (Refer to Prep and Demo).
4. On your host machine, run ```ctsTraffic.exe -target:{Your VM IP Address} -connections:5 -iterations:5 -transfer:1000000 -consoleverbosity:1 -statusfilename:clientstatus.csv -connectionfilename:clientconnections.csv```
5. You can change the iteration, connections and transfer amount to customize how you'd like to send over the bytes.
6. From the host machine's command line prompt, you'll see the packets being sent to VM. From the VM, you'll see the packets being received.
7. You can stop the host at any time and it will give you how many bytes of traffic sent, and you can compare it to what the console application says.
