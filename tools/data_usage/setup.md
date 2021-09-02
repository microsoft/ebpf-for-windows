# Setting up eBPF for Data Usage

## Step 1: eBPF Installation
Follow the [instructions](https://github.com/microsoft/ebpf-for-windows/blob/master/docs/GettingStarted.md#Prerequisites) for "Prerequisites", "How to clone and build the project" and "Installing eBPF for Windows" sections. 
For the "How to clone and build the project" section instead of:
> 1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git```

Run the following:
> ```git clone --recurse-submodules https://github.com/trishms/ebpf-for-windows.git```

## Step 2: VM Installation Instructions
Follow the [instructions](https://github.com/microsoft/ebpf-for-windows/blob/master/docs/vm-setup.md) for the "One-Time Setup" and "Installing eBPF into a VM". You'll need this VM to load eBPF, the necessary eBPF programs and run the user mode application.

## Step 3: Prep and demo

1. Set up the VM (Refer to Step 2)
2. Power it off and in that VM's settings, go to Processor and change the number of processors to 1. (This is because Per-CPU maps are not yet implemented).
3. Click View on the toolbar and turn on Enhanced Mode
4. Copy and paste the folder x64/Debug from the repo you built to your VM's C:\Temp folder or in any other place you want. If the repo is built in the VM, you do not need to do this. As long as the binaries are in the VM.
5. In an elevated command prompt, go to the x64/Debug folder you just pasted in your VM and run ```console.exe load``` to load the associatetoflow and countbytes programs.
6. Then run ```console.exe query``` to start querying for the data usage.
7. Once you are done querying, CTRL-C and run ```console.exe unload``` to unload and disable the programs.

## How to create your own traffic and have data usage outputted:
1. Visit [ctstraffic](https://github.com/microsoft/ctsTraffic) and download the binary on both your host and VM machine.
2. Then after you have ran install-ebpf.bat (Refer to Step 2) on your VM, run ```ctstraffic.exe -listen:* -consoleverbosity:1``` on another command prompt on the VM side.
3. Copy and paste your eBPF programs and run your console app (Refer to Prep and Demo).
4. On your host machine, run ```ctsTraffic.exe -target:{Your VM IP Address} -connections:5 -iterations:5 -transfer:1000000 -consoleverbosity:1 -statusfilename:clientstatus.csv -connectionfilename:clientconnections.csv```
5. You can change the iteration, connections and transfer amount to customize how you'd like to send over the bytes.
6. From the host machine's command line prompt, you'll see the packets being sent to VM. From the VM, you'll see the packets being received.
7. You can stop the host at any time and it will give you how many bytes of traffic sent, and you can compare it to what the console application says.

### Some notes for troubleshooting:
- You need to reload your NetEbpfExt driver after restart or rebooting, because it does not work properly after. Ebpfsvc stops after restarting or rebooting as well, so it is best to run install-ebpf.bat after a restart or boot.
- If you decide to run Netsh instead of loading via the console user mode application, make sure you include both the program type and section name. For example: it is ```netsh add program associatetoflow.o flow flow```, and NOT ```netsh add program associatetoflow.o flow```.

## Understanding the output
- The console will query every 10 seconds and thus may repeat some application data usage if it stays the same. You will see when each 10 second query is when you see  ```Querying...``` being outputted.
- Many application names may be repeated after ```App entry found:``` because there may be more than one five-tuple for each app. For example, for ctstraffic, if it sends the bytes over 5 connections, it established those 5 connections and thus has 5 different five-tuple entries in the app map.
- After each ```App entry found:```, you will either see ```Byte count entry found:``` or ```Byte count deleted or not stored:```. This determines whether or not a byte count with the same five-tuple as the app entry was found in the byte count map. Byte count entries are deleted every time it is matched to its corresponding application. This is because the console stores it in its own map and deletes the entry from the byte count eBPF map. So you may see the byte count one iteration in the query and then it is deleted in the next.
- If you want to know the total number of bytes the applications are sending and receiving, look at the ```Data Usage:``` outputted. It gives you the app name and total byte count.
