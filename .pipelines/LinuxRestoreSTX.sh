#!/bin/bash

set +e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR
echo -----------------------------------------------
echo Cleaning up old stuff
rm -f $DIR/*.txt
rm -f $DIR/*.gz
rm -f -R $DIR/hello*
rm -f -R $DIR/../src/LinuxSample/hello*
echo -----------------------------------------------
cd $DIR/../src/LinuxSample

echo ----------- .NET Core -------------------------
cd $DIR/../src/LinuxSample/DotNet
dotnet restore > store.txt
dotnet run

echo ----------- Nuget -----------------------------
cd $DIR/../src/LinuxSample/Nuget
nuget install WindowsAzure.ServiceBus -Version 4.0.0

echo ----------- Native ----------------------------
mkdir $DIR/../src/LinuxSample/Make
cd $DIR/../src/LinuxSample/Make
wget -O hello-2.7.tar.gz http://ftp.gnu.org/gnu/hello/hello-2.7.tar.gz > download.txt
tar -zxf hello-2.7.tar.gz > tar.txt 

cd $DIR
