#!/bin/bash

set +e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

cd $DIR/../src/LinuxSample

echo ----------- GCC -------------------------------
cd $DIR/../src/LinuxSample/C 
gcc HelloWorld.c -o helloc 
./helloc

echo ----------- G++ -------------------------------
cd $DIR/../src/LinuxSample/C++
g++ HelloWorld.cpp -o hellocplusplus
./hellocplusplus

echo ----------- .NET Core -------------------------
cd $DIR/../src/LinuxSample/DotNet
dotnet run

echo ----------- Erlang ----------------------------
cd $DIR/../src/LinuxSample/Erlang
erlc helloworld.erl
erl -noshell -s helloworld start -s init stop

echo ----------- Go --------------------------------
cd $DIR/../src/LinuxSample/Go
go build HelloWorld.go
./HelloWorld

echo ----------- Haskell ---------------------------
cd $DIR/../src/LinuxSample/Haskell
ghc -o helloHaskell HelloWorld > buildHaskell.txt
./helloHaskell

echo ----------- Java Standalone -------------------
cd $DIR/../src/LinuxSample/Java
javac HelloWorld.java
java HelloWorld

echo ----------- Perl ------------------------------
cd $DIR/../src/LinuxSample/Perl
perl HelloWorld.pl

echo ----------- Python 2.0 ------------------------
cd $DIR/../src/LinuxSample/Python2
python2 HelloWorld.py

echo ----------- Python 3.0 ------------------------
cd $DIR/../src/LinuxSample/Python3
python3 HelloWorld.py

echo ----------- Ruby ------------------------------
cd $DIR/../src/LinuxSample/Ruby
ruby HelloWorld.rb

echo ----------- Rust ------------------------------
cd $DIR/../src/LinuxSample/Rust
rustc HelloWorld.rs
./HelloWorld

echo ----------- Native ----------------------------
cd $DIR/../src/LinuxSample/Make
cd ./hello-2.7
./configure > config.txt
make > make.txt
make install > makeInstall.txt
hello
cd $DIR
