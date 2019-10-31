cd /D "%~dp0"

pushd
echo --------------- PYTHON 2 ---------------------
python2.exe "%~dp0\..\src\WindowsServerSample\Python2\HelloWorld.py"
popd

pushd
echo --------------- PYTHON 3 ---------------------
python3 "%~dp0\..\src\WindowsServerSample\Python3\HelloWorld.py"
popd

pushd
echo --------------- PERL ---------------------
perl "cd %~dp0\..\src\WindowsServerSample\perl\HelloWorld.pl"
popd

REM pushd
REM cd "%~dp0\..\src\WindowsServerSample\Java"
REM javac HelloWorld.java
REM java HelloWorld
REM popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Go"
go build HelloWorld.go
.\HelloWorld.exe
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Haskell"
ghc -o helloHaskell HelloWorld > buildHaskell.txt
.\helloHaskell
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Ruby"
ruby "HelloWorld.rb"
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Rust"
rustc HelloWorld.rs
.\HelloWorld
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Node"
node app.js
popd


pushd
cd "%~dp0\..\src\WindowsServerSample\DotNet"
dotnet restore
dotnet run
popd

"%VS140COMNTOOLS%\vsvars32.bat"

pushd
cd "%~dp0\..\src\WindowsServerSample\C"
cl.exe HelloWorld.c -o helloc
helloc.exe
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\C++"
cl.exe HelloWorld.cpp -o hellocplusplus
hellocplusplus.exe"
popd

pushd
choco.exe install -y winrar
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\Erlang"
erl -noshell -s helloworld start -s init stop
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\VisualStudio\HelloWorld"
msbuild HelloWorld.sln"
popd

pushd
cd "%~dp0\..\src\WindowsServerSample\VisualStudio\Various"
msbuild Various.sln
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe" /logger:trx ".\MyClassLibrary.Test\bin\Debug\MyClassLibrary.Test.dll"
popd

cd "%~dp0"
