setlocal
set ghc=%HASKELL%\bin\ghc.exe
echo "Verify ghc version"
call "%ghc%" --version
cd /D "%~dp0"
dir
echo "Building Haskell HelloWorld"
call "%ghc%" "HelloWorld.hs"
dir
echo "Calling Haskell HelloWorld Output"
call "HelloWorld.exe"