#!/bin/bash

# Save current working directory
PWD=`pwd`
pushd $PWD

echo '-------- Build C (GCC) --------------------------'

# Find location of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the C sample folder
cd $DIR

echo "Building C sample in ..."
pwd

# Invoke gcc to compile the code
gcc -v HelloWorld.c -o HelloWorld &> build.log

# Save exit code from gcc
EX=$?

# Check exit code and exit with it if it is non-zero so that build will fail
if [ "$EX" -ne "0" ]; then
    popd
    echo Failed to build C sample code.
fi

# Restore working directory
popd 

# Exit with explicit 0 exit code so build will not fail
exit $EX
