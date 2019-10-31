#!/bin/bash

# Save current working directory
PWD=`pwd`
pushd $PWD

echo '-------- Build C++ (G++) ------------------------'

# Figure out location of this script. Don't assume absolute paths because paths can change between pipeline host and dev box.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the location of the C++ sample.
cd $DIR

echo "Building C++ sample in ..."
pwd

# Invoke G++ to compile the sample.
g++ -v HelloWorld.cpp -o HelloWorld &> build.log

# Save the exit code from G++
EX=$?

# Check exit code from G++ and exit with it to ensure build fails
if [ "$EX" -ne "0" ]; then
    popd
    echo Failed to build C++ sample
fi

# Restore working directory
popd

# Exit with explicit 0 exit code to make sure build passes
exit $EX
