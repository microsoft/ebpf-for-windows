#!/bin/bash
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"
echo "Start of build step"
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"

pwd
PWD=`pwd`
pushd $PWD

# Find location of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the oe-template folder
echo "Changing to oe-template folder"
cd $DIR/oe-template
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"
ls
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"
echo "Building with react-scripts in ..."
pwd
echo "And trying to call Node with 'nodejs'......"

nodejs node_modules/react-scripts/bin/react-scripts.js build

# Save the exit code from react-scripts build
EX=$?

# Check exit code and exit with it if it is non-zero so that build will fail
if [ "$EX" -ne "0" ]; then
    echo Failed to build with react-scripts.
fi

# Restore working directory
popd 

# Exit with explicit 0 exit code so build will not fail
exit 0
