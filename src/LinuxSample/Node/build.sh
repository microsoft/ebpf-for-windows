#!/bin/bash
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"
echo "Start of build step"
echo "***************************************************************************"
echo "***************************************************************************"
echo "***************************************************************************"

BUILD_OUTPUT_DIR="build"

pwd
PWD=`pwd`
# pushd $PWD

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

echo "Double checking Node version"
nodejs --version

echo "And trying to call Node with 'nodejs'......"

nodejs node_modules/react-scripts/bin/react-scripts.js build

# Save the exit code from react-scripts build
EX=$?

echo "Now that that is done, let us see what we have"
ls


# Check exit code and exit with it if it is non-zero so that build will fail
if [ "$EX" -ne "0" || ! -d "$BUILD_OUTPUT_DIR"]; then
    # popd
    echo Failed to build with react-scripts.
    exit $EX
fi

# Restore working directory
popd 

# Exit with explicit 0 exit code so build will not fail
exit $EX
