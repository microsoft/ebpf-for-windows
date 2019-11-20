#!/bin/bash
pwd
PWD=`pwd`
pushd $PWD

# Find location of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the azure-devops-extension-sample folder
cd $DIR/azure-devops-extension-sample

echo "Calling NPM install in ..."
pwd

npm install --force

# Save the exit code from npm install
EX=$?

# Check exit code and exit with it if it is non-zero so that build will fail
if [ "$EX" -ne "0" ]; then
    echo Failed to install npm modules.
fi

# Restore working directory
popd 

# Exit with explicit 0 exit code so build will not fail
exit $EX