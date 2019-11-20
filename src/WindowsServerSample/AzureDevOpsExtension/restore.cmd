@echo off

pushd "%~dp0azure-devops-extension-sample"

npm install || exit /b 1

popd
