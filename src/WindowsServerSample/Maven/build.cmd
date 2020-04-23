
pushd "%~dp0"
mvn --offline package -DskipTests -e
popd