
pushd "%~dp0"
mvn dependency:go-offline
REM mvn install:install-file -DgroupId=org.apache.maven.surefire -DartifactId=surefire-junit3 -Dversion=2.12.4 -Dpackaging=jar -Dfile=target
popd