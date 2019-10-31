#!/bin/bash

#Generate Container Name
Container_Name=$(sudo cat /dev/urandom |tr -cd 'a-z' | head -c 10)
Image_Name="ubuntu160401"

echo "Start "
sudo docker run -td --name $Container_Name $Image_Name

sudo docker cp XPlat-Sample $Container_Name:/XPlat-Sample

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/C && gcc HelloWorld.c -o helloc && ./helloc"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/C++ && g++ HelloWorld.cpp -o hellocplusplus && ./hellocplusplus"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/DotNet && dotnet restore > store.txt && dotnet run"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Erlang && erlc helloworld.erl && erl -noshell -s helloworld start -s init stop"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Go && go build HelloWorld.go && ./HelloWorld"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Haskell && ghc -o helloHaskell HelloWorld > buildHaskell.txt && ./helloHaskell"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/java && javac HelloWorld.java && java HelloWorld"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Perl && perl HelloWorld.pl"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/python2 && python2 HelloWorld.py"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/python3 && python3 HelloWorld.py"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Ruby && ruby HelloWorld.rb"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Rust && rustc HelloWorld.rs && ./HelloWorld"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Node && nodejs app.js"

sudo docker exec -i $Container_Name bash -c "cd XPlat-Sample/linuxSample/Gradle+Java && gradle build > gradleBuild.txt && gradle run"

sudo docker exec -i $Container_Name bash -c "echo "MavenJava" && mkdir -p XPlat-Sample/linuxSample/Maven && cd XPlat-Sample/linuxSample/Maven && mvn archetype:generate -DgroupId=xplat -DartifactId=helloworld -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false > mavenCreate.txt && cd helloworld && mvn package > mavenPackage.txt && java -cp target/helloworld-1.0-SNAPSHOT.jar xplat.App"

sudo docker exec -i $Container_Name bash -c "mkdir XPlat-Sample/linuxSample/nuget && nuget install WindowsAzure.ServiceBus -Version 4.0.0"

sudo docker exec -i $Container_Name bash -c "wget -O hello-2.7.tar.gz "http://ftp.gnu.org/gnu/hello/hello-2.7.tar.gz" > download.txt && tar -zxf hello-2.7.tar.gz > tar.txt && cd hello-2.7 && ./configure > config.txt && make > make.txt && make install > makeInstall.txt && hello"

echo "Remove the container: "
sudo docker rm $Container_Name -f
