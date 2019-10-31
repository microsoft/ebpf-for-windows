#!/bin/bash

echo debconf shared/accepted-oracle-license-v1-1 select true |  debconf-set-selections
echo debconf shared/accepted-oracle-license-v1-1 seen true |  debconf-set-selections 

sh -c 'echo "deb [arch=amd64] https://apt-mo.trafficmanager.net/repos/dotnet-release/ xenial main" > /etc/apt/sources.list.d/dotnetdev.list'
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 417A0893
apt-get update -y
apt-get dist-upgrade -y

apt-get install -y gcc golang erlang ruby oracle-java8-installer oracle-java8-set-default python python3 perl maven gradle nodejs dotnet-dev-1.0.1 mono-complete curl gettext
export JAVA_HOME=/usr/lib/jvm/java-8-oracle/bin

curl -sSf https://static.rust-lang.org/rustup.sh | sh