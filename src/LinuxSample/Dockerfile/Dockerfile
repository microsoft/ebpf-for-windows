FROM ubuntu:16.04

# INSTALL SOME COMMON PACKAGES
RUN apt-get update && apt-get install -y \
    vim \
    nano \
    curl \
    software-properties-common \
    apt-transport-https \
    wget \
    tree \
    libgmp-dev \
    openssl \
    unzip \
    build-essential \
    expect

# DOWNLOAD VISUAL STUDIO CODE PACKAGE
RUN curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
RUN mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
RUN sh -c 'echo "deb [arch=amd64] http://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'

# INSTALL PERL, MAVEN, NPM, VISUAL STUDIO CODE, RUST, CARGO, ERLANG
RUN apt-get update && apt-get install -y \
    perl \
    maven \
    npm \
    code \
    rustc \
    cargo \
    erlang \
    ruby-full \
    nuget \
    nodejs

# INSTALL JAVA 8u121
RUN wget --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u121-b13/e9e7ea248e2c4826b92b3f075a80e441/jdk-8u121-linux-x64.tar.gz
RUN mkdir /opt/jdk
RUN tar -zxf jdk-8u121-linux-x64.tar.gz -C /opt/jdk
ENV JAVA_HOME /opt/jdk/jdk1.8.0_121
RUN update-alternatives --install /usr/bin/java java /opt/jdk/jdk1.8.0_121/bin/java 100
RUN update-alternatives --install /usr/bin/javac javac /opt/jdk/jdk1.8.0_121/bin/javac 100
RUN update-alternatives --install /usr/bin/jar jar /opt/jdk/jdk1.8.0_121/bin/jar 100
RUN rm jdk-8u121-linux-x64.tar.gz

# INSTALL .NETCORE
RUN sh -c 'echo "deb [arch=amd64] https://apt-mo.trafficmanager.net/repos/dotnet-release/ xenial main" > /etc/apt/sources.list.d/dotnetdev.list'
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 417A0893
RUN apt-get update && apt-get install -y \
    dotnet-dev-1.0.1

# INSTALL HASKELL PLATFORM
RUN wget https://haskell.org/platform/download/8.0.2/haskell-platform-8.0.2-unknown-posix--full-x86_64.tar.gz
RUN tar -xf haskell-platform-8.0.2-unknown-posix--full-x86_64.tar.gz
RUN ./install-haskell-platform.sh
RUN rm haskell-platform-8.0.2-unknown-posix--full-x86_64.tar.gz
RUN rm hp-usr-local.tar.gz
RUN rm install-haskell-platform.sh

# INSTALL BOWER BY NPM
RUN npm install -g bower

# INSTALL GO
RUN wget https://storage.googleapis.com/golang/go1.8.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.8.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
RUN rm go1.8.linux-amd64.tar.gz

# INSTALL GRADLE
RUN wget https://services.gradle.org/distributions/gradle-3.4.1-bin.zip
RUN mkdir /opt/gradle
RUN unzip -d /opt/gradle gradle-3.4.1-bin.zip
ENV PATH=$PATH:/opt/gradle/gradle-3.4.1/bin
RUN rm gradle-3.4.1-bin.zip

# INSTALL ANDROID SDK
RUN wget https://dl.google.com/android/repository/tools_r25.2.3-linux.zip
RUN unzip tools_r25.2.3-linux.zip -d /opt/android-sdk

# UPDATE EVERYTHING
RUN apt-get update