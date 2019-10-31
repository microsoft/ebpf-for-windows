FROM microsoft/windowsservercore

# CHOCOLATEY 
ENV CHOCOLATEY_VERSION 0.10.3
RUN powershell -Command \  
    $ErrorActionPreference = 'Stop'; \
    "iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex"

# Go HASKELL JAVA MAVEN NODE PERL PYTHON3 RUBY ERLANG RUBY GRADLE RUST NUGET ANDRIOID-SDK
RUN powershell -Command $ErrorActionPreference = 'Stop'; \
    choco install -y \
    golang  \
    ghc \
    jdk8 \
    maven \
    nodejs.install \
    strawberryperl \
    python \
    ruby \
    erlang \
    gradle \
    rust \
    nuget.commandline 
	   
# BOWER
RUN npm install -g bower

# PYTHON 2
ENV PYTHON2_VERSION 2.7.13
ARG PYTHON2_MD5=0f057ab4490e63e528eaa4a70df711d9
RUN powershell -Command \
    $ErrorActionPreference = 'Stop'; \
    wget https://www.python.org/ftp/python/%PYTHON2_VERSION%/python-%PYTHON2_VERSION%.msi -OutFile c:\python-%PYTHON2_VERSION%.msi ; \
    if ((Get-FileHash c:\python-%PYTHON2_VERSION%.msi -Algorithm MD5).Hash -ne $env:PYTHON2_MD5) {exit 1} ; \
    Start-Process msiexec.exe -Wait -ArgumentList '/I c:\python-%PYTHON2_VERSION%.msi /quiet' ; \
    Remove-Item c:\python-%PYTHON2_VERSION%.msi -Force	
ENV PYTHON2 "c:\Python27\python.exe"

# DOTNET CORE
ENV DOTNET_CORE_VERSION 1.1.1
RUN powershell -Command \
    $ErrorActionPreference = 'Stop'; \
    wget https://go.microsoft.com/fwlink/?linkid=843448 -OutFile c:\dotnet-$DOTNET_CORE_VERSION$-sdk-win-x64.exe ; \
    Start-Process c:\dotnet-$DOTNET_CORE_VERSION$-sdk-win-x64.exe -Wait -ArgumentList '/install /quiet /nostart' ; \
    Remove-Item c:\dotnet-$DOTNET_CORE_VERSION$-sdk-win-x64.exe -Force	
	
# ANDRIOD SDK
ENV ANDROID_SDK_VERSION 25.2.3
ARG ANDROID_SDK_CHECKSUM=23d5686ffe489e5a1af95253b153ce9d6f933e5dbabe14c494631234697a0e08
RUN powershell -Command \
    $ErrorActionPreference = 'Stop'; \
    wget https://dl.google.com/android/repository/tools_r%ANDROID_SDK_VERSION%-windows.zip -OutFile c:\tools_r%ANDROID_SDK_VERSION%-windows.zip ; \
 	if ((Get-FileHash c:\tools_r%ANDROID_SDK_VERSION%-windows.zip -Algorithm sha256).Hash -ne $env:ANDROID_SDK_CHECKSUM) {exit 1} ; \
    Expand-Archive c:\tools_r%ANDROID_SDK_VERSION%-windows.zip -DestinationPath c:\ ; \
    Remove-Item c:\tools_r%ANDROID_SDK_VERSION%-windows.zip -Force
ENV ANDROID_SDK_BIN "C:\tools"

# VS2015PROFESSIONAL--PRODUCT KEY SHOULD NOT BE CHECKED IN, REPLACE IT WHEN YOU USE THIS DOCKERFILE
COPY Enterprise2015.3 C:/VSInstall
RUN C:/VSInstall/vs_enterprise.exe /Full /S /ProductKey %productKey%
RUN rd /s /q C:\VSInstall
ENV VS2015_BIN "C:\Program Files (x86)\Microsoft Visual Studio 14.0"
