#Introduction 
This repository contains sample code that  illustrates how to build code in many different languages such as Go, Erlang, VS, Java, Python, Perl, Node etc. 
and how to run those programs or
run tests with the build frameworks such as Maven or VSTest. 

Start with the file <tt>.pipelines\pipeline.user.windows.yml</tt> that is the entry point for CDPX a.k.a Project Endor.
The OneBranch cross-platform pipeline (CDPX a.k.a Project Endor) will load this file first and use it to execute your
build. Any governance/compliance actions such as static analysis, malware scanning, binary scanning, signing are 
interleaved transparently by Endor without any additional work on your part.

#Tools Supported On Windows Container By Default (these should just work)
- .Net Core
- .NET Framework
- Go
- Node
- Python 3

#Tools Not Supported on Windows Container By Default (sample tool install scripts included here, though)
- Java
- Maven
- Perl
- Ruby