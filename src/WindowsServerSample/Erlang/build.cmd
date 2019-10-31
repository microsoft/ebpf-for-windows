
cd /D "%~dp0"

del /F /Q helloworld.beam
erlc -v -W .\helloworld.erl
erl -noshell -s helloworld start -s init stop
