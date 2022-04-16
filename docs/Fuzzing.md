# Fuzz Testing in eBPF-For-Windows

## Overview
Fuzz testing is a test methodology that finds a class of bugs in the code-base
by generating random inputs and verifying that the code doesn't crash.

## Tests
The fuzzing tests are in the repo under tests/fuzz. Fuzz tests execute as part
of each CI/CD workflow. The tests generate a random block of bytes with a
length in the range from minimum input size for that method to minimum input
size + 1024. Many eBPF-For-Windows protocol messages contain a handle as their
first element, so the tests create several valid handles and insert them at
the beginning of the message.

## Reproducing a failure from CI/CD
At the start of each fuzzing run, the tests generate a random number seed and
prints it out to the console. The random seed appears similar to the following:
```
[Begin random seed]
6bcd4d9f e4be3204 66f59b19 fc13dfd0 49aee1d3 a9fec550 1a6aea17 b0bf0eb6
398939cd 565ea6ec 15e3c09d 1844f118 fcdf6860 1e892676 f8fa75af 84e23b43
..
02fc4779 15c10832 2c6a717c 79404590 7634d1fe f0ddd687 81d67357 091d3f2b
c447caca c0626a08 4c6c8656 0c88d48c e20e975b 5e7ff362 bd982986 6e50d38f
[End random seed]
```

To reproduce a failure observed in fuzzing, copy this random seed into a text
file (```random_seed.txt``` as an example) and then set the environment variable
```RANDOM_SEED``` to the path of the file containing the random seed. The tests
will then use the provided seed instead of generating a new one, which results
in the tests repeating the sequence of steps that resulted in the crash.