# Qil-fuzz
A Simple coverage-guided snapshot fuzzer, written in Python. It utilizes the Qiling snapshot functionality.

The fuzzer can be adapted to fuzz various targets instead of just fuzzing the EXIF data in images.

It utilises 2 simple mutations:
- Bit flip
- Replacing bytes with magic numbers.

Inspired by : [exif-fuzz](https://github.com/d4rk-kn1gh7/exif-fuzz/tree/main)

The fuzz target was inspired by : [Fuzzing like a Caveman](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/#)
