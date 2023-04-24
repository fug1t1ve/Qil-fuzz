# Qil-fuzz
A Simple coverage-guided snapshot fuzzer, written in Python. It utilizes the Qiling snapshot functionality.

The fuzzer can be adapted to fuzz various targets instead of just fuzzing the EXIF data in images.

It utilises 2 simple mutations:
- Bit flip
- Replacing bytes with magic numbers.
