# xmss_simple
# Simple and Memory-efficient XMSS^MT.

This is a reference implementation of a paper I am currently submitting. The algorithm I use is simpler and more memory efficient than exisitng algorithms.

### Installing

My code runs using the reference implementation of
https://github.com/XMSS/xmss-reference
(hereinafter, we call "original implementation")
Please download the above source codes.

Put all of the following files under the directly "xmss-reference-master" of the original implementation.\
 xmss_core_simple.c,\
 hash_address_2.c,\
 hash_address_2.h,\
 Makefile (replace from existing one)
  
Then, my codes are built by "make" and you can use executables in "test" and "ui" directlies by the same way as the original implementation.

## License

This source code was written by Haruhisa Kosuge. All included code is available under the CC0 1.0 Universal Public Domain Dedication.
