# CSX-512
 An [Experimental] authenticated stream cipher based on ChaCha using 64-bit integers, a 1024-bit block and a 512-bit key, and authenticated with KMAC.
This implementation uses a base reference code, or AVX implementations of the cipher. For best performance, set the project properties to the highest available SIMD instruction set supported by your CPU. AVX-512 instructions are fully supported in this implementation and offer the best performance profile.


## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the extended symmetric cipher key lengths (512 bit and higher), and other cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.