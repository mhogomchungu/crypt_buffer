crypt_buffer
============

this projects uses libgcrypt to encrypt and decrypt a block of data

main_0.c and main_1.c source files contains sample examples on how to use the API

to build these sample programs,run

gcc -o main_1 -Wall -pedantic -Wextra crypt_buffer.c main_1.c -lgcrypt
gcc -o main_0 -Wall -pedantic -Wextra crypt_buffer.c main_0.c -lgcrypt

To run these two programs,just run:

./main_0

or

./main_1
