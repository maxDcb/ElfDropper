#!/bin/bash

g++ -Os -static -fPIC -I./include -L./lib -o ./bin/implant run_shellcode.c -lssl -lcrypto -pthread -lz
strip ./bin/implant
g++ -Os -shared -fPIC -I./include -L./lib -o ./bin/implant.so run_shellcode_dll.c -lssl -lcrypto -pthread -lz
strip ./bin/implant.so