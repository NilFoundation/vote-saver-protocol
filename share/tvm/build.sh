#!/bin/sh
echo "Compiling $1..."
solc $1.sol
tvm_linker compile $1.code --lib ~/bin/stdlib_sol.tvm -o $1.tvc
