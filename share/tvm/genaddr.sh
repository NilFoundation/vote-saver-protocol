#!/bin/sh
echo "Generating address $1$2..."
tonos-cli genaddr $1.tvc $1.abi.json --genkey keys/$1$2.keys.json > genaddr-output/genaddr-output$2.txt
