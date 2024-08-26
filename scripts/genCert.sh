# Script for generating certificates and keys for TLS communication. Use as follows: "./genCert {NAME OF SERVER} "
# Requires openssl
echo "Generating key and certificate for $1" 

openssl ecparam -out ./src/config/$1.key -name secp256r1 -genkey

openssl req -new -key ./src/config/$1.key -x509 -nodes -days 365 -out ./src/config/$1.crt