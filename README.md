# Type 6 decoder

The code here is largely based on information found in

https://github.com/CiscoDevNet/Type-6-Password-Encode/

and is is basically a decode-only C variant of the encode6.py you'll find there.

## Compile:
```
cc -std=c99 -o decrypt_type6 decrypt_type6.c -lcrypto
```
## Usage:
```
decrypt_type6 <master_key> <encrypted_password>
```
## Sample usage:
```
# ./decrypt_type6 'mySecretMasterkey' 'XOUDEUYHeLGdB`UAZKX\GK[iEgCWMZXEXN^dTGZ[UAAAB'
Decrypted password: 'mySecretPassword'
```
