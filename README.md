# Type 6 decoder

The code here is largely based on information found in

https://github.com/CiscoDevNet/Type-6-Password-Encode/

and is is basically a C variant of the encode6.py you'll find there.

## Compile:
```
cc -std=c99 -o type6 type6.c -lcrypto
```
## Optional symlinks:
```
ln -s type6 decrypt_type6
ln -s type6 encrypt_type6
```
## Usage:
```
# ./type6 -d <master_key> <encrypted_password>
# ./type6 -e <master_key> <cleartext_password>
# ./decrypt_type6 <master_key> <encrypted_password>
# ./encrypt_type6 <master_key> <cleartext_password>
```
## Sample usage:
```
# ./type6 -d 'mySecretMasterkey' 'XOUDEUYHeLGdB`UAZKX\GK[iEgCWMZXEXN^dTGZ[UAAAB'
Decrypted password: 'mySecretPassword'
```
