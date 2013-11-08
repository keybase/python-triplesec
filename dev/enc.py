
import triplesec
import sys
import binascii

key = sys.argv[1]
data = sys.argv[2]
ciphertext = triplesec.encrypt(data,key)

print binascii.hexlify(ciphertext)
