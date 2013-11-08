
import triplesec
import sys
import binascii

key = binascii.unhexlify(sys.argv[1])
data = binascii.unhexlify(sys.argv[2])
clear = triplesec.decrypt(data,key)

print clear