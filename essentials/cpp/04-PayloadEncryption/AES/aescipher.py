import sys
import hashlib

from Crypto.Cipher import AES
from os import urandom


KEY = urandom(16)

def encrypt_aes(data, key):

	hash = hashlib.sha256(key).digest()
	salt = AES.new(hash, AES.MODE_CBC, 16 * '\x00')
	
	return salt.encrypt(bytes(data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size)))
	
def print_hash(magic):
    print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in magic) + ' };')
	
try:
	file = open(sys.argv[1], "rb").read()
except:
	print("File argume needed! %s <raw payload file>" % sys.argv[0])
	sys.exit()
	
magic = encrypt_aes(file, KEY)
print_hash(magic)
print_hash(KEY)