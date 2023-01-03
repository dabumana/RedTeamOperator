import sys

KEY = "noonxoon"

def encrypt_xor(data, key):

	key = str(key)
	key_len = len(key)
	output = ""
	
	for i in range(len(data)):
		current = data[i]
		current_key = key[i % key_len]
		output += chr(ord(current) ^ ord(current_key))
		
	return output
	
def print_hash(magic):
    print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in magic) + ' };')
	
try:
	file = open(sys.argv[1], "rb").read()
except:
	print("File argume needed! %s <raw payload file>" % sys.argv[0])
	sys.exit()
	
magic = encrypt_xor(file, KEY)
print_hash(magic)
