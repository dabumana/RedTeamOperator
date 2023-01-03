import sys
import hashlib

from base64 import b64encode
from Crypto.Cipher import AES
from os import urandom

class user_preferences:
    SIZE = 0
    KEY = "noonxoon"
    PROTOCOL = ""

print ('''

 ▄████▄   ██▀███   ██▓ ██▓███  ▄▄▄█████▓ ██▓ ▄████▄        ██▓███ ▓██   ██▓
▒██▀ ▀█  ▓██ ▒ ██▒▓██▒▓██░  ██▒▓  ██▒ ▓▒▓██▒▒██▀ ▀█       ▓██░  ██▒▒██  ██▒
▒▓█    ▄ ▓██ ░▄█ ▒▒██▒▓██░ ██▓▒▒ ▓██░ ▒░▒██▒▒▓█    ▄      ▓██░ ██▓▒ ▒██ ██░
▒▓▓▄ ▄██▒▒██▀▀█▄  ░██░▒██▄█▓▒ ▒░ ▓██▓ ░ ░██░▒▓▓▄ ▄██▒     ▒██▄█▓▒ ▒ ░ ▐██▓░
▒ ▓███▀ ░░██▓ ▒██▒░██░▒██▒ ░  ░  ▒██▒ ░ ░██░▒ ▓███▀ ░ ██▓ ▒██▒ ░  ░ ░ ██▒▓░
░ ░▒ ▒  ░░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ▒ ░░   ░▓  ░ ░▒ ▒  ░ ▒▓▒ ▒▓▒░ ░  ░  ██▒▒▒ 
  ░  ▒     ░▒ ░ ▒░ ▒ ░░▒ ░         ░     ▒ ░  ░  ▒    ░▒  ░▒ ░     ▓██ ░▒░ 
░          ░░   ░  ▒ ░░░         ░       ▒ ░░         ░   ░░       ▒ ▒ ░░  
░ ░         ░      ░                     ░  ░ ░        ░           ░ ░     
░                                           ░          ░           ░ ░
 --------------------------------------------------------------------------
|   Simple minimal tool to encrypt payloads, generating keys and hidding   |
|   kernel callbacks.                                                      |
|                                                                          |
|   How to use?:                                                           |
|                                                                          |
|                 criptic.py <filename-binary> <protocol>                  |
|                                                                          |
|   <filename-binary> : Specify the binary that you want to use as input   |
|             <protocol> : You can choose between --aes | --xor            |
 --------------------------------------------------------------------------
''')

def encrypt_aes(data):
    user_preferences.PROTOCOL = "AES"
    user_preferences.SIZE = 16
    if user_preferences.KEY == "":
        user_preferences.KEY = b64encode(urandom(user_preferences.SIZE))
    hash = hashlib.sha256(user_preferences.KEY).digest()
    salt = AES.new(hash, AES.MODE_CBC, 16 * '\x00'.encode('utf-8'))
    magic = salt.encrypt(bytes(data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size).encode('utf-8')))
    
    return magic

def encrypt_xor(data):
    user_preferences.PROTOCOL = "XOR"
    user_preferences.SIZE = 8
    if user_preferences.KEY == "":
        user_preferences.KEY = b64encode(urandom(user_preferences.SIZE)).decode('utf-8')
    key = str(user_preferences.KEY)
    key_len = len(key)
    magic = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % key_len]
        magic += chr(ord(chr(current)) ^ ord(current_key))
		
    return magic

def generate_payload(magic):
    payload = b''

    if user_preferences.PROTOCOL == "AES":
        payload = '{ 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in magic) + ' }'
    elif user_preferences.PROTOCOL == "XOR":
        payload = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in magic) + ' }'

    print(" -------------------------------------------------------------------------- ")
    print("PAYLOAD> ", payload)
    print(" -------------------------------------------------------------------------- ")
    print("PAYLOAD SIZE> ", len(payload))

    return payload

def generate_hash(signature):
    flavor = b''

    if user_preferences.PROTOCOL == "AES":
        flavor = '{ 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in signature) + ' }'
        print(" ---------------------------------BYTE KEY--------------------------------- ")
        print("SIGNATURE> ", signature.decode())
    elif user_preferences.PROTOCOL == "XOR":
        flavor = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in signature) + ' }'
        print(" ---------------------------------BYTE KEY--------------------------------- ")
        print("SIGNATURE> ", signature)

    print(" -------------------------------------------------------------------------- ")
    print("PAYLOAD KEY> ", flavor)
    
    return flavor

def generate_obfuscation():
    op = open("op", "rb").readline().split()
    callbacks = []
    flavor = b''
    
    for o in op:
        if user_preferences.PROTOCOL == "AES":
            magic = encrypt_aes(o)
            flavor = '{ 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in magic) + ' }'
        elif user_preferences.PROTOCOL == "XOR":
            magic = encrypt_xor(o)
            flavor = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in magic) + ' }'

        callbacks.append(flavor)
        print(" -------------------------------------------------------------------------- ")
        print(o.decode("UTF-8"), "> ", flavor)
    
    return callbacks

def export_op(magic, payload, flavor, callbacks, key):
    if user_preferences.PROTOCOL == "AES":
        open("favicon.ico","wb").write(magic)
        open("rawkey", "wb").write(key)
    if user_preferences.PROTOCOL == "XOR":
        open("favicon.ico","wb").write(magic.encode('utf-8'))
        open("rawkey", "wb").write(key.encode('utf-8'))

    open("payloadbin", "w").write(payload)
    open("payloadkey", "w").write(flavor)
    open("payloadop", "w").write("".join(callbacks))
    
    print(" ------------------------------EXPORTED OBJECTS----------------------------")
    print(" -payloadop generated. ***\n")
    print(" -payloadkey generated. ***\n")
    print(" -raw key generated. ***\n")
    print(" -ico generated. ***\n")
    print(" --------------------------------------------------------------------------")

try:
    file = open(sys.argv[1], "rb").read()

    if sys.argv[2] == "--aes":
        magic = encrypt_aes(file)
    elif sys.argv[2] == "--xor":
        magic = encrypt_xor(file)

    flavor = generate_hash(user_preferences.KEY)
    callbacks = generate_obfuscation()
    payload = generate_payload(magic)

    export_op(magic, payload, flavor, callbacks, user_preferences.KEY)
except:
    print("File argument needed! %s <raw payload file> --aes || --xor arguments needed!" % sys.argv[0])
    sys.exit()