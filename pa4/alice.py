import pickle
import socket
import rsa
from rsa.bigfile import *
from pyDes import *
from io import BytesIO

objList = []
mes = "HELLO!"
## Use 3DES to create a symmetric key
#def create_symmetric():
#    key = pyDes.des(b"DESCRYPT")
#    return key

# Requests Kb+ from bob. The key is signed with Kc-. Use Kc+ to verify.
def get_kc_pub():
    with open('keys/kcpub.pem') as keyfile:
        keydata = keyfile.read()
#    print keydata
    return rsa.PublicKey.load_pkcs1(keydata)

def get_ka_priv():
    with open('keys/kapriv.pem') as keyfile:
        keydata = keyfile.read()
#    print keydata
    return rsa.PrivateKey.load_pkcs1(keydata)  
  
kapriv = get_ka_priv()
kcpub = get_kc_pub()
host = 'localhost'
port = 10101
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
 
#this should loop around until a delimeter is read
#or something similar
rcstring = pickle.loads(s.recv(2048))

# Decrypt kb+ using kc+
rsa.verify(rcstring[0], rcstring[1], kcpub)

bobpub = rsa.PublicKey.load_pkcs1(rcstring[0])

objList.append(mes)

# Hashed message, signed with Alice ka+.
signed_mes = rsa.sign(mes, kapriv, 'SHA-1')

objList.append(signed_mes)

##encrypt the top secret data!
deskey = triple_des(b"passwordPASSWORD")

#bundledKey = rsa.encrypt(pickle.dumps(deskey), bobpub)
sendOver = []

# Encode the 3DES key to a temporary file.
infile = open('infile', 'w')
pickle.dump(deskey, infile)
infile.close()

with open('infile', 'r') as infile, open('outfile', 'wb') as outfile1:
    encrypt_bigfile(infile, outfile1, bobpub)
outfile1 = open('outfile')
sendOver.append(pickle.dumps(outfile1.read())) # Send the 3DES key over as a pickled file string.
outfile1.close()

# Encrypt (m + Ka(H(m))) 
secretBundle = deskey.encrypt(pickle.dumps(objList), padmode=PAD_PKCS5)

infile = BytesIO(secretBundle)
outfile = BytesIO()
encrypt_bigfile(infile, outfile, bobpub)
sendOver.append(pickle.dumps(outfile.read()))

## Encode secretBundle to file
#infile = open('infile', 'wb')
#pickle.dump(secretBundle, infile)
#infile.close()
#with open('infile', 'rb') as infile, open('outfile', 'wb') as outfile2:
#    encrypt_bigfile(infile, outfile2, bobpub)
#outfile2 = open('outfile')
#sendOver.append(outfile2.read())
#outfile2.close()

#f = s.makefile('wb')
#pickle.dump(sendOver[0], f, pickle.HIGHEST_PROTOCOL)
print len(sendOver[0])
s.sendall(sendOver[0])
#f.close()
s.close()

