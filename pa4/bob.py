import socket
import rsa
import pyDes
import pickle
from rsa.bigfile import *
from io import BytesIO
   
def generate_keypair():
    (publickey, privatekey) = rsa.newkeys(1024)
    return {"pub": publickey, "priv": privatekey}

#Generate keys
keys = generate_keypair()
with open('keys/kcpriv.pem') as keyfile:
    keydata = keyfile.read()
kcpriv = rsa.PrivateKey.load_pkcs1(keydata)

signed_pub = rsa.sign(keys['pub'].save_pkcs1(), kcpriv, 'SHA-1')

_s = []

_s.append(keys['pub'].save_pkcs1())
_s.append(signed_pub)

#listen for a connection
host = ''
port = 10101
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(1)

print "Server is running on port %d; press Ctrl-C to terminate." % port
 
while 1:
    clientsock, clientaddr = s.accept()
    print "got connection from ", clientsock.getpeername()
    
    #Sign Bob's key with Kc+...
    objList = pickle.dumps(_s)
    #send the public key over
    clientsock.send(objList)
    
    rcstring = ''
#    f = clientsock.makefile('rb')
#    data = pickle.load(f)
#    f.close()
#    print data
    while 1:
        buf = pickle.loads(clientsock.recv(4096))
        rcstring += buf
#        print rcstring
        if not len(buf):
            break
    clientsock.close()
    #done with the network stuff, at least for this connection
    print rcstring

#    print data
    #encmessage is the cipher text
    infile = open('infile', 'w')
    pickle.dump(rcstring, infile)
    infile.close()
    with open('infile', 'r') as infile, open('outfile', 'wb') as outfile:
        decrypt_bigfile(infile, outfile, keys['priv'])
    outfile = open('outfile')
    deskey = pickle.load(outfile)
    outfile.close()
    print deskey
    
