import socket
import rsa
import pickle
from rsa.bigfile import *
from pyDes import *


#Load keys
with open('keys/kbpriv.pem') as keyfile:
    keydata = keyfile.read()
kbpriv = rsa.PrivateKey.load_pkcs1(keydata)
print "Bob: Retrieved Bob's private key."

with open('keys/kbpub.pem') as keyfile:
    keydata = keyfile.read()
kbpub = rsa.PublicKey.load_pkcs1(keydata)
print "Bob: Retrieved Bob's public key."

with open('keys/kapub.pem') as keyfile:
    keydata = keyfile.read()
kapub = rsa.PublicKey.load_pkcs1(keydata)
print "Bob: Retrieved Alice's Public key."

with open('keys/kcpriv.pem') as keyfile:
    keydata = keyfile.read()
kcpriv = rsa.PrivateKey.load_pkcs1(keydata)
print "Bob: Retrieved CA's Private key."

print "Bob: Signing Kb+ with CA's Kc-..."
signed_pub = rsa.sign(kbpub.save_pkcs1(), kcpriv, 'SHA-1')

_s = []

_s.append(kbpub.save_pkcs1())
_s.append(signed_pub)

#listen for a connection
host = ''
port = 10111
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
s.bind((host, port))
s.listen(0)

print "Bob: Server is running on port %d." % port
 
while True:
    clientsock, clientaddr = s.accept()
    print "Bob: Received connection from ", clientsock.getpeername()
    
    #Sign Bob's key with Kc+...
    objList = pickle.dumps(_s)
    #send the public key over
    print "Bob: Sending signed key to Alice..."
    clientsock.send(objList)
    
    enchilada = ''
    while True:
        buf = clientsock.recv(1024)
        enchilada += buf
        if len(buf) < 1024:
            print "Bob: Received data from Alice... Unpacking now..."
            break
    #enchilada = ''
    try:
        enchilada = pickle.loads(enchilada)
    except EOFError:
        print "Bob: Something went awry with the pickling... Dropping connection. Try again."
        clientsock.close()
        continue
    
    print "Bob: Retrieving 3DES key and IV..."
    password = rsa.decrypt(enchilada[0], kbpriv)
    cipher = triple_des(password)
    print "Bob: Cipher created... Password is %s" % password
    
    print "Bob: Decrypting message payload with 3DES cipher..."
    msg_payload = pickle.loads(cipher.decrypt(enchilada[1], padmode=PAD_PKCS5))
    try:
        rsa.verify(msg_payload[0], msg_payload[1], kapub)
        print "Bob: Success: Message successfully verified."
        msg = msg_payload[0]
        print "Bob: Alice says: " + msg
        clientsock.close()
    except:
        print "Bob: Error validating authenticity of message. Alice might be lying."
        clientsock.close()
        continue
    
    
    
    
    
    

    
