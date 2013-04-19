import pickle
import socket
import rsa, time
import sys, getopt
from rsa.bigfile import *
from pyDes import *
    
# Requests Kb+ from bob. The key is signed with Kc-. Use Kc+ to verify.
def get_kc_pub():
    with open('keys/kcpub.pem') as keyfile:
        keydata = keyfile.read()
    return rsa.PublicKey.load_pkcs1(keydata)

def get_ka_priv():
    with open('keys/kapriv.pem') as keyfile:
        keydata = keyfile.read()
    return rsa.PrivateKey.load_pkcs1(keydata)  

def start(mes, host, port, password):
    
    msg_payload = [] # Represents m + Ka-(H(m))
    enchilada = [] # Represents Ks(*) + Kb+(Ks)
    # Some variables...    
    
    # Obtain the necessary certificates...
    print "Alice: Retrieving Ka- from disk"
    kapriv = get_ka_priv()
    print "Alice: Ka-:\n", kapriv
    
    print "Alice: \nObtaining Kc+ from 'CA'"
    kcpub = get_kc_pub()
    print "Alice: Kc+:\n", kcpub
    
    print "Alice: Opening connection to Bob..." 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(2)
    rcstring = ''
    while True:
        buf = s.recv(1024)
        rcstring += buf
        print len(buf)
        if len(buf) < 1024:
            break
    
    rcstring = pickle.loads(rcstring)

    print "Alice: Received signed Kb+ from Bob... Now verifying authenticity..."
    # Decrypt kb+ using kc+
    try:
        rsa.verify(rcstring[0], rcstring[1], kcpub)
        print "Alice: Successfully verified Kb+ authenticity."
    except:
        print "Alice: Error: Could not verify authenticity of Bob! He might be an impostor!"
        s.close()
        return None
    
    bobpub = rsa.PublicKey.load_pkcs1(rcstring[0])
    
    print "Alice: Creating Message Payload (Message + Ka-(H(Message)))... "
    # Hashed message, signed with Alice ka+.
    signed_mes = rsa.sign(mes, kapriv, 'SHA-1')
    print "Alice: Message and Signed message: ", mes, signed_mes
    msg_payload.append(mes)
    msg_payload.append(signed_mes)
    
#    password = b'passwordPASSWORD'
    try:
        cipher = triple_des(password)
    except ValueError:
        print "Alice: <password> must be 16 or 24 bits long. Assuming default..."
        password = b'passwordPASSWORD'
        
    # Kb+(Ks)
    print "Alice: Encrypting Symmetric Key with Bob's public key..."
    bundledKey = rsa.encrypt(cipher.getKey(), bobpub)
   
    # Ks(m + Ka(H(m))) 
    print "Alice: Encrypting the message payload with the Symmetric Key..."
    secretBundle = cipher.encrypt(pickle.dumps(msg_payload), padmode=PAD_PKCS5)
    
    print "Alice: Bundling the Symmetric key and encrypted message payload together, serializing and sending to Bob."
    enchilada.append(bundledKey)
    enchilada.append(secretBundle)
    
    s.sendall(pickle.dumps(enchilada))
    print "Alice: Successfully sent to Bob. Exiting..."
    s.close()
    return True

def main(argv):
    message = 'Goodbye from Alice!'
    host = 'localhost'
    port = 10111
    password = b'passwordPASSWORD'
    try:
        opts, args = getopt.getopt(argv,"m:i:p:pw:",["message=","host=", "port=", "password="])
    except getopt.GetoptError:
        print 'alice.py -m <message> -i <host> -p <port> -pw <password>'

        start(message, host, port, password)
    for opt, arg in opts:
        if opt in ("-m", "--message"):
            message = arg
        elif opt in ("-i", "--host"):
            host = arg
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-pw", "--password"):
            password = arg
    start(message, host, port, password)

if __name__ == '__main__':
    main(sys.argv[1:])
    
    
    
    
    
    
