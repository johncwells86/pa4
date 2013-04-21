import pickle, string
import socket, random
import rsa, time
import sys, argparse, logging
from pyDes import *

  
def iv_generator():
    '''
    Generates an 8-byte sequence of random values. This is used for the Initialization Vector for 3DES.
    All ascii letters and digits are considered valid.
    @return: 8-byte sequence of random ascii characters.
    '''
    size = 8 
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for x in range(size))
  
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
    iv = iv_generator()
    pad_mode = 2 # Used for pyDes.triple_des...
    block_mode = 'CBC'
    # Obtain the necessary certificates...
    logging.info("Alice: Retrieving Ka- from disk")
    kapriv = get_ka_priv()
    logging.info("Alice: Ka-:\n", kapriv)
    
    logging.info("Alice: \nObtaining Kc+ from 'CA'")
    kcpub = get_kc_pub()
    logging.info("Alice: Kc+:\n", kcpub)
    
    logging.info("Alice: Opening connection to Bob...") 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(2)
    rcstring = ''
    while True:
        buf = s.recv(1024)
        rcstring += buf
        if len(buf) < 1024:
            break
    
    rcstring = pickle.loads(rcstring)

    logging.info("Alice: Received signed Kb+ from Bob... Now verifying authenticity...")
    # Decrypt kb+ using kc+
    try:
        rsa.verify(rcstring[0], rcstring[1], kcpub)
        logging.info("Alice: Successfully verified Kb+ authenticity.")
    except:
        logging.info("Alice: Error: Could not verify authenticity of Bob! He might be an impostor!")
        s.close()
        return None
    
    bobpub = rsa.PublicKey.load_pkcs1(rcstring[0])
    
    logging.info("Alice: Creating Message Payload (Message + Ka-(H(Message)))... ")
    # Hashed message, signed with Alice ka+.
    signed_mes = rsa.sign(mes, kapriv, 'SHA-1')
    logging.info("Alice: Message and Signed message:", mes)
    msg_payload.append(mes)
    msg_payload.append(signed_mes)
    
#    password = b'passwordPASSWORD'
    try:
        cipher = triple_des(password, block_mode, iv, None, padmode=pad_mode)
    except ValueError:
        logging.info("Alice: <password> must be 16 or 24 bits long. Assuming default...")
        password = b'passwordPASSWORD'
        cipher = triple_des(password, block_mode, iv, None, padmode=pad_mode)
    
    logging.info("Creating cipher bundle (password, block mode, IV, padding)...")
    cipher_bundle = [cipher.getKey(), cipher.getMode(), cipher.getIV(), cipher.getPadMode()]    
    # Kb+(Ks)
    logging.info("Alice: Encrypting Symmetric Key with Bob's public key...")
    bundledKey = rsa.encrypt(pickle.dumps(cipher_bundle), bobpub)
   
    # Ks(m + Ka(H(m))) 
    logging.info("Alice: Encrypting the message payload with the Symmetric Key...")
    secretBundle = cipher.encrypt(pickle.dumps(msg_payload), padmode=PAD_PKCS5)
    
    logging.info("Alice: Bundling the Symmetric key and encrypted message payload together, serializing and sending to Bob.")
    enchilada.append(bundledKey)
    enchilada.append(secretBundle)
    
    s.sendall(pickle.dumps(enchilada))
    logging.info("Alice: Successfully sent to Bob. Exiting...")
    s.close()
    return True

def main(argv):
    message = 'Goodbye from Alice!'
    password = b'passwordPASSWORD'
    log_level = logging.WARNING
       
    # Populate our options, -h/--help is already there for you.
    parser = argparse.ArgumentParser(description='Connects to Bob and sends a secure, encrypted message.')
    parser.add_argument("-v", "--verbose", help='Verbose output', action="store_true")
    parser.add_argument('-i', '--host', help='Provide an external hostname/IP. Defaults to localhost.', default='localhost')
    parser.add_argument('-p', '--port', help='Provide an external Port number. Defaults to 10101.', type=int, default=10101)
    parser.add_argument('-P', '--password', help='Provide a 16/24 bit 3DES password. ')
    parser.add_argument('-m', '--message', help='Message to send to Bob.')

    args = parser.parse_args()
    
    if args.verbose:
        log_level = logging.INFO
    if args.password:
        if len(args.password) is 16 or len(args.password) is 24:
            password = args.password
        else:
            logging.info("Invalid password length. Assuming default.")
    if args.message:
        message = args.message
    # Here would be a good place to check what came in on the command line and
    # call optp.error("Useful message") to exit if all it not well.


    # Set up basic configuration, out to stderr with a reasonable default format.
    logging.basicConfig(level=log_level)
    start(message, args.host, args.port, password)

if __name__ == '__main__':
    main(sys.argv[1:])
    
    
    
    
    
    
