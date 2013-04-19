import rsa

def generate_keypair():
    (publickey, privatekey) = rsa.newkeys(1024)
    return {"pub": publickey, "priv": privatekey}
    
# Write the keys to a file on disk.
def write_keys(keys, name):
    try:
        fi = open('keys/'+name+'pub.pem', 'w')
        fi.write(keys['pub'].save_pkcs1('PEM'))
        fi.close()
    except:
        return False
    try:
        f = open('keys/'+name+'priv.pem', 'w')
        f.write(keys['priv'].save_pkcs1('PEM'))
        f.close()
    except:
        return False
    return True

write_keys(generate_keypair(), 'ka')
write_keys(generate_keypair(), 'kb')
#write_keys(generate_keypair(), 'kc')    