import rsa

def generate_keypair(n):
    (publickey, privatekey) = rsa.newkeys(n)
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

write_keys(generate_keypair(1024), 'ka')
write_keys(generate_keypair(1024), 'kb')
write_keys(generate_keypair(2048), 'kc')    