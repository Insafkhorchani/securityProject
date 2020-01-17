from OpenSSL import crypto
from createCert import *  

def createCA():
    cakey = createKeyPair(TYPE_RSA, 2048)
    careq = createCertRequest(cakey, CN='Certificate Authority')
    cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5)) # five years
    open('CA.pkey', 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey))
    open('CA.cert', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))

    return cakey, cacert

def createRequest(origin):
    pkey = createKeyPair(TYPE_RSA, 2048)
    req = createCertRequest(pkey, CN=origin)
    if origin=="server" :
        open('keys/server.pkey', 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    
    elif origin=="client" :
        open('keys/client.pkey', 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))        
    return req

def signCertificates(req, cacert, cakey):
    cert = createCertificate(req, cacert, cakey, 1,0, 60*60*24) #24 hours.
    return cert