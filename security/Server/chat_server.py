# chat_server.py
import sys, socket, select, base64, os
import threading
from threading import Lock
import json as simplejson
from sign import verifySignature
try:
    import queue
except ImportError:
    import Queue as queue
#ssl
from mk_cert_files import *
from OpenSSL import SSL

#x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    #print 'Got certificate: %s' % cert.get_subject()
    return ok

def main():
    #create server certificates.
    createServerCert()
    signCertThread()
    #Defines which port that should be accessible
    q = queue.Queue()

# ************* create servr certificate 
def createServerCert():
    #load CAkey and cert
    file = open('CA.pkey')
    cakey = ''.join(file.readlines())
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey)
    file.close()

    file = open('CA.cert')
    cacert = ''.join(file.readlines())
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cacert)
    file.close()
    
    #Creating server certificate and signing it with the CA private key. Is ok as the server is also the CA :-) 
    print(" #Creating server certificate and signing it with the CA private key. Is ok as the server is also the CA :-) ")
    serv_req = createRequest('server')
    serv_cert = signCertificates(serv_req, cacert, cakey)
    #Writes the cert as PEM encoded to disk
    open('server.cert', 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, serv_cert))  




#****** sign clients certificat : get request from clients 

def signCertThread():
    print ("Started signing thread")
    HOST = '127.0.0.1'
    SOCKET_LIST = []
    RECV_BUFFER = 4096
    socketS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketS.bind(('', 9009))
    #load CAkey and cert
    file = open('CA.pkey')
    cakey = ''.join(file.readlines())
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey)
    file.close()
    file = open('CA.cert')
    cacert = ''.join(file.readlines())
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cacert)
    file.close()
    while True:
        socketS.listen(5)
        client, address = socketS.accept()
        print ("{} connected".format( address ))
        
        data = client.recv(4096)
        print (data)
        req = crypto.load_certificate_request(crypto.FILETYPE_ASN1,data)
                                
        #Sign the cert_req with CA and return the certificate.
        cert_to_be_parsed = signCertificates(req, cacert, cakey)
        client.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_to_be_parsed))
        print("send certificat  to client")
        
      

    
    client.close()
    stockS.close()

def initSSL():
    # Initialize context
    #Could be a function from SSLutils.
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2)
    ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
    ctx.use_privatekey_file (os.path.join('keys', 'server.pkey'))
    ctx.use_certificate_file(os.path.join('', 'server.cert'))
    ctx.load_verify_locations(os.path.join('', 'CA.cert'))

def keyExchange(hub_socket, client_socket, server_socket):
    json_string = {"message":"", "dh":"c"}
    client_socket.send(json.dumps(json_string))
    #listen for client keys
    client_public = client_socket.recv(4096)
    #hend the public client key to Hub
    json_string = {"message": client_public, "dh": "h"}
    hub_socket.send(json.dumps(json_string))
    #listen for the encrypted Fernet key from the Hub
    encrypted_fernet = hub_socket.recv(4096)
    #Send the encrypted fernet key, hub pubzlic key and some  encryption data to the client.
    json_string = {"message": encrypted_fernet, "dh": "c1"}
    client_socket.send(json.dumps(json_string))

def createAnVerifySignature(client_socket, addr, user_dictionary):
    #First send the hashed message
    prehash = base64.b64encode(os.urandom(16))
    json_str = {"message":prehash}
    client_socket.send(json.dumps(json_str))
    #Receive signature and public key IMPORTANT!!! Obviously not for production
    unparsed = client_socket.recv(4096)
    data = json.loads(unparsed)
    #Verify the signature and send acknowledgement
    check = verifySignature(data["public_key"], base64.b64decode(data["signature"]), prehash)
    user_dictionary[addr] = data["username"]
    return check

def electNewHub(socket_list, server_socket):
    for socket in SOCKET_LIST:
        if socket != server_socket:
            HUBSOCK = socket
            break
    return HUBSOCK

main()
