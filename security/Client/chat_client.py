# chat_client.py
import sys, socket, select, os, base64, getpass, time
import json as simplejson
import ssl
#from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.backends import default_backend
from mk_cert_files import *
from OpenSSL import SSL

#Own modules
from dh import *
from messencrypt import *
from sign import *
from SSLUtil import *

def chat_client(port, password):
    #As this is just a basic program to show encryption, signatures and
    #elliptic curve diffie-hellman some production features will obvious not exist
    #as for example an login/register which would solve some really important issues
    #with this program. As a public key not sent from the client before signing for example.

    #Create a password for the signature private key
    if password == None:
        while 1:
            Ncarte = getpass.getpass("Enter your card number>")
            Name = getpass.getpass("Enter your name>")
            LastName = getpass.getpass("Enter your lastName :>")
            Login = getpass.getpass("enter your login >")
            password = getpass.getpass("Enter a password for your private key>")
            password_check = getpass.getpass("Enter it again>")
            if password == password_check:
                break
            else:
                print ("Passwords does not match.")

    host = '127.0.0.1'  
    #Get CA signed SSL certificate from server
    getCertificate()
    s = initSSLClient(9009)
    roomHandler(s)
    
    
    
    
def roomHandler(s):
    port = 9009
    name=""
    operation=""
    done = False
    try:
        while done == False:
            print ("Define action: \n1. Create a room. \n2. Join a room. \n3. Get a list of all rooms.\n4. :q to quit.")
            action = input(">")
            if action.lower() == ":q":
                sys.exit()
            if action == "1":
                while True:
                    operation = "create"
                    name = input("Name of the room>")
                    if name.lower() == ':q':
                        return roomHandler(s)
                    
                    #Check if that room already exists or the queue is full
                    jsonstr = {"name":name, "operation":operation}
                    s.send(json.dumps(jsonstr))
                    condition = s.recv(4096)

                    if condition == "exist":
                        print ("Chatroom already exists")
                    elif condition == "full":
                        print ("Chatroom capacity met.")
                    else:
                        print ("Room created successfully")
                        jsonstr = {"name":name, "operation":"join"}
                        s.send(json.dumps(jsonstr))
                        port = s.recv(4096)
                        break
                done = True

            if action == "2":
                while 1:
                    operation = "join"
                    name = input("Name of the room>")
                    if name.lower() == ':q':
                        return roomHandler(s)

                    jsonstr = {"name":name, "operation":operation}
                    s.send(json.dumps(jsonstr))
                    port = s.recv(4096)
                    if port == "0":
                        print ("Room does not exist...")
                    else:
                        break
                done = True

            if action == "3":
                operation = "list"
                jsonstr = {"name": name, "operation": operation}
                s.send(json.dumps(jsonstr))
                roomlist = s.recv(4096)
                print ("#################ROOMS##################")
                for room in roomlist.split():
                    print ("----------------------------------------")
                    print (room)
                print ("----------------------------------------")
                print ("########################################")
    except KeyboardInterrupt:
        sys.exit()
    
    return int(port)   

if __name__ == "__main__":
    sys.exit(chat_client(9009, None))
