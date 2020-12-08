"""
SecureMessaging.py

NAMES: Chase (Xi) Jiang, Nhiem Ngo

Run as client: python3 SecureMessaging.py [Server IP] [Server Port]
Run as server: python3 SecureMessaging.py [Server Port]

"""

import sys
import socket
import os
from threading import Thread

import Crypto
import pyDH
from Crypto.Cipher import AES

QUEUE_LENGTH = 1
SEND_BUFFER_SIZE = 2048


class SecureMessage:

    def __init__(self, server_ip=None, server_port=None):
        """Initialize SecureMessage object, create & connect socket,
           do key exchange, and start send & receive loops"""

        # create IPv4 TCP socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # connect as client
        if server_ip and server_port:
            self.s.connect((server_ip, server_port))

        # connect as server
        elif server_port and not server_ip:
            self.s.bind(('', server_port))
            self.s.listen(QUEUE_LENGTH)
            self.s, _ = self.s.accept()

        # Run Diffie-Hellman key exchange
        self.key_exchange()

        # start send and receive loops
        self.recv_thread = Thread(target=self.recv_loop, args=())
        self.recv_thread.start()
        self.send_loop()

    def send_loop(self):
        """Loop to check for user input and send messages"""
        while True:
            try:
                user_input = input().encode("ISO-8859-1")
                sys.stdout.flush()
                message = self.process_user_input(user_input)
                self.s.send(message[:SEND_BUFFER_SIZE])
            except EOFError:
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    def recv_loop(self):
        """Loop to receive and print messages"""
        while True:
            recv_msg = self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1")
            if recv_msg:
                message = self.process_received_message(recv_msg)
                sys.stdout.write("\t" + message + "\n")
                sys.stdout.flush()
            else:
                os._exit(0)

    def key_exchange(self):
        """TODO: Diffie-Hellman key exchange"""
        global d1_sharedkey_send 
        global d1_sharedkey_recv
        if len(sys.argv) == 3:
            #exchange shared key for sending as a client
            d1_send = pyDH.DiffieHellman()
            d1_pubkey_send = d1_send.gen_public_key()
            self.s.send(str(d1_pubkey_send).encode("ISO-8859-1")[:SEND_BUFFER_SIZE])
            d2_pubkey_send = int(self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1"))
            d1_sharedkey_send = d1_send.gen_shared_key(d2_pubkey_send)
            #exchage shared key for receiving as a client
            d1_recv = pyDH.DiffieHellman()
            d1_pubkey_recv = d1_recv.gen_public_key()
            self.s.send(str(d1_pubkey_recv).encode("ISO-8859-1")[:SEND_BUFFER_SIZE])
            d2_pubkey_recv = int(self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1"))
            d1_sharedkey_recv = d1_recv.gen_shared_key(d2_pubkey_recv)
        elif len(sys.argv) == 2:
            #exchage shared key for receiving as a server
            d1_recv = pyDH.DiffieHellman()
            d1_pubkey_recv = d1_recv.gen_public_key()
            self.s.send(str(d1_pubkey_recv).encode("ISO-8859-1")[:SEND_BUFFER_SIZE])
            d2_pubkey_recv = int(self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1"))
            d1_sharedkey_recv = d1_recv.gen_shared_key(d2_pubkey_recv)
            #exchange shared key for sending as a server
            d1_send = pyDH.DiffieHellman()
            d1_pubkey_send = d1_send.gen_public_key()
            self.s.send(str(d1_pubkey_send).encode("ISO-8859-1")[:SEND_BUFFER_SIZE])
            d2_pubkey_send = int(self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1"))
            d1_sharedkey_send = d1_send.gen_shared_key(d2_pubkey_send)
        pass

    def process_user_input(self, user_input):
        """TODO: Add authentication and encryption"""
        #encryption process using the send key
        key = d1_sharedkey_send.encode("ISO-8859-1")[:32]
        cipher = AES.new(key,AES.MODE_EAX)  ##### nonce,spliter,ciphertext,spliter,tag
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(user_input)
        spliter = "splt".encode("ISO-8859-1")
        user_input =b"".join([nonce,spliter,ciphertext,spliter,tag])
        return user_input

    def process_received_message(self, recv_msg):
        """TODO: Check message integrity and decrypt"""
        #decryption and authentication process using the recv key
        recv_msg = recv_msg.encode("ISO-8859-1")
        arr = recv_msg.split(b'splt')
        nonce = arr[0]
        ciphertext = arr[1]
        tag = arr[2]
        key = d1_sharedkey_recv.encode("ISO-8859-1")[:32]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        b_plaintext = (cipher.decrypt(ciphertext))
        plaintext = b_plaintext.decode("ISO-8859-1")
        #verification for integrity and authen
        try:
            cipher.verify(tag)
        except ValueError:
            print("MessageModificationDetected")
        return plaintext

def main():
    """Parse command-line arguments and start client/server"""

    # too few arguments
    if len(sys.argv) < 2:
        sys.exit(
            "Usage: python3 SecureMessaging.py [Server IP (for client only)] [Server Port]")

    # arguments for server
    elif len(sys.argv) == 2:
        server_ip = None
        server_port = int(sys.argv[1])

    # arguments for client
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])

    # create SecureMessage object
    secure_message = SecureMessage(
        server_ip=server_ip, server_port=server_port)


if __name__ == "__main__":
    main()
