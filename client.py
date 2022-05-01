import socket
import threading
from hashlib import sha256
from rsa import generate_keys, rsa_decrypt, rsa_encrypt


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.server_ip, self.port))
        except Exception as err:
            print("[client]: could not connect to server: ", err)
            return
        self.sock.send(self.username.encode())

        print("Wait to secure connection....", end="")
        # create key pair
        (n, e), d = generate_keys()
        self.public, self.secret = (n, e), d

        # receive server public from server
        pub_s = self.sock.recv(1024).decode().split("*")
        self.serv_pub = (int(pub_s[0]), int(pub_s[1]))

        # send client public to server
        public = str(n) + "*" + str(e)
        self.sock.send(public.encode())

        # receive encrypted server secret from server
        serv_se = self.sock.recv(1024).decode()
        self.serv_sd = int(rsa_decrypt(serv_se, d, (n, e)))
        print("Ready to chat.")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            encrypted_message = self.sock.recv(1024).decode()
            enc_message, old_hash = encrypted_message.split('|')

            # decrypt message with the secrete key
            decrypted_msg = rsa_decrypt(
                enc_message, self.serv_sd, self.serv_pub)

            
            print(decrypted_msg)


    def write_handler(self):
        while True:
            message = input()

            encrypted_msg = rsa_encrypt(message, self.serv_pub) + '|' + sha256(message.encode()).hexdigest() 
            self.sock.send(encrypted_msg.encode())


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "yz")
    cl.init_connection()
