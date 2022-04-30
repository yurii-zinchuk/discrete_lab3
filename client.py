import socket
import threading
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
        serv_se = int(self.sock.recv(1024).decode())
        self.serv_sd = rsa_decrypt(serv_se, d, (n, e))
        print("Ready to chat.")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            encrypted_message = int(self.sock.recv(1024).decode())

            # decrypt message with the secrete key
            decrypted_msg = rsa_decrypt(
                encrypted_message, self.serv_sd, self.serv_pub)

            print(decrypted_msg)

    def write_handler(self):
        while True:
            message = input()

            # encrypt message with the secrete key
            encrypted_msg = rsa_encrypt(message, self.serv_pub)
            # send message
            self.sock.send(str(encrypted_msg).encode())


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "yz")
    cl.init_connection()
