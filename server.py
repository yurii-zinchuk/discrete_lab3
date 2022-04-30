import socket
import threading
from rsa import generate_keys, rsa_encrypt


class Server:
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(100)

        print("Securing connection....", end="")
        # create key pair
        (n, e), d = generate_keys()
        self.public, self.secret = (n, e), d
        print("Ready!")

        while True:
            cli, addr = self.sock.accept()
            username = cli.recv(1024).decode()
            print(f"{username} tries to connect")
            # self.broadcast(f'new person has joined: {username}')
            self.username_lookup[cli] = username
            self.clients.append(cli)

            # send server public to client
            public = str(n) + "*" + str(e)
            cli.send(public.encode())

            # recieve client public from client
            pub_c = cli.recv(1024).decode().split("*")
            cli_public = (int(pub_c[0]), int(pub_c[1]))

            # encrypt server secret with client public
            encrypted_secret = rsa_encrypt(d, cli_public)

            # send encrypted server secret to client
            cli.send(str(encrypted_secret).encode())

            threading.Thread(
                target=self.handle_client,
                args=(
                    cli,
                    addr,
                ),
            ).start()

    def broadcast(self, msg: str):
        for client in self.clients:

            # encrypt message
            encrypted_msg = rsa_encrypt(msg, self.public)
            # send message
            client.send(str(encrypted_msg).encode())

    def handle_client(self, cli: socket, addr):
        while True:
            msg = cli.recv(1024)

            for client in self.clients:
                if client != cli:
                    client.send(msg)


if __name__ == "__main__":
    s = Server(9001)
    s.start()
