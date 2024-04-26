#!/usr/bin/env python3

import argparse
import socket
import socketserver
import sys


class MyTCPHandler(socketserver.BaseRequestHandler):
    # def setup(self):
    #     print("Configuring socket as non-blocking...")
    #     self.request.setblocking(0)

    def handle(self):
        # buf = b""

        # while True:
        #     read = self.request.recv(4096)
        #     if read == b"":
        #         break
        #     buf += read
        #     read = b""

        self.data = self.request.recv(4096).strip()

        print(
            "Received {}B received from {}:{}".format(
                len(self.data), self.client_address[0], self.client_address[1]
            )
        )

        self.request.sendall(self.data)
        self.request.close()


parser = argparse.ArgumentParser("Simple TCP Server")
parser.add_argument(
    "--localip",
    default="127.0.0.1",
    help="The local IP address on which to bind the TCP client socket",
    type=str,
)
parser.add_argument(
    "--localport",
    required=True,
    help="The local port on which to bind the TCP client socket",
    type=int,
)


if __name__ == "__main__":
    argvars = vars(parser.parse_args())

    LOCALIP = argvars["localip"]
    LOCALPORT = argvars["localport"]

    print("Starting TCP server at {}:{}...".format(LOCALIP, LOCALPORT))

    try:
        with socketserver.TCPServer((LOCALIP, LOCALPORT), MyTCPHandler) as server:
            server.serve_forever()

    except KeyboardInterrupt:
        print("Shutting down TCP server...")
        server.shutdown()
        server.socket.close()
        sys.exit()
