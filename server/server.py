from helper import AuthHelper
from utils.utils import str_to_dict

import socket
import socketserver

# CONFIG parameters
TIMEOUT = 1

class AuthenticationHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        """
        Describe the authentication server behaviours
        """
        self.request.settimeout(TIMEOUT) # setting up the timeout to receiving next message from the client
        buffer: bytes = b'' # contains all the data sent during all the session, after the authentication
        helper: AuthHelper = AuthHelper() # makes possible to compute the authentication protocol operations

        try:
            # AUTHENTICATION

            # STEP1: receiving M1 from IoT device
            m1 = str_to_dict(self.request.recv(1024).decode())

            device_ID: bytes = m1["device_ID"]
            session_ID: bytes = m1["session_ID"]

            print(f"Device ID: {device_ID}")
            print(f"Session ID: {session_ID}")

            # STEP 1-2: verifying the deviceID validity
            op_res = helper.set_vault(None, device_ID.decode())

            if not op_res.startswith("OK"):
                return

            # STEP 2: creates and sends M2 to IoT device
            print("Sending M2 to the client!")

            self.request.sendall(helper.create_m2())

            # STEP 3: receiving M3 from IoT device
            m3 = self.request.recv(1024)

            print(f"Received M3: {m3}")

            # STEP 3-4: verifying the IoT device's response
            if helper.verify_device_response(m3):
                #STEP 4: create and sends M4 to IoT device
                self.request.sendall(helper.create_m4())

                # RECEIVING DATA
                while not (data := self.request.recv(1024)) == b'':
                    # data registration (out of scope)
                    print(f"Data: {data}")
                    buffer += data

                helper.update_vault(buffer, session_ID.decode())
        except socket.timeout:
            pass


if __name__ == "__main__":
    HOST, PORT = "localhost", 5050

    # server creation and binding the socket to a given port
    auth_server = socketserver.TCPServer((HOST, PORT), AuthenticationHandler)

    auth_server.serve_forever()