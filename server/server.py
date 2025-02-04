from helper import AuthHelper

import socketserver

# CONFIG parameters
SESSION_KEY = b"chiave di prova"

class AuthenticationHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self._helper: AuthHelper = AuthHelper(SESSION_KEY)
        self._sessionID = None
        self._deviceID = None

    def handle(self):
        self.request.settimeout(TIMEOUT) # setting up the timeout to receiving next message from the client
        buffer: bytes = b''

        try:
            # AUTHENTICATION

            # STEP1: receiving M1 from IoT device
            m1 = self.request.recv(1024)

            self._deviceID = m1[: DEVICE_ID_LENGTH]
            self._sessionID = m1[DEVICE_ID_LENGTH:]

            print(f"Device ID: {self._deviceID}")
            print(f"Session ID: {self._sessionID}")

        # STEP 1-2: verifying the deviceID validity
        op_res = self._helper.set_vault(None, self._deviceID)

        if not op_res.startswith("OK"):
            return

        # STEP 2: creates and sends M2 to IoT device
        self.request.sendall(self._helper.create_m2())

        # STEP 3: receiving M3 from IoT device
        m3 = self.request.settimeout(self._timeout)

        # STEP 3-4: verifying the IoT device's response
        self._helper.verify_device_response()

        #STEP 4: create and sends M4 to IoT device
        self.request.sendall(self._helper.create_m4())

            # RECEIVING DATA
            while not (data := self.request.recv(1024)) == b'':
                # data registration (out of scope)
                    print(f"Data: {data}")
                    #self._buffer += data
                    buffer += data
                    self.request.sendall(data)

            # self._helper.update_vault(self._buffer.encode(), self._sessioID)
        except socket.timeout:
            pass


if __name__ == "__main__":
    HOST, PORT = "localhost", 5050

    # server creation and binding the socket to a given port
    auth_server = socketserver.TCPServer((HOST, PORT), AuthenticationHandler)

    auth_server.serve_forever()