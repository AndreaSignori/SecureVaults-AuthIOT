from helper import AuthHelper

import socketserver

# CONFIG parameters
SESSION_KEY = b"chiave di prova"

class AuthenticationHandler(socketserver.BaseRequestHandler):
    def __init__(self):
        super().__init__(self.request, self.client_address, self.server)
        self._helper: AuthHelper = AuthHelper(SESSION_KEY)
        self._buffer: str = ""
        self._deviceID: str = ""
        self._sessioID: str = ""
        self._timeout: int = 1 # express in second
    def handle(self):
        # TODO: serve un protocollo per identificare i pacchetti per gestire al meglio il server
        # AUTHENTICATION
        # STEP1: receiving M1 from IoT device
        m1 = self.request.settimeout(self._timeout)
        self._deviceID = m1[: ...] # TODO: difinire limiti
        self._sessioID = m1[: ...] # TODO: definire limiti

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
        while (data := self.request.settimeout(self._timeout)) is not None:
            # data registration (out of scope)
            self._buffer += data

        self._helper.update_vault(self._buffer.encode(), self._sessioID)


if __name__ == "__main__":
    HOST, PORT = "localhost", 5050

    # server creation and binding the socket to a given port
    auth_server = socketserver.TCPServer((HOST, PORT), AuthenticationHandler)

    auth_server.serve_forever()