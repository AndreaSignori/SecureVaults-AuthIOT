from securevault import SecureVault
from utils.utils import str_to_dict
from sensors import TemperatureSensor
from helper import AuthHelper

import socket
import time

# CONFIG parameters
DEVICE_ID = "IOTAuth30L"
SESSION_ID = "ID_Session"
TIMEOUT = 1
SESSION_DURATION = 60 # in second

if __name__ == '__main__':
    HOST, PORT = "localhost", 5050
    helper: AuthHelper = AuthHelper() # makes possible to compute the authentication protocol operations
    buffer: str = ""

    # sensors initialization
    tempSensor = TemperatureSensor()

    op_res = helper.set_vault() # getting actual value for the secure vault

    if not op_res.startswith("FAILED"):
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((HOST, PORT))
            sock.settimeout(TIMEOUT) # setting up the timeout to receiving next message from the server

            while True:
                # STEP 1: sends M1
                sock.sendall(helper.create_m1(DEVICE_ID, SESSION_ID))

                # STEP 2: receives M2
                m2 = sock.recv(1024)
                m2 = str_to_dict(m2.decode())

                c1, r1 = [i for i in map(int, m2['C1'].split(','))], m2['r1']

                helper.set_c1(c1)
                helper.set_r1(r1)
                del c1, r1

                # STEP 3: send M3
                sock.sendall(helper.create_m3())

                # STEP 4: receive M4
                m4 = sock.recv(1024)

                # STEP 4-5: verifying the server response
                if helper.verify_server_response(m4):
                    end_time = time.time() + SESSION_DURATION

                    while time.time() < end_time: # communications for a certain amount of time
                        # STEP 5: sending data
                        temp: str = str(tempSensor.get_temperature())
                        buffer += temp

                        sock.sendall(buffer.encode())

                    # STEP 6: update the secure vault
                    helper.update_vault(buffer)

                time.sleep(1) # wait a second before reinitialize new session
        finally:
            sock.close()
    else:
        print(op_res)