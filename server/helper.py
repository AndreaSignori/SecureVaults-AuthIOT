from numpy.random import choice, randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from SVManager import SVManager
from securevault import SecureVault
from utils.utils import padding, str_to_dict

import numpy as np

# CONFIG parameters
DB_NAME = "./data/devices.db"
GENERATOR_UPPER_BOUND = 10000
KEY_LENGTH = 32 # length of the key according to the AES algorithm that we want to use
IV = b'0' * 16 #* KEY_LENGTH

class AuthHelper:
    """
    Class that define the server side authentication for our protocol defining every operation need to accomplish the authentication
    """
    def __init__(self, sv: list|None=None) -> None:
        """
        :param sv: secure vault to be used during the authentication
        """
        self._secure_vault: SecureVault | None = sv
        self._manager: SVManager = SVManager(DB_NAME)
        self._c1: np.ndarray|None = None
        self._c2: np.ndarray|None = None
        self._r1: int = -1
        self._r2: int = -1
        self._t1: int = -1
        self._t2: int = -1
        self._session_key: int = -1

    def set_vault(self, sv: list[int]|None, id: str|None) -> str|None:
        """
        Set the initial value for the secure vault to be used during the authentication according to some possible

        :param sv: values for the secure vault if it knows. Ignore the id parameter
        :param id: id of the device for which we retrieve from the database
        :return: string that describe the successful or not. If not explai the why
        """
        if self._secure_vault is not None:
            return "Secure vault already set"

        if sv is not None: # secure vault gets from the network (initial value is sent by IoT device)
            if not isinstance(sv, list):
                return f"The set should be a list and not {type(sv)}"
            else:
                self._secure_vault = SecureVault(sv)

                return "OK: Secure vault set"
        else: # retrieve secure vault from the db
            if (secure_vault := self._manager.get_SV(id).split(',')) is not None:
                # removing non-printable character maybe added by the encryption (due to padding)
                secure_vault[-1] = "".join([c for c in secure_vault[-1] if c.isprintable()])
                secure_vault = ",".join(secure_vault)

                secure_vault = [i for i in map(int, secure_vault.split(','))]

                self._secure_vault = SecureVault(secure_vault)
            else:
                return f"Device with ID {id} isn't registered!"
            return "OK: Secure vault set"

    def create_m2(self) -> bytes:
        """
        Build message M2={C1, r1}  that consist of the challenge message from server to device as follows:
            * C1 is a set of p random distinct numbers (p is random too) within 0 and n-1, where n is the number of key in the secure vault. In other words each number of C1 is an index of a key stored in the secure vault
            * r1 is a random number used for the challenge, later use to verify the response from the device

        :return: message m2 in json format encoded
        """
        self._c1: np.ndarray= choice(range(self._secure_vault.get_vault_dim()),
                                     size=(randint(1, self._secure_vault.get_vault_dim() + 1),),
                                     replace=False)
        self._r1 = randint(GENERATOR_UPPER_BOUND)

        return str({"C1": ",".join(map(str, self._c1)), "r1": self._r1}).encode()

    def _m3_decrypt(self, cypher_message: bytes) -> bytes:
        """
        Decrypt a message M3 that will contain r1 and the device challenge for the server

        :param cypher_message: cypher message using AES

        :return: decrypted message
        """
        key: str = self._compute_key(self._c1).decode('utf-8')

        # adjust the key length
        if len(key) < KEY_LENGTH: # we get AES-256, aka 32 bytes long key
            key = padding(key, KEY_LENGTH)

        return AES.new(key.encode(), AES.MODE_CBC, iv=IV).decrypt(cypher_message)

    def _compute_key(self, index_set: list, const: int=0) -> bytes:
        """
        Computes the key as a XOR of all the keys in the secure vault indexed by index_set

        :param index_set: list of indexes of the key values used to compute the XOR
        :param const: eventual additional value to XORed with the key. Default value is 0, so doesn't influence the final key value

        :return: key used to decrypt the message
        """
        P = self._secure_vault.get_keys(index_set)
        key = 0

        for i in range(len(P)):
            key ^= P[i]

        return str(key ^ const).encode()

    def verify_device_response(self, message: bytes) -> bool:
        """
        Verify the challenge response from the device if the r1 generated is the same in the message received

        :param message: received message from the device containing r1, t1 (portion of the session key) and the new challenge

        :return: True if r1 sent correspond to the one received, False otherwise
        """
        plain = str_to_dict(self._m3_decrypt(message).decode()) # convert string in dictionary format to actual dictionary

        self._c2 = [i for i in map(int, plain["C2"].split(','))]
        self._t1 = int(plain["t1"])
        self._r2 = int("".join([c for c in plain["r2"] if c.isprintable()]))

        return int(plain["r1"]) == self._r1


    def _m4_encrypt(self, plain_message: bytes) -> bytes:
        """
        Encrypt a message M4 with the key computed as k2 xor t1.

        :param plain_message: message to encrypt using AES

        :return: encrypted message
        """
        key: str = self._compute_key(self._c2, self._t1).decode()

        # adjust the key length
        if len(key) < KEY_LENGTH:  # we get AES-128, aka 16 bytes long key
            key = padding(key, KEY_LENGTH)

        return AES.new(key.encode(), AES.MODE_CBC, iv=IV).encrypt(pad(plain_message, AES.block_size)).hex().encode()

    def create_m4(self) -> bytes:
        """
        Create a message M4=Enc(k2 xor t1, r2||t2), where the content of the message is r2||t2 (r2 is the challenge for the device and t2 is the second part for the session key, and it is a random value).
        While k2 xor t1 is the key used to encrypt the message.

        :return: encrypted message
        """
        self._t2 = randint(GENERATOR_UPPER_BOUND)

        message = str({"r2": self._r2, "t2": self._t2}).encode()

        self._compute_session_key()

        return self._m4_encrypt(message)

    def _compute_session_key(self) -> None:
        """
        Compute the session key as the xor between t1 and t2
        """
        self._session_key = self._t1 ^ self._t2

    def update_vault(self, key: bytes, device: str) -> None:
        """
        Update the secure vault with the given key used during the computation of HMAC

        :param key: HMAC key
        :param device: id of the device use to save the secure vault into the database kept by the server
        """
        new_vault = [i for i in map(str, self._secure_vault.update(key))] # compute the updated value for the secure vault

        self._manager.update_SV(device, ",".join(new_vault))  # update the value for the secure vault into the database