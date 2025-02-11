from numpy.random import choice, randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from utils.utils import padding, str_to_dict
from securevault import SecureVault
from memManager import MemManager

import numpy as np

# CONFIG parameters
MEM_IDX = "./mem/mem.txt"
GENERATOR_UPPER_BOUND = 10000
KEY_LENGTH = 16 # length of the key according to the AES algorithm that we want to use
IV = b'0' * KEY_LENGTH

class AuthHelper:
    """
    Class that define the client side authentication for our protocol defining every operation need to accomplish the authentication
    """
    def __init__(self, sv: list|None=None) -> None:
        """
        :param sv: secure vault to be used during the authentication
        """
        self._secure_vault: SecureVault | None = sv
        self._mem_manager: MemManager = MemManager(MEM_IDX)
        self._c1: np.ndarray|None = None
        self._c2: np.ndarray|None = None
        self._r1: int = -1
        self._r2: int = -1
        self._t1: int = -1
        self._t2: int = -1
        self._session_key: int = -1

    def set_c1(self, value: np.ndarray|None) -> None:
        self._c1 = value

    def set_r1(self, value: int) -> None:
        self._r1 = value

    def set_vault(self) -> SecureVault:
        """
        Set the initial value for the secure vault to be used during the authentication according to some possible

        :return:
        """
        return SecureVault([i for i in map(int, self._mem_manager.read().split(','))])

    def create_m1(self, device_id, session_id) -> bytes:
        """
        Build message M1{deviceID, sessionID} that is a sort of "welcoming" message from the client to the server

        :return: message m1 in json format encoded
        """
        return  str({"device_ID": device_id, "session_ID": session_id}).encode()

    def _m3_encrypt(self, plain_message: bytes) -> bytes:
        """
        Encrypt a message M3 that will contain r1 and the device challenge for the server

        :param plain_message: cypher message using AES

        :return: encrypted message
        """
        key: str = self._compute_key(self._c1).decode('utf-8')

        # adjust the key length
        if len(key) < KEY_LENGTH: # we get AES-128, aka 16 bytes long key
            key = padding(key, KEY_LENGTH)

        return AES.new(key.encode(), AES.MODE_CBC, iv=IV).encrypt(pad(plain_message, AES.block_size)).hex().encode()

    def _compute_key(self, index_set: list, const: int=0) -> bytes:
        """
        Computes the key as XOR of all the keys in the secure vault indexed by index_set

        :param index_set: list of indexes of the key values used to compute the XOR
        :param const: eventual additional value to XORed with the key. Default value is 0, so doesn't influence the final key value

        :return: key used to decrypt the message
        """
        P = self._secure_vault.get_keys(index_set)
        key = 0

        for i in range(len(P)):
            key ^= P[i]

        return str(key ^ const).encode()

    def create_m3(self) -> bytes:
        """
        Create a message M4=Enc(k2 xor t1, r2||t2), where the content of the message is r2||t2 (r2 is the challenge for the device and t2 is the second part for the session key, and it is a random value).
        While k2 xor t1 is the key used to encrypt the message.

        :return: encrypted message
        """
        self._t1 = np.random.randint(GENERATOR_UPPER_BOUND)
        self._c2: np.ndarray = choice(range(self._secure_vault.get_vault_dim()),
                                      size=(randint(1, self._secure_vault.get_vault_dim() + 1),),
                                      replace=False)
        self._r2 = randint(GENERATOR_UPPER_BOUND)

        message = str({"r1": self._r1, "t1": self._t1, "C2": self._c2, "r2": self._r2}).encode()

        return self._m3_encrypt(message)

    def _m4_decrypt(self, cypher_message: bytes) -> bytes:
        """
        Encrypt a message M4 with the key computed as k2 xor t1.

        :param plain_message: message to encrypt using AES

        :return: encrypted message
        """
        key: str = self._compute_key(self._c2, self._t1).decode()

        # adjust the key length
        if len(key) < KEY_LENGTH:  # we get AES-128, aka 16 bytes long key
            key = padding(key, KEY_LENGTH)

        return AES.new(key, AES.MODE_CBC, iv=IV).decrypt(bytes.fromhex(cypher_message.decode()))

    def verify_server_response(self, message: bytes) -> bool:
        """
        Verify the challenge response from the device if the r1 generated is the same in the message received

        :param message: received message from the device containing r1, t1 (portion of the session key) and the new challenge

        :return: True if r1 sent correspond to the one received, False otherwise
        """
        plain = str_to_dict(self._m4_decrypt(message).decode()) # convert string in dictionary format to actual dictionary

        self._t2 = plain["t2"]
        self._r2 = plain["r2"]

        self._compute_session_key()

        return plain["r2"] == self._r2

    def _compute_session_key(self) -> None:
        """
        Compute the session key as the xor between t1 and t2
        """
        self._session_key = self._t1 ^ self._t2

    def update_vault(self, key: bytes) -> None:
        """
        Update the secure vault with the given key used during the computation of HMAC

        :param key: HMAC key
        :param id: id of the device use to save the secure vault into the database kept by the server
        """
        new_vault = self._secure_vault.update(key) # compute the updated value for the secure vault

        self._mem_manager.write(",".join(new_vault)) # update the value for the secure vault into the database