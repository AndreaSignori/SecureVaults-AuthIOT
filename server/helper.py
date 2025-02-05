from SVManager import SVManager
from securevault import SecureVault
from numpy.random import choice, randint
from Crypto.Cipher import AES

from utils.utils import padding, str_to_dict

import numpy as np

# CONFIG parameters
DB_NAME = "data/devices.db"
GENERATOR_UPPER_BOUND = 10000

class AuthHelper:
    """
    Class that define the server side authentication for our protocol
    """
    def __init__(self, sv: list[int]|None=None):
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
        if self._secure_vault is not None:
            return "Secure vault already set"

        if sv is not None: # secure vault gets from the network (initial value is sent by IoT device)
            if not isinstance(sv, list):
                return f"The set should be a list and not {type(sv)}"
            else:
                self._secure_vault = SecureVault(sv)

                return "OK: Secure vault set"
        else:
            if (secure_vault := self._manager.get_SV(id)) is not None:
                secure_vault = [i for i in map(int, list(secure_vault)[0].split(','))]

                self._secure_vault = SecureVault(secure_vault)
            else:
                return f"Device with ID {id} isn't registered!"
            return "OK: Secure vault set"

    def create_m2(self) -> bytes:
        self._c1: np.ndarray= choice(range(self._secure_vault.get_vault_dim()),
                                     size=(randint(1, self._secure_vault.get_vault_dim() + 1),),
                                     replace=False)
        self._r1 = randint(GENERATOR_UPPER_BOUND)

        return str({"C1":",".join(map(str, self._c1)), "r1": self._r1}).encode()

    def _m3_decrypt(self, cypher_message: bytes) -> bytes:
        key: str = self._compute_key().decode('utf-8')

        if len(key) < 16: # we get AES-128, aka 16 bytes long key
            key = padding(key, 16)

        return AES.new(key.encode(), AES.MODE_EAX).decrypt(cypher_message)

    def _compute_key(self, const: int=0) -> bytes:
        P = self._secure_vault.get_keys(self._c1)
        key = 0

        for i in range(len(P)):
            key ^= P[i]

        return str(key ^ const).encode()

    def verify_device_response(self, message: bytes) -> bool:
        plain = str_to_dict(self._m3_decrypt(message).decode())

        self._c2 = plain["C2"]
        self._t1 = plain["t1"]
        self._r2 = plain["r2"]


        return plain["r1"] == self._r1


    def _m4_encrypt(self, plain_message: bytes) -> bytes:
        key: str = self._compute_key(self._t1).decode()

        if len(key) < 16:  # we get AES-128, aka 16 bytes long key
            key = padding(key, 16)

        return AES.new(key, AES.MODE_EAX).encrypt(plain_message)

    def create_m4(self):
        self._t2 = randint(GENERATOR_UPPER_BOUND)

        message = str({"r2": self._r2, "t2": self._t2}).encode()

        self._compute_session_key()

        return self._m4_encrypt(message)

    def _compute_session_key(self) -> int:
        self._session_key = self._t1 ^ self._t2

    def update_vault(self, key: bytes, id: str):
        new_vault = self._secure_vault.update(key)

        self._manager.update_SV(id, ",".join(new_vault))
