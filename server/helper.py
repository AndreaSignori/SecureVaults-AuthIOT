from SVManager import SVManager
from securevault import SecureVault
from numpy.random import randint

import numpy as np

# CONFIG parameters
DB_NAME = "data/devices.db"
GENERATOR_UPPER_BOUND = 10000

class AuthHelper:
    """
    Class that define the server side authentication for our protocol
    """
    def __init__(self, session_key: bytes, sv: list[int]|None=None):
        """
        :param session_key: shared secret between client and server
        :param sv: secure vault to be used during the authentication
        """
        self._session_key: bytes = session_key
        self._secure_valult: SecureVault|None = sv
        self._manager: SVManager = SVManager(DB_NAME)
        self._c1: np.ndarray|None = None
        self._r1: int = -1
        #self._k1: int = 0

    def set_vault(self, sv: list[int]|None, id: str|None) -> str|None:
        if not isinstance(sv, list):
            return f"The set should be a list and not {type(sv)}"

        if self._secure_valult is not None:
            return "Secure vault already set"

        if sv is not None: # secure vault gets from the network (initial value is sent by IoT device)
            self._secure_valult = SecureVault(sv)
        else:
            if (secure_vault := self._manager.get_SV(id)) is not None:
                self._secure_valult = SecureVault(list(secure_vault))
            else:
                return f"Device with ID {id} isn't registered!"
            return "OK: Secure vault set"

    def create_m2(self) -> dict:
        self._c1: np.ndarray= randint(0, self._secure_valult.get_vault_dim(),
                                      size=(randint(0, self._secure_valult.get_vault_dim()), ),
                                      dtype=int)
        self._r1 = randint(GENERATOR_UPPER_BOUND)

        return {"C1": self._c1, "r1": self._r1}

    def verify_device_response(self):
        pass

    def create_m4(self):
        pass

    def _computeKey1(self) -> int:
        P = self._secure_valult.get_keys(self._c1)
        k1 = 0

        for i in range(len(P)):
            k1 ^= P[i]

        return k1

    def update_vault(self, key: bytes, id: str):
        new_vault = self._secure_valult.update(key)

        self._manager.update_SV(id, ",".join(new_vault))
