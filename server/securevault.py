import numpy as np

from utils.utils import padding

import hmac
import hashlib
import random
import numpy

PARTITION_DIM = 512 # linked to the hash function used for HMAC

class SecureVault:
    """
    Class that describe a secure vault. A secure vault, briefly, is a set of n keys of m bits each that is shared between each IoT device and server.
    """
    def __init__(self, sv: list[int]):
        """
        :param sv: list of all keys that belong to the secure vault.
        """
        self._n: int = len(sv) # number of keys in the secure vault
        self._m: int = sv[np.argmax(sv)].bit_length() # number of bits for each keys. We are interested in the maximum value of bit for each key
        self._sv: list = sv

    def get_vault_dim(self) -> int:
        return self._n

    def get_keys(self, idxs: list) -> list:
        return [self._sv[idx] for idx in idxs]

    def update(self, key: bytes) -> list:
        """
        Update the secure vault keys.
        TODO: spiegare algoritmo

        :param key: key use to compute the HMAC signature.
        :param partition_dim: number of bit for each partition
        """
        h  = int(hmac.new(key, ",".join(map(str, self._sv)).encode(), hashlib.sha512).digest().hex(), 16)

        vault_partitions = self._compute_vault_partition()

        self._sv = [h ^ partition for partition in vault_partitions]

        print(self._sv)

    def _compute_vault_partition(self) -> list: #TODO: da sistemare
        """
        Divide the current secure vault into j partition of 256 bits.

        :return: partition of the current secure vault.
        """
        sv_str = "".join(map(str, self._sv))
        bin_vault = bin(int(sv_str)).replace("0b", "")

        if (reminder := len(bin_vault) % PARTITION_DIM) != 0:
            bin_vault = padding(bin_vault, len(bin_vault) + (PARTITION_DIM - reminder))

        return [int(f"0b{bin_vault[(start := i * PARTITION_DIM): start + PARTITION_DIM]}", 2) for i in range(len(bin_vault) // PARTITION_DIM)]