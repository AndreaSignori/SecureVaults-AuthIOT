from utils.utils import padding

import hmac
import hashlib
import random

PARTITION_DIM = 256 # linked to the hash function used for HMAC

class SecureVault:
    """
    Class that describe a secure vault. A secure vault, briefly, is a set of n keys of m bits each that is shared between each IoT device and server.
    """
    def __init__(self, sv: list[int]):
        """
        :param sv: list of all keys that belong to the secure vault.
        """
        self._n: int = len(sv) # number of keys in the secure vault
        self._m: int = max([key.bit_length() for key in sv]) # number of bits for each keys
        self._sv: list = sv

    def get_vault_dim(self) -> int:
        return self._n

    def get_keys(self, idxs: list) -> list:
        return [self._sv[idx] for idx in idxs]

    def update(self, key: bytes) -> list: #TODO: da sistemare
        """
        Update the secure vault keys.
        TODO: spiegare algoritmo

        :param key: key use to compute the HMAC signature.
        :param partition_dim: number of bit for each partition
        """
        h  = hmac.new(key, bytes(self._sv), hashlib.sha256).digest()
        vault_partitions = self._compute_vault_partition()

        #print(vault_partitions)

        for elem in zip(h, [partition for partition in vault_partitions]):
            print(elem)

        self._sv = [a ^ b for a, b in zip(h, [partition for partition in vault_partitions])]

        return self._sv
        #print(self._sv)

    def _compute_vault_partition(self) -> list: #TODO: da sistemare
        """
        Divide the current secure vault into j partition of 256 bits.

        :return: partition of the current secure vault.
        """
        # TODO: to fix
        sv_str = "".join([padding(bin(value).replace("0b", ""), self._m) for value in self._sv])

        # vault partitioning
        if (reminder := len(sv_str) % PARTITION_DIM) != 0:
            sv_str = padding(sv_str, len(sv_str) + reminder)
        print(sv_str)

        vault_partitions = [sv_str[(start := i * PARTITION_DIM) : start + PARTITION_DIM] for i in range(len(sv_str) // PARTITION_DIM)]

        return vault_partitions

if __name__ == '__main__':
    sv = SecureVault([random.getrandbits(6) for _ in range(3)])

    sv.update(b"dati prova")