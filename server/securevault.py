from utils.utils import padding

import numpy as np
import hmac
import hashlib

# CONFIG params
PARTITION_DIM = 512 # linked to the hash function used for HMAC

class SecureVault:
    """
    Class that describe a secure vault. A secure vault, briefly, is a set of n keys of m bits each that is shared between each IoT device and server.
    """
    def __init__(self, sv: list[int]) -> None:
        """
        :param sv: list of all keys that belong to the secure vault.
        """
        self._n: int = len(sv) # number of keys in the secure vault
        self._m: int = sv[np.argmax(sv)].bit_length() # number of bits for each key. We are interested in the maximum value of bit for each key
        self._sv: list = sv

    def get_vault_dim(self) -> int:
        """
        :return: the dimension of the secure vault.
        """
        return self._n

    def get_keys(self, idxs: list) -> list:
        """
        :param idxs: set of indexes that point to a subset of keys in the secure vault

        :return: subset of keys in the secure vault.
        """
        return [self._sv[idx] for idx in idxs]

    def update(self, key: bytes) -> list:
        """
        Update the secure vault keys according to the following algorithm at the end of the session.
            * compute the HMAC of the actual secure vault value with a given key (in this case we use the data sent during all the session as key);
            * divide the current value of the secure vault in j equal partition fo k bits (k is the length in bits of the HMAC result);
            * XORed each partition of the secure vault with the HMAC result.
        NOTE:
            if the size of the secure vault is not divisible for k, we add a sequence of zeros at the end, as padding, in order to get j equal partitions.

        :param key: key use to compute the HMAC signature.

        :return: secure vault updated.
        """
        h  = int(hmac.new(key, ",".join(map(str, self._sv)).encode(), hashlib.sha512).digest().hex(), 16)

        vault_partitions = self._compute_vault_partition()

        self._sv = [h ^ partition for partition in vault_partitions]

        return self._sv

    def _compute_vault_partition(self) -> list:
        """
        Divide the current secure vault into j partition of PARTITION_DIM bits.

        :return: partition of the current secure vault.
        """
        sv_str = "".join(map(str, self._sv))
        bin_vault = bin(int(sv_str)).replace("0b", "")

        if (reminder := len(bin_vault) % PARTITION_DIM) != 0:
            bin_vault = padding(bin_vault, len(bin_vault) + (PARTITION_DIM - reminder)) # PARTITION - reminder gives an amount of zeros need to add to get a secure vault divisible by k

        return [int(f"0b{bin_vault[(start := i * PARTITION_DIM): start + PARTITION_DIM]}", 2) for i in range(len(bin_vault) // PARTITION_DIM)]