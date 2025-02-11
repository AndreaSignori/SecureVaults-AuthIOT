from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# CONFIG params
KEY = b"super_secret_key"
IV = b'0' * 16

class MemManager:
    def __init__(self, mem_idx: str) -> None:
        self._mem_idx = mem_idx

    def read(self) -> str:
        with open(self._mem_idx, "rb") as f:
             return AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(f.read()).decode()

    def write(self, new_content: str) -> None:
        with open(self._mem_idx, "wb") as f:
            f.write(AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(pad(new_content.encode(), AES.block_size)))