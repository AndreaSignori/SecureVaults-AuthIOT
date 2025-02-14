from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# CONFIG params
KEY = b"super_secret_key"
IV = b'0' * 16

class MemManager:
    def __init__(self, mem_idx: str) -> None:
        self._mem_idx = mem_idx

    def read(self) -> str:
        try:
            with open(self._mem_idx, "rb") as f:
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                #plain = AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(f.read()).decode().split(',')

                #plain[-1] = "".join([c for c in plain[-1].strip(',') if c.isprintable()])

                #return ",".join(plain)
                return unpad(cipher.decrypt(f.read()), cipher.block_size).decode()
        except FileNotFoundError:
            return ""

    def write(self, new_content: str) -> None:
        try:
            with open(self._mem_idx, "wb") as f:
                f.write(AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(pad(new_content.encode(), AES.block_size)))
        except FileNotFoundError:
            pass