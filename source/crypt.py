import sys, json, logging, json_logging, pickle, os

from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# log is initialized without a web framework name
json_logging.ENABLE_JSON_LOGGING = True
json_logging.init_non_web()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler(sys.stdout))

with open("config.json") as f:
    cryptkey = json.load(f)["encryptionkey"]

def encrypt(objects):
    blob = pickle.dumps(objects)
    cipher = Cipher(
        algorithms.AES(shared_key.encode()),
        modes.CTR(
            "\x00".encode() * 16),
        backend=default_backend())
    e = cipher.encryptor()

    return hexlify(e.update(blob) + e.finalize())


def decrypt(cryptpickle):
    ct = unhexlify(cryptpickle)
    cipher = Cipher(
        algorithms.AES(shared_key.encode()),
        modes.CTR(
            "\x00".encode() * 16),
        backend=default_backend())
    d = cipher.decryptor()

    return pickle.loads(d.update(ct) + d.finalize())
