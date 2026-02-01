import os
from argon2.low_level import hash_secret_raw, Type

def derive_key(password: str, salt: bytes):
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return key

def generate_salt():
    return os.urandom(16)

