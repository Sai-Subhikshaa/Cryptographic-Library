from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from os import urandom

def generate_weak_key(password, salt=None):
    """
    Generates a cryptographic key using PBKDF2 with SHA1,
    a weak hashing algorithm for this purpose.
    """
    if salt is None:
        salt = urandom(16) # Generate a random salt if not provided

    # Using SHA1 for PBKDF2 is considered insecure.
    # A stronger algorithm like SHA256 or SHA512 should be used.
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA1)
    return key, salt

# Example usage:
password = b"mysecretpassword"
weak_key, generated_salt = generate_weak_key(password)

print(f"Generated Key (hex): {weak_key.hex()}")
print(f"Salt (hex): {generated_salt.hex()}")

# In a real scenario, an attacker could potentially brute-force
# or use rainbow tables more effectively against keys derived with SHA1,
# compared to stronger hash functions.
