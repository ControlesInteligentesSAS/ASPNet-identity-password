from itsdangerous import base64_decode, base64_encode
from passlib.utils.pbkdf2 import pbkdf2
import secrets
import base64


def hashPassword(password) -> str:
    salt = secrets.token_bytes(16)
    passgened=pbkdf2(password, salt, 1000, 32, "hmac-sha1")
    resultado = b'0' + salt + passgened
    return base64.b64encode(resultado).decode('ASCII')


def validatePassword(password: str, hashedPassword) -> bool:
    src = base64_decode(hashedPassword)
    if len(src) != 49:
        return False
    salt = src[1:17]
    bytes = src[17:49]
    passgened=pbkdf2(password, salt, 1000, 32, "hmac-sha1")
    for i in range(0, len(bytes)):
        if bytes[i] != passgened[i]:
            return False
    return True
    
