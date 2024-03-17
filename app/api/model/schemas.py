from pydantic import BaseModel


class ECPublicKey(BaseModel):
    x: str
    y: str


class RSAPublicKey(BaseModel):
    modulus: str
    exponent: str


class ECSignature(BaseModel):
    r: str
    s: str


class BaseCertificate(BaseModel):
    signature: ECSignature


class CertificateIn(BaseCertificate):
    json_encoded_keys: str


class CertificateOut(BaseCertificate):
    signature_public_key: ECPublicKey
    encryption_public_key: RSAPublicKey

class TrusteeCertificates(BaseModel):
    certificates: list[CertificateOut]

class SignedBroadcast(BaseModel):
    broadcast: str  # Tuple(BigInt, BigInt) encoded as String
    signature: ECSignature


class SignedShare(BaseModel):
    encrypted_share: str  # BigInt encoded as String
    signature: ECSignature


class KeyGenStep1Data(BaseModel):
    signed_broadcasts: list[SignedBroadcast]
    signed_shares: list[SignedShare]


class KeyGenStep2Data(BaseModel):
    acknowledgements: list[ECSignature]


class KeyGenStep3Data(BaseModel):
    verification_key: str # Tuple(BigInt, BigInt) encoded as String


# --- Placeholders ---


class DecryptionIn(BaseModel):
    decryptions: list
