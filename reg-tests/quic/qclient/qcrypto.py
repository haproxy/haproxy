"""Minimal QUIC v1 packet protection (RFC 9001) with the cryptography package."""
import hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def hkdf_extract(salt, ikm, h=hashlib.sha256):
    return hmac.new(salt, ikm, h).digest()

def hkdf_expand(prk, info, length, h=hashlib.sha256):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest(); out += t; i += 1
    return out[:length]

def hkdf_label(secret, label, ctx, length, h=hashlib.sha256):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_expand(secret, info, length, h)

class Keys:
    def __init__(self, secret, h=hashlib.sha256, klen=16):
        self.secret = secret
        self.key = hkdf_label(secret, b"quic key", b"", klen, h)
        self.iv = hkdf_label(secret, b"quic iv", b"", 12, h)
        self.hp = hkdf_label(secret, b"quic hp", b"", klen, h)
        self.aead = AESGCM(self.key)
    def mask(self, sample):
        e = Cipher(algorithms.AES(self.hp), modes.ECB()).encryptor()
        return e.update(sample) + e.finalize()
    def nonce(self, pn):
        return bytes(a ^ b for a, b in zip(self.iv, pn.to_bytes(12, "big")))

def initial_keys(dcid):
    s = hkdf_extract(SALT_V1, dcid)
    return Keys(hkdf_label(s, b"client in", b"", 32)), Keys(hkdf_label(s, b"server in", b"", 32))

def varint(v):
    if v < 0x40: return bytes([v])
    if v < 0x4000: return struct.pack(">H", v | 0x4000)
    if v < 0x40000000: return struct.pack(">I", v | 0x80000000)
    return struct.pack(">Q", v | 0xC000000000000000)

def read_varint(b, i):
    l = 1 << (b[i] >> 6); v = b[i] & 0x3f
    for k in range(1, l): v = (v << 8) | b[i + k]
    return v, i + l

def protect_long(keys, ptype, dcid, scid, pn, payload, token=b"", pn_len=4, version=1):
    """ptype: 0 Initial, 2 Handshake. Returns protected packet bytes."""
    first = 0xC0 | (ptype << 4) | (pn_len - 1)
    hdr = bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    if ptype == 0: hdr += varint(len(token)) + token
    length = pn_len + len(payload) + 16
    hdr += varint(length)
    pn_off = len(hdr)
    hdr += (pn & ((1 << (8 * pn_len)) - 1)).to_bytes(pn_len, "big")
    ct = keys.aead.encrypt(keys.nonce(pn), payload, hdr)
    pkt = bytearray(hdr + ct)
    m = keys.mask(bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= m[0] & 0x0f
    for k in range(pn_len): pkt[pn_off + k] ^= m[1 + k]
    return bytes(pkt)

def protect_short(keys, dcid, pn, payload, pn_len=4, key_phase=0):
    first = 0x40 | (key_phase << 2) | (pn_len - 1)
    hdr = bytes([first]) + dcid
    pn_off = len(hdr)
    hdr += (pn & ((1 << (8 * pn_len)) - 1)).to_bytes(pn_len, "big")
    ct = keys.aead.encrypt(keys.nonce(pn), payload, hdr)
    pkt = bytearray(hdr + ct)
    m = keys.mask(bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= m[0] & 0x1f
    for k in range(pn_len): pkt[pn_off + k] ^= m[1 + k]
    return bytes(pkt)

def unprotect(keys, pkt, pn_off, long_hdr, end, largest=0):
    """Remove protection of the packet pkt[0:end] whose pn starts at pn_off."""
    pkt = bytearray(pkt[:end])
    m = keys.mask(bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= m[0] & (0x0f if long_hdr else 0x1f)
    pn_len = (pkt[0] & 3) + 1
    pn = 0
    for k in range(pn_len):
        pkt[pn_off + k] ^= m[1 + k]; pn = (pn << 8) | pkt[pn_off + k]
    # pn reconstruction (RFC 9000 A.3)
    win = 1 << (8 * pn_len); exp = largest + 1
    cand = (exp & ~(win - 1)) | pn
    if cand <= exp - win // 2 and cand < (1 << 62) - win: cand += win
    elif cand > exp + win // 2 and cand >= win: cand -= win
    hdr = bytes(pkt[:pn_off + pn_len])
    pt = keys.aead.decrypt(keys.nonce(cand), bytes(pkt[pn_off + pn_len:]), hdr)
    return cand, pt, pkt[0]

if __name__ == "__main__":
    # RFC 9001 appendix A.1
    c, s = initial_keys(bytes.fromhex("8394c8f03e515708"))
    assert c.key.hex() == "1f369613dd76d5467730efcbe3b1a22d", c.key.hex()
    assert c.iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert c.hp.hex() == "9f50449e04a0e810283a1e9933adedd2"
    assert s.key.hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert s.hp.hex() == "c206b8d9b9f0f37644430b490eeaa314"
    # A.5 ChaCha is not used; A.2 client initial header protection check
    print("RFC 9001 A.1 vectors OK")
