# https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

VERBOSE = False

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

PC_1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,

]

PC_2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

SBOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

SBOX_P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

CD_SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
]

def log(s: str | None = None) -> None:
    if VERBOSE:
        print(s)

def pbin(num: int, pad: int = 64) -> str:
    return bin(num)[2:].zfill(pad)


def phex(num: int, pad: int = 16) -> str:
    return hex(num)[2:].zfill(pad)


def permute(block: int, table: list[int], block_size: int) -> int:
    result = 0
    for bit_position in table:
        bit_set = (block >> (block_size - bit_position)) & 1
        result <<= 1
        result |= bit_set

    return result


def kdf(key: int) -> list[int]:
    log(f"initial key: {phex(key)} ({pbin(key)})")

    permuted_key = permute(key, PC_1, 64) & 0xFFFFFFFFFFFFFF
    log(f"after key ip: {phex(permuted_key, 14)} ({pbin(permuted_key, 56)})")

    log()

    c0 = permuted_key >> 28 & 0xFFFFFFF
    d0 = permuted_key & 0xFFFFFFF

    log(f"C0: {phex(c0, 7)} ({pbin(c0, 28)})")
    log(f"D0: {phex(d0, 7)} ({pbin(d0, 28)})")

    log()

    lc = c0
    ld = d0

    keys = []

    for n in range(16):
        cn = lc
        dn = ld

        for _ in range(CD_SHIFTS[n]):
            c_leftmost_bit = (cn >> 27) & 1
            cn = ((cn << 1) & 0xFFFFFFF) | c_leftmost_bit

            d_leftmost_bit = (dn >> 27) & 1
            dn = ((dn << 1) & 0xFFFFFFF) | d_leftmost_bit

        log(f"C{n + 1}: {phex(cn, 7)} ({pbin(cn, 28)})")
        log(f"D{n + 1}: {phex(dn, 7)} ({pbin(dn, 28)})")

        cd = (cn << 28) | dn
        log(f"CD{n + 1}: {phex(cd, 14)} ({pbin(cd, 56)})")

        kn = permute(cd, PC_2, 56)
        log(f"K{n + 1}: {phex(kn, 12)} ({pbin(kn, 48)})")

        keys.append(kn)

        lc = cn
        ld = dn

        log()

    return keys


def f(block: int, key: int) -> int:
    block_ex = permute(block, E, 32)
    log(f"E(Rn): {phex(block_ex, 12)} ({pbin(block_ex, 48)})")

    xorred = (block_ex ^ key) & 0xFFFFFFFFFFFF
    log(f"E(Rn) ^ Kn: {phex(xorred, 12)} ({pbin(xorred, 48)})")

    result = 0
    for n in range(8):
        b = (xorred >> ((8 - n - 1) * 6)) & 0b111111
        log(f"B{n + 1}: {pbin(b, 6)}")
        row = (((b >> 5) & 1) << 1) | (b & 1)
        col = (b >> 1) & 0b1111

        s_num = SBOX[n][row][col]
        log(f"S{n + 1}: {pbin(s_num, 4)}")

        result <<= 4
        result |= s_num

    log(f"S...: {phex(result, 8)} ({pbin(result, 32)})")
    log()

    return permute(result, SBOX_P, 32) & 0xFFFFFFFF


def one_round(last_l: int, last_r: int, key: int) -> tuple[int, int]:
    return last_r, last_l ^ f(last_r, key)


def sixteen_rounds(l0: int, r0: int, keys: list[int]) -> int:
    last_l = l0
    last_r = r0

    for n in range(16):
        last_l, last_r = one_round(last_l, last_r, keys[n])

    return (last_r << 32) | last_l


def process_block(block: int, key: int, decrypt: bool) -> int:
    log(f"initial data: {phex(block)} ({pbin(block)})")

    permuted = permute(block, IP, 64)
    log(f"after data ip: {phex(permuted)} ({pbin(permuted)})")

    log()

    l0 = permuted >> 32 & 0xFFFFFFFF
    r0 = permuted & 0xFFFFFFFF

    log(f"L0: {phex(l0, 8)} ({pbin(l0, 32)})")
    log(f"R0: {phex(r0, 8)} ({pbin(r0, 32)})")

    log()

    keys = kdf(key)
    if decrypt:
        keys.reverse()

    rl = sixteen_rounds(l0, r0, keys)

    final = permute(rl, FP, 64)
    log(f"final: {phex(final)} ({pbin(final)})")

    return final


def encrypt_block(data: int, key: int) -> int:
    return process_block(data, key, False)


def decrypt_block(data: int, key: int) -> int:
    return process_block(data, key, True)


def pad(data: bytes, to_size: int) -> bytes:
    if len(data) % to_size == 0:
        return data

    add_padding = (-len(data) % to_size)
    return data + bytes([add_padding]) * add_padding


def unpad(data: bytes, max_size: int) -> bytes:
    if not data:
        return data

    last = data[-1]
    if last >= max_size:
        return data

    if data[-last:] == bytes([last]) * last:
        return data[:-last]

    return data


def ecb_encrypt(data: bytes, key: int) -> bytes:
    result = b""

    for blocknum in range((len(data) + 7) // 8):
        block_bytes = data[blocknum * 8:(blocknum + 1) * 8]
        block_bytes = pad(block_bytes, 8)

        block = int.from_bytes(block_bytes, "big", signed=False)
        encrypted = encrypt_block(block, key)
        result += encrypted.to_bytes(8, "big", signed=False)

    return result


def ecb_decrypt(data: bytes, key: int) -> bytes:
    result = b""

    for blocknum in range((len(data) + 7) // 8):
        block_bytes = data[blocknum * 8:(blocknum + 1) * 8]
        block = int.from_bytes(block_bytes, "big", signed=False)
        decrypted = decrypt_block(block, key)
        decrypted_bytes = decrypted.to_bytes(8, "big", signed=False)
        result += unpad(decrypted_bytes, 8)

    return result


def main_block() -> None:
    key = 0x133457799BBCDFF1
    data = 0x0123456789ABCDEF

    encrypted = encrypt_block(data, key)
    print(f"encrypted: {phex(encrypted)} ({pbin(encrypted)})")

    decrypted = decrypt_block(encrypted, key)
    print(f"decrypted: {phex(decrypted)} ({pbin(decrypted)})")


def main() -> None:
    key = 0x133457799BBCDFF1
    data = b"test message"

    encrypted = ecb_encrypt(data, key)
    print(f"encrypted: {encrypted.hex()}")

    decrypted = ecb_decrypt(encrypted, key)
    print(f"decrypted: {decrypted}")


if __name__ == "__main__":
    main()
