"""
AES-128 (noldan) - 1-qism:
  1) S-box va Rcon jadvallari
  2) Key Expansion (16 bayt kalit -> 11 ta raund kaliti)
  3) Boshlang'ich raund: AddRoundKey
"""


# ---------- 1. S-box va Rcon ----------

def gf_mul(a, b):
    """GF(2^8) da ko'paytirish (modul: x^8 + x^4 + x^3 + x + 1 = 0x11B)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res


def make_sbox():
    """S-box: GF(2^8) da teskari element + affin almashtirish."""
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gf_mul(x, y) == 1:
                inv[x] = y
                break
    sbox = []
    for x in range(256):
        b = inv[x]
        s = b
        for i in range(1, 5):
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF   # chapga sirkulyar siljitish
        sbox.append(s ^ 0x63)
    return sbox


SBOX = make_sbox()

# Rcon: 0x01 dan boshlab har safar GF(2^8) da 2 ga ko'paytiriladi
RCON = [0x01]
for _ in range(9):
    RCON.append(gf_mul(RCON[-1], 2))
# RCON = 01 02 04 08 10 20 40 80 1B 36


# ---------- 2. Key Expansion ----------

def key_expansion(key: bytes):
    """16 baytlik kalitdan 11 ta raund kaliti (har biri 16 bayt) hosil qiladi."""
    assert len(key) == 16, "Kalit aynan 16 bayt bo'lishi kerak"

    # w - 44 ta so'z (word), har biri 4 bayt
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]

    for i in range(4, 44):
        temp = w[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // 4 - 1]             # Rcon
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    # 4 tadan so'zni birlashtirib, 11 ta 16 baytlik raund kaliti
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(11)]


# ---------- 3. State va AddRoundKey ----------

def bytes_to_state(block: bytes):
    """16 bayt -> 4x4 matritsa (ustunlar bo'yicha: state[qator][ustun])."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


def add_round_key(state, round_key: bytes):
    """State ning har bir baytini raund kaliti bilan XOR qiladi."""
    rk = bytes_to_state(round_key)
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def print_state(title, state):
    print(title)
    for row in state:
        print("  " + " ".join(f"{b:02x}" for b in row))


# ---------- Kiritish va ishga tushirish ----------

def fit16(text: str, name: str) -> bytes:
    """Matnni 16 baytga keltiradi (kam bo'lsa 0x00 bilan to'ldiradi, ko'p bo'lsa kesadi)."""
    data = text.encode("utf-8")
    if len(data) < 16:
        print(f"[!] {name} {len(data)} bayt - 0x00 bilan 16 baytgacha to'ldirildi.")
        data = data.ljust(16, b"\x00")
    elif len(data) > 16:
        print(f"[!] {name} {len(data)} bayt - dastlabki 16 baytga qisqartirildi.")
        data = data[:16]
    return data


def main():
    plaintext = fit16(input("Ochiq matn (16 belgigacha): "), "Ochiq matn")
    key = fit16(input("Kalit so'z (16 belgigacha): "), "Kalit")

    round_keys = key_expansion(key)

    print("\n--- Raund kalitlari ---")
    for r, rk in enumerate(round_keys):
        print(f"Raund {r:2d}: {rk.hex()}")

    state = bytes_to_state(plaintext)
    print()
    print_state("Boshlang'ich state:", state)

    state = add_round_key(state, round_keys[0])     # Boshlang'ich raund
    print()
    print_state("AddRoundKey (raund 0) dan keyin:", state)
    print("Hex:", state_to_bytes(state).hex())


if __name__ == "__main__":
    main()
