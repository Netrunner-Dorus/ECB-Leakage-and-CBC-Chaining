from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size
KEY = b"1234567890abcdef"
PLAINTEXT = b"AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB"

def split_blocks(data: bytes, size: int = BLOCK_SIZE) -> list[bytes]:
    return [
        data[i:i + size]
        for i in range(0, len(data), size)
    ]

def print_blocks(blocks: list[bytes], label: str):
    print(f"\n  {label}")

    for index, block in enumerate(blocks, start=1):
        print(f"    Block {index}: {block.hex()}")

def run_experiment():
    print("=" * 65)
    print("AES ECB LEAKAGE AND CBC CHAINING EXPERIMENT")
    print("=" * 65)

    # ==========================================================
    # PART 1: AES-ECB DETERMINISTIC BLOCK LEAKAGE
    # ==========================================================

    print("\n=== PART 1: AES-ECB Deterministic Block Leakage ===")
    plaintext_padded = pad(PLAINTEXT, BLOCK_SIZE)
    plaintext_blocks = split_blocks(plaintext_padded)
    ecb_cipher = AES.new(KEY, AES.MODE_ECB)
    ecb_ct = ecb_cipher.encrypt(plaintext_padded)
    ecb_blocks = split_blocks(ecb_ct)

    print(f"  Plaintext length : {len(PLAINTEXT)} bytes")
    print(f"  Number of blocks : {len(ecb_blocks)}")

    print_blocks(plaintext_blocks, "Plaintext Blocks:")
    print_blocks(ecb_blocks, "ECB Ciphertext Blocks:")

    print(
        "\n  Leakage Check (Block 1 == Block 2):",
        ecb_blocks[0] == ecb_blocks[1]
    )

    print(
        "  Expected Result: True"
    )

    # ==========================================================
    # PART 2: DATABASE ROLE INFERENCE
    # ==========================================================

    print("\n=== PART 2: Database Role Inference Under AES-ECB ===")

    records = {
        "alice": b"ROLE:ADMIN      ",
        "bob":   b"ROLE:GUEST      ",
        "cara":  b"ROLE:ADMIN      "
    }

    encrypted_db = {}

    for user, role in records.items():
        # Each role is exactly one AES block (16 bytes).
        assert len(role) == BLOCK_SIZE
        cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted_db[user] = cipher.encrypt(role)

    for user, ciphertext in encrypted_db.items():
        print(f"  {user:8} -> {ciphertext.hex()}")

    alice_cara_match = (
        encrypted_db["alice"] == encrypted_db["cara"]
    )

    alice_bob_match = (
        encrypted_db["alice"] == encrypted_db["bob"]
    )

    print("\n  Alice == Cara:", alice_cara_match)
    print("  Alice == Bob :", alice_bob_match)

    print(
        "\n  Observation: Identical plaintext blocks produce "
        "identical ciphertext blocks under the same key."
    )

    # ==========================================================
    # PART 3: AES-CBC CHAINING WITH RANDOM IV
    # ==========================================================

    print("\n=== PART 3: AES-CBC Chaining with Random IV ===")

    cbc_results = []

    for run in range(1, 3):

        iv = get_random_bytes(BLOCK_SIZE)

        cbc_cipher = AES.new(
            KEY,
            AES.MODE_CBC,
            iv
        )

        cbc_ct = cbc_cipher.encrypt(
            pad(PLAINTEXT, BLOCK_SIZE)
        )

        cbc_blocks = split_blocks(cbc_ct)

        cbc_results.append({
            "iv": iv,
            "blocks": cbc_blocks
        })

        print(f"\n  Run {run}")
        print(f"    IV: {iv.hex()}")

        print_blocks(
            cbc_blocks,
            "CBC Ciphertext Blocks:"
        )

        print(
            "    Block 1 == Block 2:",
            cbc_blocks[0] == cbc_blocks[1]
        )

    # Compare repeated plaintext blocks in CBC.
    print("\n  CBC Chaining Check:")

    print(
        "    Same plaintext blocks:",
        plaintext_blocks[0] == plaintext_blocks[2]
    )

    print(
        "    Same ciphertext blocks:",
        cbc_results[0]["blocks"][0]
        == cbc_results[0]["blocks"][2]
    )

    # Compare the first ciphertext block across two runs.
    print("\n  Random IV Check:")

    print(
        "    Same IV:",
        cbc_results[0]["iv"] == cbc_results[1]["iv"]
    )

    print(
        "    Same first ciphertext block:",
        cbc_results[0]["blocks"][0]
        == cbc_results[1]["blocks"][0]
    )

if __name__ == "__main__":
    run_experiment()