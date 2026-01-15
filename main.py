import os
import hmac
import hashlib
import struct
import base58
from mnemonic import Mnemonic
from nacl import signing
from solders.keypair import Keypair
from solana.rpc.api import Client

WALLET_FILE = "solana_wallets.txt"
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"

ED25519_CURVE = b"ed25519 seed"
SOLANA_PATH = [
    44 | 0x80000000,
    501 | 0x80000000,
    0 | 0x80000000,
    0 | 0x80000000
]

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


def derive_ed25519_master_key(seed):
    I = hmac_sha512(ED25519_CURVE, seed)
    return I[:32], I[32:]

def derive_child_key(parent_key, parent_chain, index):
    data = b"\x00" + parent_key + struct.pack(">L", index)
    I = hmac_sha512(parent_chain, data)
    return I[:32], I[32:]

def derive_path(seed, path):
    key, chain = derive_ed25519_master_key(seed)
    for index in path:
        key, chain = derive_child_key(key, chain, index)
    return key

def generate_wallet():
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128)

    seed = mnemo.to_seed(mnemonic)
    derived_key = derive_path(seed, SOLANA_PATH)

    signing_key = signing.SigningKey(derived_key)
    keypair = Keypair.from_seed(bytes(signing_key._seed))

    address = str(keypair.pubkey())

    #(64 bytes)
    private_key_base58 = base58.b58encode(bytes(keypair.to_bytes())).decode()

    return address, private_key_base58, mnemonic

def create_wallets():
    try:
        count = int(input("Сколько кошельков создать (1–500)? ").strip())
        if not 1 <= count <= 500:
            print("Неверное количество")
            return
    except ValueError:
        print("Введите число")
        return

    with open(WALLET_FILE, "a", encoding="utf-8") as f:
        for _ in range(count):
            addr, pk, mn = generate_wallet()
            f.write(
                f"ADDRESS: {addr}\n"
                f"PRIVATE_KEY: {pk}\n"
                f"MNEMONIC: {mn}\n"
                f"{'-'*60}\n"
            )

    print(f"\n Создано {count} кошельков")
    print(f"Сохранено в {WALLET_FILE}\n")

def check_balances():
    rpc = input(f"RPC (Enter = {DEFAULT_RPC}): ").strip() or DEFAULT_RPC
    client = Client(rpc)

    if not os.path.exists(WALLET_FILE):
        print("Файл с кошельками не найден")
        return

    with open(WALLET_FILE, "r", encoding="utf-8") as f:
        addresses = [
            line.split(":")[1].strip()
            for line in f if line.startswith("ADDRESS")
        ]

    print("\nПроверка балансов:\n")

    for addr in addresses:
        try:
            balance = client.get_balance(addr).value / 1_000_000_000
            print(f"{addr} | {balance:.6f} SOL")
        except Exception:
            print(f"{addr} | ошибка RPC")

    print("\n✔ Готово\n")

def main():
    while True:
        print("===== Sol Wallet Gen =====")
        print("1. Создать кошельки (mnemonic + private key)")
        print("2. Проверить балансы")
        print("3. Выход")

        choice = input("Выбор: ").strip()

        if choice == "1":
            create_wallets()
        elif choice == "2":
            check_balances()
        elif choice == "3":
            print("Выход...")
            break
        else:
            print("Неверный пункт\n")


if __name__ == "__main__":
    main()