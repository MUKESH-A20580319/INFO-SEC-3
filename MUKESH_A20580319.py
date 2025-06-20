#pip install pycryptodome
# remove the comment '#' above if running in colab or any interactive tool
# use pip install pycryptodome in the command line, not the python interpreter not on the py shell
import random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad

# === Shift Cipher ===
def shift_encrypt(text, shift):
    return ''.join(chr((ord(c.upper()) - 65 + shift) % 26 + 65) if c.isalpha() else c for c in text)

def shift_decrypt(ciphertext, shift):
    return shift_encrypt(ciphertext, -shift)

# === Permutation Cipher ===
def permute_encrypt(text, key):
    n = len(key)
    padding = (n - len(text) % n) % n
    text += ' ' * padding
    chunks = [text[i:i+n] for i in range(0, len(text), n)]
    return ''.join(''.join(chunk[i] for i in key) for chunk in chunks), key

def permute_decrypt(ciphertext, key):
    n = len(key)
    inv_key = [0]*n
    for i, k in enumerate(key):
        inv_key[k] = i
    chunks = [ciphertext[i:i+n] for i in range(0, len(ciphertext), n)]
    return ''.join(''.join(chunk[i] for i in inv_key) for chunk in chunks)

# === Rail Fence Cipher ===
def rail_fence_encrypt(text, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(ciphertext, rails):
    fence = [[] for _ in range(rails)]
    pattern = [0] * len(ciphertext)
    rail = 0
    direction = 1
    for i in range(len(ciphertext)):
        pattern[i] = rail
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    index = 0
    for r in range(rails):
        for i in range(len(ciphertext)):
            if pattern[i] == r:
                fence[r].append(ciphertext[index])
                index += 1
    result = ''
    rail_pointer = [0]*rails
    for r in pattern:
        result += fence[r][rail_pointer[r]]
        rail_pointer[r] += 1
    return result

# === Double Permutation Transposition ===
def double_permutation_encrypt(text, key1, key2):
    step1, _ = permute_encrypt(text, key1)
    step2, _ = permute_encrypt(step1, key2)
    return step2

def double_permutation_decrypt(cipher, key1, key2):
    step1 = permute_decrypt(cipher, key2)
    return permute_decrypt(step1, key1)

# === Vigenere Cipher ===
def vigenere_encrypt(text, key):
    text, key = text.upper(), key.upper()
    return ''.join(chr((ord(c) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65) if c.isalpha() else c for i, c in enumerate(text))

def vigenere_decrypt(ciphertext, key):
    ciphertext, key = ciphertext.upper(), key.upper()
    return ''.join(chr((ord(c) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65) if c.isalpha() else c for i, c in enumerate(ciphertext))

# === Block Ciphers (AES/DES/3DES) ===
def get_cipher(method, key, mode):
    key = key.ljust(24)[:24].encode()
    iv = b'12345678abcdefgh'
    if method == 'AES':
        if mode == AES.MODE_ECB:
            return AES.new(key[:16], mode)
        return AES.new(key[:16], mode, iv[:16])
    elif method == 'DES':
        if mode == DES.MODE_ECB:
            return DES.new(key[:8], mode)
        return DES.new(key[:8], mode, iv[:8])
    elif method == '3DES':
        if mode == DES3.MODE_ECB:
            return DES3.new(key, mode)
        return DES3.new(key, mode, iv[:8])

def block_encrypt(method, text, key, mode_str):
    modes = {'1': AES.MODE_ECB, '2': AES.MODE_CBC, '3': AES.MODE_CFB, '4': AES.MODE_OFB}
    cipher = get_cipher(method, key, modes[mode_str])
    return b64encode(cipher.encrypt(pad(text.encode(), cipher.block_size))).decode()

def block_decrypt(method, ciphertext, key, mode_str):
    modes = {'1': AES.MODE_ECB, '2': AES.MODE_CBC, '3': AES.MODE_CFB, '4': AES.MODE_OFB}
    cipher = get_cipher(method, key, modes[mode_str])
    return unpad(cipher.decrypt(b64decode(ciphertext)), cipher.block_size).decode()

# === Test All Block Cipher Combinations ===
def test_all_cipher_combinations():
    print("\n Test All Combinations: AES, DES, 3DES × ECB, CBC, CFB, OFB")
    text = input("Enter plaintext to encrypt: ")
    key = input("Enter encryption key (will be padded to 24 chars): ")

    algorithms = {'AES': AES, 'DES': DES, '3DES': DES3}
    modes = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB, 'OFB': AES.MODE_OFB}

    for algo_name, algo in algorithms.items():
        for mode_name, mode in modes.items():
            try:
                cipher = get_cipher(algo_name, key, mode)
                block_size = cipher.block_size
                padded = pad(text.encode(), block_size)
                encrypted = cipher.encrypt(padded)
                encoded = b64encode(encrypted).decode()

                decipher = get_cipher(algo_name, key, mode)
                decrypted = unpad(decipher.decrypt(b64decode(encoded)), block_size).decode()

                print(f"\n {algo_name} + {mode_name}")
                print(f"   Encrypted: {encoded}")
                print(f"   Decrypted: {decrypted}")
            except Exception as e:
                print(f"\n {algo_name} + {mode_name} failed: {e}")

# === Main Menu ===
def main():
    print("==== Encryption Tool ====")
    print("1. Shift Cipher")
    print("2. Permutation Cipher")
    print("3. Single Transposition (Rail Fence)")
    print("4. Double Permutation Transposition")
    print("5. Vigenère Cipher")
    print("6. AES / DES / 3DES")
    print("7. Test All Block Cipher Combinations")

    choice = input("Choose a method (1-7): ")

    if choice == '1':
        text = input("Enter text to encrypt: ")
        shift = int(input("Enter shift: "))
        ciphertext = shift_encrypt(text, shift)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            shift_d = int(input("Enter decryption shift: "))
            print("Decrypted:", shift_decrypt(ciphertext, shift_d))

    elif choice == '2':
        text = input("Enter text to encrypt: ")
        key_input = input("Enter permutation key (e.g. 2,0,1): ")
        key = list(map(int, key_input.strip().split(',')))
        ciphertext, _ = permute_encrypt(text, key)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            key_d = list(map(int, input("Enter decryption key: ").strip().split(',')))
            print("Decrypted:", permute_decrypt(ciphertext, key_d))

    elif choice == '3':
        text = input("Enter text to encrypt: ")
        rails = int(input("Enter number of rails: "))
        ciphertext = rail_fence_encrypt(text, rails)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            rails_d = int(input("Enter rails used for decryption: "))
            print("Decrypted:", rail_fence_decrypt(ciphertext, rails_d))

    elif choice == '4':
        text = input("Enter text to encrypt: ")
        key1 = list(map(int, input("Enter first permutation key: ").strip().split(',')))
        key2 = list(map(int, input("Enter second permutation key: ").strip().split(',')))
        ciphertext = double_permutation_encrypt(text, key1, key2)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            key1_d = list(map(int, input("Enter first decryption key: ").strip().split(',')))
            key2_d = list(map(int, input("Enter second decryption key: ").strip().split(',')))
            print("Decrypted:", double_permutation_decrypt(ciphertext, key1_d, key2_d))

    elif choice == '5':
        text = input("Enter text to encrypt: ")
        key = input("Enter Vigenère key: ")
        ciphertext = vigenere_encrypt(text, key)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            key_d = input("Enter decryption key: ")
            print("Decrypted:", vigenere_decrypt(ciphertext, key_d))

    elif choice == '6':
        text = input("Enter text to encrypt: ")
        print("1. AES\n2. DES\n3. 3DES")
        algo_choice = input("Choose algorithm (1-3): ")
        method = {'1': 'AES', '2': 'DES', '3': '3DES'}.get(algo_choice, 'AES')

        print("1. ECB\n2. CBC\n3. CFB\n4. OFB")
        mode_choice = input("Choose mode (1-4): ")

        key = input("Enter encryption key (padded to 24 chars): ")
        ciphertext = block_encrypt(method, text, key, mode_choice)
        print("Encrypted:", ciphertext)
        if input("Decrypt? (y/n): ").lower() == 'y':
            key_d = input("Enter decryption key (same padding): ")
            print("Decrypted:", block_decrypt(method, ciphertext, key_d, mode_choice))

    elif choice == '7':
        test_all_cipher_combinations()

    else:
        print("Invalid option.")

# Run the tool
main()
