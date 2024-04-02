import hashlib


def generate_aes_key(input1, input2, input3):
    concatenated_inputs = f"{input1}{input2}{input3}"
    hashed_input = hashlib.sha256(concatenated_inputs.encode()).digest()
    aes_key = hashed_input[:32]
    return aes_key


def main():
    input1 = input("Enter input 1: ")
    input2 = input("Enter input 2: ")
    input3 = input("Enter input 3: ")
    aes_key = generate_aes_key(input1, input2, input3)
    aes_key_hex = aes_key.hex()


if __name__ == "__main__":
    main()
