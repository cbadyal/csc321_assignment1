1 #!pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Random import get_random_bytes
from binascii import unhexlify
import re
# AES-CBC uses 16-byte blocks. Both key and IV must be 16 bytes
key = get_random_bytes(16)
iv = get_random_bytes(16)
def encrypt_data(data):
  # PKCS7 padding ensures the input length is a multiple of 16 bytes (the AES block size)
  padded = pad(data.encode(),16,style='pkcs7')
  cipher = AES.new(key, AES.MODE_CBC,iv)
  enc = cipher.encrypt(padded) #cipher.encrpyt takes in raw binary form with .encode()
  return enc.hex()

def decrypt_data(encryptedParams):
  cipher = AES.new(key, AES.MODE_CBC,iv)
  paddedParams = cipher.decrypt(unhexlify(encryptedParams)) #decrpyt takes in raw binary form with unhelify
  print("Decrypted data:", paddedParams)
  # Check if the decrypted data contains the target string
  if b'admin&password=goBigDawgs123' in unpad(paddedParams,16,style='pkcs7'):
    return 1
  else:
    return 0

try:
  # The attack relies on the fact that we can send 'parsword' which is wrong,
  # but modify the ciphertext to make it decrypt to 'password'
  user = 'admin&parsword=goBigDawgs123' # Note the intentional 'parsword'
  password = 'goBigDawgs123'
  msg = 'logged_username=' + user +'&password=' + password
  print("Original message:", msg)
  print("Message length:", len(msg))

  # This XOR value when applied will change 'r' to 's' because:
  # 1. In CBC mode, each decrypted block is XORed with the previous ciphertext block
  # 2. If we XOR the ciphertext with (r⊕s), during decryption this will:
  # - First decrypt the modified ciphertext block
  # - Then XOR with previous block, which includes our injected XOR
  # - The XOR operations will cancel out except for flipping 'r' to 's'
  xor = ord('r') ^ ord('s')
  # Encrypt our message containing 'parsword'
  cipher = encrypt_data(msg)
  print("\nOriginal ciphertext:", cipher)
  # The bit flipping modification:

  # cipher[:16] - Keep first block unchanged
  # cipher[16:18] - These hex chars represent the byte we want to modify
  # cipher[18:] - Keep the rest unchanged
  # The modification works because:
  # 1. In CBC, each plaintext block is XORed with previous ciphertext block
  # 2. By modifying the ciphertext block before where 'r' appears,
  # we affect the XOR operation during decryption of the next block!!!
  # 3. This causes 'r' to become 's' after decryption
  cipher = cipher[:16] + hex(int(cipher[16:18], 16) ^ xor)[2:] + cipher[18:]
  print("Modified ciphertext:", cipher)

  # When this modified ciphertext is decrypted:
  # 1. The decryption process XORs each block with the previous ciphertext block
  # 2. Our modified ciphertext block causes the XOR to flip the bits just right
  # 3. The 'r' in 'parsword' becomes 's', making it 'password'
  # 4. The check for 'admin&password=goBigDawgs123' now succeeds
  result = decrypt_data(cipher)
  print("\nDecryption result:", result)
except Exception as e:
  print(f"An error occurred: {e}")
