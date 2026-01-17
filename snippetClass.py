1 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding

# Original message
message = b'userid=456;userdata=admin/true;session-id=31337'
print(f"Plaintext before byte-flip: {message.decode('ascii')}")

# Generate key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)
# Find position of '/'
slash_pos = message.index(b'/')#b'/' is bytes
# Encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
padded_message = pad(message)
ciphertext = cipher.encrypt(padded_message)
# Show ciphertext before the flip
print("\nBefore admin/true - Ciphertext (hex):")
ciphertext_hex = ''.join([hex(x)[2:].zfill(2) for x in ciphertext])
print(ciphertext_hex)
# Calculate which block needs modification
block_num = (slash_pos // 16) # Block containing the target byte
pos_in_prev_block = slash_pos % 16
prev_block_start = (block_num - 1) * 16 # Start of previous block
# XOR the byte in previous block
modified_ciphertext = bytearray(ciphertext)
modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('/') ^ ord('='))
# Show ciphertext after the flip
print("\nAfter admin=true - Ciphertext (hex):")
modified_hex = ''.join([hex(x)[2:].zfill(2) for x in modified_ciphertext])
print(modified_hex)
# Show the changed byte
print(f"\nChanged byte position: {prev_block_start + pos_in_prev_block}")
print(f"Original byte: {hex(ciphertext[prev_block_start + pos_in_prev_block])[2:].zfill(2)}")
print(f"Modified byte: {hex(modified_ciphertext[prev_block_start + pos_in_prev_block])[2:].zfill(2)}")
# Decrypt modified ciphertext
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(bytes(modified_ciphertext))
print(f"\nPlaintext after byte-flip: userid=456;userdata=admin=true;session-id=31337")
