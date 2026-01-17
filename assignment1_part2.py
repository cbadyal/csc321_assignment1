
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption



def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding

#helper function to xor individual bytes in the cipher text strings since xor is bitwise operator
def xor_bytes(a, b):
    return bytes([a[i] ^ b[i] for i in range(16)])

def urlEncode(s):
   return s.replace(";", "%3B").replace("=", "%3D")

def submit(user_input):
   url_encoded_input = urlEncode(user_input)
   message = f"userid=456;userdata={url_encoded_input};session-id=31337"
   return CBC_encrypt(message.encode("ascii")) #have to convert back to ascii

def verify(ciphertext):
   cipher = AES.new(key, AES.MODE_CBC, iv)
   padded = cipher.decrypt(ciphertext)
   plaintext = unpad(padded, 16, style="pkcs7")
   if (b";admin=true;" in plaintext):
      return True
   else:
      return False
   

  
def CBC_encrypt(plaintext):
  CBC_output = bytearray()
  cipher = AES.new(key, AES.MODE_ECB) 
  padded_message = pad(plaintext) #starting point
  prev_message = xor_bytes(padded_message[:16], iv)
  prev_message_enc = cipher.encrypt(prev_message)
  CBC_output += prev_message_enc
  for i in range(16, len(padded_message), 16):
    ciphertext = cipher.encrypt(xor_bytes(padded_message[i:i+16], prev_message_enc))
    prev_message_enc = ciphertext
    CBC_output += prev_message_enc
  return bytes(CBC_output)

def bitFlip():
   user_input = "admin/true"
   ciphertext = submit(user_input)
   message = f"userid=456;userdata={urlEncode(user_input)};session-id=31337".encode("ascii")
   # Find position of '/' for bit flipping
   slash_pos = message.index(b'/')#b'/' is bytes
   block_num = slash_pos // 16
   offset = slash_pos % 16
   prev_block_start = (block_num-1) * 16
   flip_idx = prev_block_start + offset
   cipherFlipped = bytearray(ciphertext)
   cipherFlipped[flip_idx] ^= (ord("/") ^ ord("="))

   #decrypt both 
   cipher = AES.new(key, AES.MODE_CBC, iv)
   beforeFlip = unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")
   afterFlip = unpad(cipher.decrypt(bytes(cipherFlipped)), 16, style="pkcs7")
   print("Before flip:", beforeFlip)
   print("After flip:", afterFlip)
   print("Changed byte index: ", flip_idx)

   print("verify(original) ->", verify(ciphertext))
   print("verify(modified) ->", verify(bytes(cipherFlipped))) 
   #also print out the changed position or whatever

key = get_random_bytes(16)
iv = get_random_bytes(16)

bitFlip()
   
'''
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
'''
