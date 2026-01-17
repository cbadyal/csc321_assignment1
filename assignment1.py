from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption

file1 = "./mustang.bmp"
file2 = "./cp-logo.bmp"

def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding

#helper function to xor individual bytes in the cipher text strings since xor is bitwise operator
def xor_bytes(a, b):
    return bytes([a[i] ^ b[i] for i in range(16)])

def readBMP(filename):
   try:
      with open(filename, 'rb') as f:
         bmp_bytes = f.read()
      return bmp_bytes #data from file as a bytes object
   except:
      print("Error opening/reading file")
      return None
  
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

def save_bmp(res_bytes, res_filename): #res_bytes should be header + encrypted bytes
   try:
    with open(res_filename, "wb") as f:
        f.write(res_bytes)
        print(f"successfully saved new bmp file: {res_filename}")
   except:
      print("error saving bmp file")

#for file1
file1_bytes = readBMP(file1)
file1_header = file1_bytes[:54] #try 138 if this doesn't work
file1_plaintext = file1_bytes[54:]

#for file2
file2_bytes = readBMP(file2)
file2_header = file2_bytes[:54]
file2_plaintext = file2_bytes[54:]


# Generate key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)

#save file 1 and file 2 as bmp encrypted
file1_enc = CBC_encrypt(file1_plaintext)
file1_res = file1_header + file1_enc
save_bmp(file1_res, "mustangEnc.bmp") 

file2_enc = CBC_encrypt(file2_plaintext)
file2_res = file2_header + file2_enc
save_bmp(file2_res, "cp-logoEnc.bmp")

#decrypt file 2 to check it's correct
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_padded = cipher.decrypt(file2_enc)     
decrypted_body = unpad(decrypted_padded, 16)    
# Re-append the original header to make a valid BMP 
file2_dec = file2_header + decrypted_body
save_bmp(file2_dec, "cp-logoDec.bmp")
