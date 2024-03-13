from django.shortcuts import render
from django.http import HttpResponse
from Crypto import Random
from Crypto.Cipher import AES
import os

# Defined Functions

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

# View functions

def index(request):
    return render(request, 'crypto_app/index.html')

def encrypt_file(request):
    if request.method == 'POST':
        # Get the uploaded file
        uploaded_file = request.FILES['file']
        
        # Create an instance of the Encryptor class
        key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
        enc = Encryptor(key)
        
        # Encrypt the file
        encrypted_data = enc.encrypt(uploaded_file.read(), key)
        
        # Return the encrypted data as a file for download
        response = HttpResponse(encrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename="{}.enc"'.format(uploaded_file.name)
        
        return response
    
    return render(request, 'crypto_app/encrypt.html')

def decrypt_file(request):
    if request.method == 'POST':
        # Get the uploaded file
        uploaded_file = request.FILES['file']
        
        # Create an instance of the Encryptor class
        key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
        enc = Encryptor(key)
        
        # Decrypt the file
        decrypted_data = enc.decrypt(uploaded_file.read(), key)
        
        # Return the decrypted data as a file for download
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(uploaded_file.name[:-4])
        
        return response
    
    return render(request, 'crypto_app/decrypt.html')