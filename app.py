from flask import Flask, request, render_template, flash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from twilio.rest import Client
import os
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load Twilio credentials from environment variables
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', 'AYV8NsMDSAw6AMRbjq5qtVhJpiyig6erJH')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '6660839698d513898ebe2e7f6c739b7a')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', '+17249481504')

# Print credentials to verify 
print(f'TWILIO_ACCOUNT_SID: "{TWILIO_ACCOUNT_SID}"')
print(f'TWILIO_AUTH_TOKEN: "{TWILIO_AUTH_TOKEN}"')
print(f'TWILIO_PHONE_NUMBER: "{TWILIO_PHONE_NUMBER}"')

client = Client(TWILIO_ACCOUNT_SID.strip(), TWILIO_AUTH_TOKEN.strip())

# Generate a key for encryption
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt a message
def encrypt_message(message, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(salt + iv + ct).decode()

# Decrypt a message
def decrypt_message(encrypted_message, password):
    decoded_data = base64.urlsafe_b64decode(encrypted_message.encode())
    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    ct = decoded_data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    return message.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = None
    decrypted_message = None

    if request.method == 'POST':
        if 'encrypt' in request.form:
            phone_number = request.form['phone_number']
            message = request.form['message']
            password = os.urandom(16).hex()  # Generate a random key (password)
            encrypted_message = encrypt_message(message, password)
            try:
                client.messages.create(
                    body=f'Your encrypted message is: {encrypted_message}\nYour decryption key is: {password}',
                    from_=TWILIO_PHONE_NUMBER,
                    to=phone_number
                )
                flash('Encrypted message and key sent via SMS', 'success')
            except Exception as e:
                flash(f'Failed to send SMS: {e}', 'danger')
        
        elif 'decrypt' in request.form:
            encrypted_message = request.form['encrypted_message']
            password = request.form['password']
            try:
                decrypted_message = decrypt_message(encrypted_message, password)
                flash('Message decrypted successfully', 'success')
            except Exception as e:
                flash(f'Failed to decrypt message: {e}', 'danger')

    return render_template('index.html', encrypted_message=encrypted_message, decrypted_message=decrypted_message)

if __name__ == '__main__':
    app.run(debug=True)
