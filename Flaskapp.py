import os
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from crypto_core import generate_rsa_key_pair, rsa_wrap_aes_key, rsa_unwrap_aes_key, encrypt_file, decrypt_file
from file_handler import write_file_data, read_file_data, save_rsa_keys
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

VAULT_DIR = "vault"
if not os.path.exists(VAULT_DIR):
    os.makedirs(VAULT_DIR)

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Upload and encrypt file
@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        flash("No file selected")
        return redirect(url_for('index'))

    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(VAULT_DIR, filename)
    uploaded_file.save(filepath)

    # Encrypt file with AES and wrap key with RSA
    aes_key = os.urandom(32)
    encrypted_file_path = filepath + ".enc"
    encrypt_file(filepath, encrypted_file_path, aes_key)

    # Save AES key wrapped with RSA
    pub_path = os.path.join(VAULT_DIR, "public_key.pem")
    if not os.path.exists(pub_path):
        flash("No public key found. Generate RSA key pair first.")
        return redirect(url_for('index'))

    public_pem = read_file_data(pub_path)
    wrapped_aes = rsa_wrap_aes_key(public_pem, aes_key)
    write_file_data(os.path.join(VAULT_DIR, filename + ".key"), wrapped_aes)

    flash(f"File {filename} encrypted successfully!")
    return redirect(url_for('index'))

# Decrypt file
@app.route('/decrypt', methods=['POST'])
def decrypt():
    filename = request.form.get('filename')
    if not filename:
        flash("No file selected")
        return redirect(url_for('index'))

    encrypted_file_path = os.path.join(VAULT_DIR, filename)
    key_path = encrypted_file_path.replace(".enc", ".key")

    priv_path = os.path.join(VAULT_DIR, "private_key.enc")
    salt_path = os.path.join(VAULT_DIR, "salt.bin")
    nonce_path = os.path.join(VAULT_DIR, "nonce.bin")

    if not os.path.exists(priv_path):
        flash("Private key missing.")
        return redirect(url_for('index'))

    password = request.form.get('password')
    if not password:
        flash("Password required for private key")
        return redirect(url_for('index'))

    from crypto_core import load_private_key_from_vault
    enc_priv = read_file_data(priv_path)
    salt = read_file_data(salt_path)
    nonce = read_file_data(nonce_path)
    private_key_obj = load_private_key_from_vault(enc_priv, salt, nonce, password.encode())

    wrapped_aes = read_file_data(key_path)
    aes_key = rsa_unwrap_aes_key(wrapped_aes, private_key_obj)

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    decrypt_file(encrypted_file_path, decrypted_file_path, aes_key)

    flash(f"File decrypted: {decrypted_file_path}")
    return send_file(decrypted_file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
