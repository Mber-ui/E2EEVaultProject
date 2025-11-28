import os
from flask import Flask, render_template, request, redirect, session, send_file
from flask_session import Session

from crypto_core import (
    generate_rsa_key_pair,
    load_private_key,
    load_public_key,
    rsa_wrap_aes_key,
    rsa_unwrap_aes_key,
    aes_encrypt,
    aes_decrypt,
    generate_aes_key
)

from file_handler import write_bytes, read_bytes, write_json, read_json

from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests

# ---------------------------- CONFIG ---------------------------- #

app = Flask(__name__)
app.secret_key = "super-secret-key"

app.config["SESSION_TYPE"] = "filesystem"
Session(app)

GOOGLE_CLIENT_ID = YOUR_GOOGLEID
GOOGLE_CLIENT_SECRET = YOUR_SECRETID

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "openid", "https://www.googleapis.com/auth/userinfo.email"],
    redirect_uri="http://localhost:5000/callback"
)

VAULT_ROOT = "vault"

# ---------------------------- HELPERS ---------------------------- #

def ensure_user_vault():
    """Creates personal vault folder and RSA keys for new users."""
    email = session.get("email")
    user_dir = os.path.join(VAULT_ROOT, email)

    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

        private_pem, public_pem = generate_rsa_key_pair()

        # save keys
        write_bytes(os.path.join(user_dir, "private_key.pem"), private_pem)
        write_bytes(os.path.join(user_dir, "public_key.pem"), public_pem)

    return user_dir

# ---------------------------- ROUTES ---------------------------- #

@app.route("/")
def index():
    message = request.args.get("msg", "")

    if "email" not in session:
        return render_template("index.html", files=[], message=message)

    user_dir = ensure_user_vault()

    encrypted_files = [
        f for f in os.listdir(user_dir)
        if f.endswith(".enc")
    ]

    return render_template("index.html", files=encrypted_files, message=message)


# ---------------- GOOGLE LOGIN ---------------- #

@app.route("/login")
def login():
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    request_session = google.auth.transport.requests.Request()

    id_info = id_token.verify_oauth2_token(
        creds.id_token, request_session, GOOGLE_CLIENT_ID
    )

    session["email"] = id_info["email"]
    ensure_user_vault()
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- ENCRYPT ---------------- #

from flask import flash
from werkzeug.utils import secure_filename

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    if "email" not in session:
        return redirect("/")

    user_dir = ensure_user_vault()

    uploaded = request.files["file"]
    filename = secure_filename(uploaded.filename)

    # Save original file temporarily
    file_path = os.path.join(user_dir, filename)
    uploaded.save(file_path)

    data = read_bytes(file_path)

    # Create AES key & encrypt
    aes_key = generate_aes_key()
    nonce, ciphertext = aes_encrypt(aes_key, data)

    # Wrap AES key with RSA public key
    public_key_pem = read_bytes(os.path.join(user_dir, "public_key.pem"))
    wrapped_key = rsa_wrap_aes_key(public_key_pem, aes_key)

    # Save encrypted file
    enc_path = file_path + ".enc"
    write_bytes(enc_path, ciphertext)

    # Save metadata
    metadata = {
        "filename": filename,
        "nonce": nonce.hex(),
        "wrapped_key": wrapped_key.hex()
    }

    write_json(enc_path + ".json", metadata)

    flash(f"Encrypted: {filename}")

    return redirect("/vault")


# ---------------- DECRYPT ---------------- #

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    if "email" not in session:
        return redirect("/")

    user_dir = ensure_user_vault()

    enc_filename = request.form.get("file")
    enc_path = os.path.join(user_dir, enc_filename)

    ciphertext = read_bytes(enc_path)
    metadata = read_json(enc_path + ".json")

    nonce = bytes.fromhex(metadata["nonce"])
    wrapped_key = bytes.fromhex(metadata["wrapped_key"])

    private_pem = read_bytes(os.path.join(user_dir, "private_key.pem"))
    aes_key = rsa_unwrap_aes_key(private_pem, wrapped_key)

    plaintext = aes_decrypt(aes_key, nonce, ciphertext)

    output_path = os.path.join(user_dir, "DECRYPTED_" + metadata["filename"])
    write_bytes(output_path, plaintext)

    flash(f"Decrypted: {metadata['filename']}")

    return redirect("/vault")


# ---------------- VAULT (FILE LISTING) ---------------- #

@app.route("/vault")
def vault():
    if "email" not in session:
        return redirect("/")

    user_dir = ensure_user_vault()

    # Gather all encrypted files
    encrypted_files = [
        f for f in os.listdir(user_dir)
        if f.endswith(".enc")
    ]

    return render_template("vault.html", encrypted_files=encrypted_files)


# ---------------------------- RUN ---------------------------- #

if __name__ == "__main__":
    app.run(debug=True)


