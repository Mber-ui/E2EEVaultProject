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

GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID_HERE"
GOOGLE_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "openid", "https://www.googleapis.com/auth/userinfo.email"],
    redirect_uri="http://localhost:5000/callback"
)

VAULT_ROOT = "static/vault"

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
    return render_template("index.html")

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

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    if "email" not in session:
        return redirect("/")

    file = request.files["file"]
    data = file.read()

    user_dir = ensure_user_vault()

    # AES key must be generated separately
    aes_key = generate_aes_key()
    nonce, ciphertext = aes_encrypt(aes_key, data)

    # Load RSA public key
    public_pem = read_bytes(os.path.join(user_dir, "public_key.pem"))
    wrapped_key = rsa_wrap_aes_key(public_pem, aes_key)

    meta = {
        "filename": file.filename,
        "nonce": nonce.hex(),
        "wrapped_key": wrapped_key.hex()
    }

    encrypted_path = os.path.join(user_dir, file.filename + ".enc")
    metadata_path = encrypted_path + ".json"

    write_bytes(encrypted_path, ciphertext)
    write_json(metadata_path, meta)

    return "File encrypted successfully!"

# ---------------- DECRYPT ---------------- #

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    if "email" not in session:
        return redirect("/")

    file = request.files["file"]
    ciphertext = file.read()

    user_dir = ensure_user_vault()

    metadata = read_json(os.path.join(user_dir, file.filename + ".json"))
    nonce = bytes.fromhex(metadata["nonce"])
    wrapped_key = bytes.fromhex(metadata["wrapped_key"])

    private_pem = read_bytes(os.path.join(user_dir, "private_key.pem"))
    aes_key = rsa_unwrap_aes_key(private_pem, wrapped_key)

    plaintext = aes_decrypt(aes_key, nonce, ciphertext)

    output_path = os.path.join(user_dir, "DECRYPTED_" + metadata["filename"])
    write_bytes(output_path, plaintext)

    return send_file(output_path, as_attachment=True)

# ---------------------------- RUN ---------------------------- #

if __name__ == "__main__":
    app.run(debug=True)

