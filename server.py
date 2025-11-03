"""
MIT License

Copyright (c) 2025 bistoyek21 R.I.C.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import os
import re
import time
import json
import shutil
import secrets
import zipfile
import hashlib
from flask import Flask, request, Response
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path
from functools import wraps
import tempfile
import random
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Node:
    __slots__ = ('serial', 'par', 'branches')
    def __init__(self, serial, par="-"):
        self.serial = serial
        self.par = par
        self.branches = set()

# Global state
bots = []
backups = []
key = get_random_bytes(32)
iv = get_random_bytes(16)
admin_key_hash = "b18b078c272d0ac43301ec84cea2f61b0c1fb1b961de7d6aa5ced573cb9132aa"

def gen_token():
    """Generate a secure random token"""
    return secrets.token_hex(32)

def sha256(data: str) -> str:
    """Compute SHA-256 hash of a string"""
    return hashlib.sha256(data.encode()).hexdigest()

def aes256_encrypt(plaintext: str) -> bytes:
    """Encrypt text using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = AES.block_size - len(plaintext.encode()) % AES.block_size
    padded = plaintext.encode() + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded)

def aes256_decrypt(ciphertext: bytes) -> str:
    """Decrypt text using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode()

def create_zip(zip_path: Path, source_dir: Path):
    """
    Create a zip archive from a directory
    - zip_path: Path to output zip file
    - source_dir: Directory to zip
    """
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in source_dir.glob('**/*'):
            if file.is_file():
                arcname = file.relative_to(source_dir)
                zipf.write(file, arcname)

def extract_zip(zip_path: Path, target_dir: Path):
    """
    Extract a zip archive to a directory
    - zip_path: Path to input zip file
    - target_dir: Directory to extract to
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        # Validate zip contents before extraction
        for name in zipf.namelist():
            if name.startswith('/') or '..' in name:
                raise ValueError("Invalid path in zip file")
        zipf.extractall(target_dir)

def global_exception_handler(f):
    """Global error handler for all endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {f.__name__}: {str(e)}")
            return Response(
                json.dumps({"status": "error", "message": "Internal server error"}),
                status=500,
                mimetype="application/json"
            )
    return decorated_function

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

@app.errorhandler(413)
def request_entity_too_large(error):
    return Response(
        json.dumps({"status": "error", "message": "File exceeds size limit"}),
        status=413,
        mimetype="application/json"
    )

# ====================== Helper Functions ======================
def validate_admin():
    """Validate admin key"""
    admin_key = request.args.get("admin_key")
    return admin_key and sha256(admin_key) == admin_key_hash

def validate_bot_name(bot):
    """Validate bot name format"""
    return bot and re.match(r"^[a-zA-Z0-9_-]{3,50}$", bot)

def find_bot_index(bot):
    """Find index of bot in global lists"""
    try:
        return bots.index(bot)
    except ValueError:
        return -1

def get_backup_dir(bot, serial):
    """Get Path object for backup directory"""
    return Path("backups") / bot / serial

# ====================== Admin Endpoints ======================
# curl --noproxy "*" -X POST "http://URL/StrikeForce/admin/add_bot?admin_key=ADMIN_KEY&bot=BOT_NAME"
@app.route("/StrikeForce/admin/add_bot", methods=["POST"])
@global_exception_handler
def admin_add_bot():
    """Add a new bot"""
    if not validate_admin():
        return Response(
            json.dumps({"status": "error", "message": "Unauthorized"}),
            status=401,
            mimetype="application/json"
        )
    
    bot = request.args.get("bot")
    if not validate_bot_name(bot):
        return Response(
            json.dumps({"status": "error", "message": "Invalid bot name format"}),
            status=400,
            mimetype="application/json"
        )
    
    if bot in bots:
        return Response(
            json.dumps({"status": "error", "message": "Bot already exists"}),
            status=400,
            mimetype="application/json"
        )
    
    bots.append(bot)
    backups.append([])
    bot_dir = Path("backups") / bot
    bot_dir.mkdir(parents=True, exist_ok=True)
    
    logging.info(f"Added new bot: {bot}")
    return Response(
        json.dumps({"status": "success", "message": "Bot added"}),
        mimetype="application/json"
    )

# curl --noproxy "*" -X POST "http://URL/StrikeForce/admin/delete_bot?admin_key=ADMIN_KEY&bot=BOT_NAME"
@app.route("/StrikeForce/admin/delete_bot", methods=["POST"])
@global_exception_handler
def admin_delete_bot():
    """Delete a bot and all its backups"""
    if not validate_admin():
        return Response(
            json.dumps({"status": "error", "message": "Unauthorized"}),
            status=401,
            mimetype="application/json"
        )
    
    bot = request.args.get("bot")
    if not bot:
        return Response(
            json.dumps({"status": "error", "message": "Missing bot name"}),
            status=400,
            mimetype="application/json"
        )
    
    bot_index = find_bot_index(bot)
    if bot_index == -1:
        return Response(
            json.dumps({"status": "error", "message": "Bot not found"}),
            status=404,
            mimetype="application/json"
        )
    
    # Delete from filesystem
    bot_dir = Path("backups") / bot
    if bot_dir.exists():
        try:
            shutil.rmtree(bot_dir)
        except Exception as e:
            logging.error(f"Failed to delete bot directory: {str(e)}")
            return Response(
                json.dumps({"status": "error", "message": "Failed to delete bot directory"}),
                status=500,
                mimetype="application/json"
            )
    
    # Delete from memory
    del bots[bot_index]
    del backups[bot_index]
    
    logging.info(f"Deleted bot: {bot}")
    return Response(
        json.dumps({"status": "success", "message": "Bot deleted"}),
        mimetype="application/json"
    )

# curl --noproxy "*" -X POST -F "file=@/path/to/backup.zip" "http://URL/StrikeForce/admin/add_backup?admin_key=ADMIN_KEY&bot=BOT_NAME"
@app.route("/StrikeForce/admin/add_backup", methods=["POST"])
@global_exception_handler
def admin_add_backup():
    """Add a backup for a bot"""
    if not validate_admin():
        return Response(
            json.dumps({"status": "error", "message": "Unauthorized"}),
            status=401,
            mimetype="application/json"
        )
    
    bot = request.args.get("bot")
    bot_index = find_bot_index(bot)
    if bot_index == -1:
        return Response(
            json.dumps({"status": "error", "message": "Bot not found"}),
            status=404,
            mimetype="application/json"
        )
    
    if 'file' not in request.files:
        return Response(
            json.dumps({"status": "error", "message": "Missing backup file"}),
            status=400,
            mimetype="application/json"
        )
    
    serial = gen_token()
    backup_dir = get_backup_dir(bot, serial)
    
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_zip:
            uploaded_file = request.files['file']
            uploaded_file.save(tmp_zip.name)
            
            # Extract to backup directory
            backup_dir.mkdir(parents=True, exist_ok=True)
            extract_zip(Path(tmp_zip.name), backup_dir)
        
        # Clean up temp file
        os.unlink(tmp_zip.name)
        
        # Create metadata
        password = gen_token()
        metadata = f"{bot},{serial},{int(time.time())},{password},-"
        encrypted = aes256_encrypt(metadata)
        (backup_dir / "metadata.enc").write_bytes(encrypted)
        
    except Exception as e:
        # Cleanup on error
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        logging.error(f"Backup creation failed: {str(e)}")
        return Response(
            json.dumps({"status": "error", "message": "Backup processing failed"}),
            status=500,
            mimetype="application/json"
        )
    
    # Add to backups tree
    backups[bot_index].append(Node(serial))
    logging.info(f"Added backup {serial} for bot {bot}")
    return Response(
        json.dumps({"status": "success", "message": "Backup registered"}),
        mimetype="application/json"
    )

# curl --noproxy "*" -X POST "http://URL/StrikeForce/admin/delete_backup?admin_key=ADMIN_KEY&bot=BOT_NAME&serial=SERIAL"
@app.route("/StrikeForce/admin/delete_backup", methods=["POST"])
@global_exception_handler
def admin_delete_backup():
    """Delete a specific backup"""
    if not validate_admin():
        return Response(
            json.dumps({"status": "error", "message": "Unauthorized"}),
            status=401,
            mimetype="application/json"
        )
    
    bot = request.args.get("bot")
    serial = request.args.get("serial")
    if not bot or not serial:
        return Response(
            json.dumps({"status": "error", "message": "Missing parameters"}),
            status=400,
            mimetype="application/json"
        )
    
    bot_index = find_bot_index(bot)
    if bot_index == -1:
        return Response(
            json.dumps({"status": "error", "message": "Bot not found"}),
            status=404,
            mimetype="application/json"
        )
    
    # Find and remove from tree
    found = False
    for i, node in enumerate(backups[bot_index]):
        if node.serial == serial:
            del backups[bot_index][i]
            found = True
            break
    
    # Remove from filesystem
    backup_path = get_backup_dir(bot, serial)
    if backup_path.exists():
        try:
            shutil.rmtree(backup_path)
        except Exception as e:
            logging.error(f"Failed to delete backup: {str(e)}")
            return Response(
                json.dumps({"status": "error", "message": "Failed to delete backup directory"}),
                status=500,
                mimetype="application/json"
            )
    
    if found:
        logging.info(f"Deleted backup {serial} for bot {bot}")
        return Response(
            json.dumps({"status": "success", "message": "Backup deleted"}),
            mimetype="application/json"
        )
    else:
        return Response(
            json.dumps({"status": "error", "message": "Backup not found"}),
            status=404,
            mimetype="application/json"
        )

# curl --noproxy "*" "http://URL/StrikeForce/admin/get_crypto?admin_key=ADMIN_KEY"
@app.route("/StrikeForce/admin/get_crypto", methods=["GET"])
@global_exception_handler
def admin_get_crypto():
    """Get encryption keys"""
    if not validate_admin():
        return Response(
            json.dumps({"status": "error", "message": "Unauthorized"}),
            status=401,
            mimetype="application/json"
        )
    
    return Response(
        json.dumps({
            "status": "success",
            "key": key.hex(),
            "iv": iv.hex()
        }),
        mimetype="application/json"
    )

# ====================== API Endpoints ======================
# curl --noproxy "*" -o backup.zip "http://URL/StrikeForce/api/request_backup?bot=BOT_NAME"
@app.route("/StrikeForce/api/request_backup", methods=["GET"])
@global_exception_handler
def request_backup():
    """Request a backup for a bot"""
    bot = request.args.get("bot")
    if bot not in bots:
        return Response(
            json.dumps({"status": "error", "message": "Bot not found"}),
            status=404,
            mimetype="application/json"
        )
    
    bot_index = bots.index(bot)
    if not backups[bot_index]:
        return Response(
            json.dumps({"status": "error", "message": "No backups available"}),
            status=404,
            mimetype="application/json"
        )
    
    # Select random backup
    selected = random.choice(backups[bot_index])
    epoch = int(time.time())
    password = gen_token()
    backup_dir = get_backup_dir(bot, selected.serial)
    metadata = f"{bot},{selected.serial},{epoch},{password},{selected.par}"
    
    try:
        # Update metadata
        encrypted = aes256_encrypt(metadata)
        (backup_dir / "metadata.enc").write_bytes(encrypted)
        
        # Create zip in memory
        with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
            create_zip(Path(tmp_zip.name), backup_dir)
            zip_content = Path(tmp_zip.name).read_bytes()
        
        # Update branches
        password_hash = sha256(password)
        selected.branches.add((epoch, password_hash))
        
        logging.info(f"Provided backup {selected.serial} for bot {bot}")
        return Response(
            zip_content,
            mimetype="application/zip",
            headers={"Content-Disposition": f"attachment; filename={bot}_backup.zip"}
        )
    
    except Exception as e:
        logging.error(f"Backup request failed: {str(e)}")
        return Response(
            json.dumps({"status": "error", "message": "Failed to prepare backup"}),
            status=500,
            mimetype="application/json"
        )

# curl --noproxy "*" -X POST -F "file=@/path/to/modified_backup.zip" "http://URL/StrikeForce/api/return_backup"
@app.route("/StrikeForce/api/return_backup", methods=["POST"])
@global_exception_handler
def return_backup():
    """Return a modified backup"""
    if 'file' not in request.files:
        return Response(
            json.dumps({"status": "error", "message": "No file uploaded"}),
            status=400,
            mimetype="application/json"
        )
    
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_zip:
            uploaded_file = request.files['file']
            uploaded_file.save(tmp_zip.name)
            temp_zip_path = Path(tmp_zip.name)
        
        # Create temp extraction directory
        with tempfile.TemporaryDirectory() as temp_dir:
            extract_zip(temp_zip_path, Path(temp_dir))
            
            # Clean up uploaded file
            os.unlink(tmp_zip.name)
            
            # Validate and read metadata
            meta_path = Path(temp_dir) / "metadata.enc"
            if not meta_path.exists():
                return Response(
                    json.dumps({"status": "error", "message": "Missing metadata file"}),
                    status=400,
                    mimetype="application/json"
                )
            
            encrypted = meta_path.read_bytes()
            try:
                decrypted = aes256_decrypt(encrypted)
            except Exception as e:
                logging.error(f"Decryption failed: {str(e)}")
                return Response(
                    json.dumps({"status": "error", "message": "Decryption failed"}),
                    status=500,
                    mimetype="application/json"
                )
            
            # Parse metadata
            parts = decrypted.split(",")
            if len(parts) != 5:
                return Response(
                    json.dumps({"status": "error", "message": "Invalid metadata format"}),
                    status=400,
                    mimetype="application/json"
                )
            
            rec_bot, rec_serial, rec_epoch, rec_password, rec_par = parts
            
            # Validate bot exists
            if rec_bot not in bots:
                return Response(
                    json.dumps({"status": "success", "message": "Bot not found, no change"}),
                    mimetype="application/json"
                )
            
            bot_index = bots.index(rec_bot)
            
            # Find the backup node
            found_node = None
            for node in backups[bot_index]:
                if node.serial == rec_serial:
                    found_node = node
                    break
            
            if not found_node:
                return Response(
                    json.dumps({"status": "success", "message": "Backup not found, no change"}),
                    mimetype="application/json"
                )
            
            # Validate credentials
            password_hash = sha256(rec_password)
            branch = (int(rec_epoch), password_hash)
            
            if branch not in found_node.branches:
                return Response(
                    json.dumps({"status": "success", "message": "Invalid credentials, no change"}),
                    mimetype="application/json"
                )
            
            # Remove branch since it's being processed
            found_node.branches.remove(branch)
            
            # Check if metadata matches original
            origin_meta_path = get_backup_dir(rec_bot, rec_serial) / "metadata.enc"
            if origin_meta_path.exists():
                origin_encrypted = origin_meta_path.read_bytes()
                if origin_encrypted == encrypted:
                    # Replace existing backup
                    shutil.rmtree(get_backup_dir(rec_bot, rec_serial))
                    shutil.move(temp_dir, get_backup_dir(rec_bot, rec_serial))
                    logging.info(f"Updated backup {rec_serial} for bot {rec_bot}")
                else:
                    # Create new backup node
                    new_serial = gen_token()
                    new_backup_dir = get_backup_dir(rec_bot, new_serial)
                    shutil.move(temp_dir, new_backup_dir)
                    
                    # Create new metadata
                    new_epoch = int(time.time())
                    new_password = gen_token()
                    new_metadata = f"{rec_bot},{new_serial},{new_epoch},{new_password},{rec_serial}"
                    new_encrypted = aes256_encrypt(new_metadata)
                    (new_backup_dir / "metadata.enc").write_bytes(new_encrypted)
                    
                    # Add to tree
                    new_node = Node(new_serial, par=rec_serial)
                    backups[bot_index].append(new_node)
                    logging.info(f"Created new backup {new_serial} for bot {rec_bot}")
            else:
                # Original backup doesn't exist, create new one
                new_backup_dir = get_backup_dir(rec_bot, rec_serial)
                shutil.move(temp_dir, new_backup_dir)
                logging.info(f"Restored missing backup {rec_serial} for bot {rec_bot}")
        
        return Response(
            json.dumps({"status": "success", "message": "Backup processed"}),
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Backup return failed: {str(e)}")
        return Response(
            json.dumps({"status": "error", "message": "Backup processing failed"}),
            status=500,
            mimetype="application/json"
        )

# ====================== Startup ======================
if __name__ == "__main__":
    # Create backups directory if not exists
    Path("backups").mkdir(exist_ok=True)
    
    # Security check for production
    if os.environ.get("FLASK_ENV") == "production":
        logging.info("Starting production server")
        # Consider using production WSGI server here
    else:
        logging.info("Starting development server")
    
    app.run(host="0.0.0.0", port=8080, threaded=True)
