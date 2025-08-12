import os
import re
import io
import sys
import time
import json
import shutil
import string
import random
import zipfile
import hashlib
import tempfile
from flask import Flask, request, send_file, Response
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path

# ----------------------------
# Data structures
# ----------------------------
class Node:
    def __init__(self, serial, par=""):
        self.serial = serial
        self.par = par
        self.branches = set()  # set of (epoch, password_hash)

bots = []               # vector<string>
backups = []            # vector<vector<node>>
key = get_random_bytes(32)
iv = get_random_bytes(16)

admin_key_hash = "b18b078c272d0ac43301ec84cea2f61b0c1fb1b961de7d6aa5ced573cb9132aa"

# ----------------------------
# Helpers
# ----------------------------
def gen_token():
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(64))

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def aes256_encrypt(plaintext: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = AES.block_size - len(plaintext.encode()) % AES.block_size
    padded = plaintext.encode() + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded)

def aes256_decrypt(ciphertext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode()

def create_zip(zip_name, path):
    shutil.make_archive(zip_name.replace('.zip', ''), 'zip', path)

def extract_zip(zip_name, target_dir):
    with zipfile.ZipFile(zip_name, 'r') as zip_ref:
        zip_ref.extractall(target_dir)

# ----------------------------
# Flask App
# ----------------------------
app = Flask(__name__)

@app.route("/StrikeForce/api/request_backup")
def request_backup():
    code = request.args.get("code")
    if code not in bots:
        return Response(json.dumps({"status":"error","message":"Bot not found"}), status=404, mimetype="application/json")
    bot_index = bots.index(code)
    if not backups[bot_index]:
        return Response(json.dumps({"status":"error","message":"No backups"}), status=404, mimetype="application/json")

    selected = random.choice(backups[bot_index])
    epoch = int(time.time())
    password = gen_token()
    backup_dir = Path(f"backups/{code}/{selected.serial}")
    metadata = f"{code},{selected.serial},{epoch},{password}"
    encrypted = aes256_encrypt(metadata)

    (backup_dir / "metadata.enc").write_bytes(encrypted)
    zip_name = gen_token() + ".zip"
    create_zip(zip_name, backup_dir)
    zip_content = Path(zip_name).read_bytes()
    Path(zip_name).unlink()
    password_hash = sha256(password)
    selected.branches.add((epoch, password_hash))

    return Response(zip_content, mimetype="application/zip",
                    headers={"Content-Disposition": "attachment; filename=backup.zip"})

@app.route("/StrikeForce/api/return_backup", methods=["POST"])
def return_backup():
    if not request.data:
        return Response(json.dumps({"status":"error","message":"No file uploaded"}), status=400, mimetype="application/json")

    temp_token = gen_token()
    updated_backup_zip = temp_token + ".zip"
    Path(updated_backup_zip).write_bytes(request.data)
    updated_backup_dir = temp_token
    extract_zip(updated_backup_zip, updated_backup_dir)
    Path(updated_backup_zip).unlink()

    encrypted = Path(f"{updated_backup_dir}/metadata.enc").read_bytes()
    try:
        decrypted = aes256_decrypt(encrypted)
    except:
        shutil.rmtree(updated_backup_dir)
        return Response(json.dumps({"status":"error","message":"Decryption failed"}), status=500, mimetype="application/json")

    parts = decrypted.split(",")
    if len(parts) != 4:
        shutil.rmtree(updated_backup_dir)
        return Response(json.dumps({"status":"error","message":"Invalid metadata"}), status=400, mimetype="application/json")

    rec_type, rec_serial, rec_epoch, rec_password = parts
    rec_epoch = int(rec_epoch)
    password_hash = sha256(rec_password)

    if rec_type not in bots:
        shutil.rmtree(updated_backup_dir)
        return Response(json.dumps({"status":"success","message":"No match, no change"}), mimetype="application/json")
    bot_index = bots.index(rec_type)

    found_node = None
    for n in backups[bot_index]:
        if n.serial == rec_serial:
            found_node = n
            break
    if not found_node:
        shutil.rmtree(updated_backup_dir)
        return Response(json.dumps({"status":"success","message":"No match, no change"}), mimetype="application/json")

    branch = (rec_epoch, password_hash)
    if branch not in found_node.branches:
        shutil.rmtree(updated_backup_dir)
        return Response(json.dumps({"status":"success","message":"No match, no change"}), mimetype="application/json")
    found_node.branches.remove(branch)

    origin_meta_path = Path(f"backups/{rec_type}/{rec_serial}/metadata.enc")
    origin_encrypted = origin_meta_path.read_bytes()
    if origin_encrypted == encrypted:
        shutil.rmtree(f"backups/{rec_type}/{rec_serial}")
        shutil.move(updated_backup_dir, f"backups/{rec_type}/{rec_serial}")
    else:
        shutil.move(updated_backup_dir, f"backups/{rec_type}/{temp_token}")
        backups[bot_index].append(Node(temp_token, par=rec_serial))

    return Response(json.dumps({"status":"success","message":"Backup processed"}), mimetype="application/json")

@app.route("/StrikeForce/admin/add_bot", methods=["POST"])
def admin_add_bot():
    admin_key = request.args.get("admin_key")
    if not admin_key or sha256(admin_key) != admin_key_hash:
        return Response(json.dumps({"status":"error","message":"Unauthorized"}), status=401, mimetype="application/json")
    name = request.args.get("name")
    if not name:
        return Response(json.dumps({"status":"error","message":"Missing name"}), status=400, mimetype="application/json")
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return Response(json.dumps({"status":"error","message":"Invalid characters in name"}), status=400, mimetype="application/json")
    if name in bots:
        return Response(json.dumps({"status":"error","message":"Bot already exists"}), status=400, mimetype="application/json")
    bots.append(name)
    backups.append([])
    return Response(json.dumps({"status":"success","message":"Bot added"}), mimetype="application/json")

@app.route("/StrikeForce/admin/add_backup", methods=["POST"])
def admin_add_backup():
    admin_key = request.args.get("admin_key")
    if not admin_key or sha256(admin_key) != admin_key_hash:
        return Response(json.dumps({"status":"error","message":"Unauthorized"}), status=401, mimetype="application/json")
    bot = request.args.get("bot")
    serial = request.args.get("serial")
    par = request.args.get("par")
    if not bot or not serial or not par:
        return Response(json.dumps({"status":"error","message":"Missing parameters"}), status=400, mimetype="application/json")
    if not re.match(r"^[a-zA-Z0-9_-]+$", bot) or not re.match(r"^[a-zA-Z0-9_-]+$", serial) or not re.match(r"^[a-zA-Z0-9_-]+$", par):
        return Response(json.dumps({"status":"error","message":"Invalid characters in parameters"}), status=400, mimetype="application/json")
    if bot not in bots:
        return Response(json.dumps({"status":"error","message":"Bot not found"}), status=404, mimetype="application/json")
    index = bots.index(bot)
    if any(n.serial == serial for n in backups[index]):
        return Response(json.dumps({"status":"error","message":"Serial already exists"}), status=400, mimetype="application/json")

    backup_dir = Path(f"backups/{bot}/{serial}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    password = gen_token()
    metadata = f"{bot},{serial},{int(time.time())},{password}"
    encrypted = aes256_encrypt(metadata)
    (backup_dir / "metadata.enc").write_bytes(encrypted)

    backups[index].append(Node(serial, par=par))
    return Response(json.dumps({"status":"success","message":"Backup registered"}), mimetype="application/json")

@app.route("/StrikeForce/admin/delete_backup", methods=["POST"])
def admin_delete_backup():
    admin_key = request.args.get("admin_key")
    if not admin_key or sha256(admin_key) != admin_key_hash:
        return Response(json.dumps({"status":"error","message":"Unauthorized"}), status=401, mimetype="application/json")
    bot = request.args.get("bot")
    serial = request.args.get("serial")
    if not bot or not serial:
        return Response(json.dumps({"status":"error","message":"Missing parameters"}), status=400, mimetype="application/json")
    if not re.match(r"^[a-zA-Z0-9_-]+$", bot) or not re.match(r"^[a-zA-Z0-9_-]+$", serial):
        return Response(json.dumps({"status":"error","message":"Invalid characters in parameters"}), status=400, mimetype="application/json")
    if bot not in bots:
        return Response(json.dumps({"status":"error","message":"Bot not found"}), status=404, mimetype="application/json")
    index = bots.index(bot)
    for i, n in enumerate(backups[index]):
        if n.serial == serial:
            backups[index].pop(i)
            shutil.rmtree(f"backups/{bot}/{serial}", ignore_errors=True)
            return Response(json.dumps({"status":"success","message":"Backup deleted"}), mimetype="application/json")
    return Response(json.dumps({"status":"error","message":"Backup not found"}), status=404, mimetype="application/json")

if __name__ == "__main__":
    app.run(port=8080, threaded=True)
