#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <random>
#include <chrono>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <iterator>
#include <iomanip>
#include <filesystem>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "crow_all.h"

namespace fs = std::filesystem;

// g++ server.cpp -o server -lcrypto -lssl -std=c++17

void create_zip(const std::string &zipName, const std::string &paths) {
    std::string cmd = "zip -r " + zipName + " " + paths;
    system(cmd.c_str());
}

void extract_zip(const std::string &zipName, const std::string &targetDir) {
    std::string cmd = "unzip -o " + zipName + " -d " + targetDir;
    system(cmd.c_str());
}

static unsigned char key[32], iv[16];

const std::string admin_key_hash = "b18b078c272d0ac43301ec84cea2f61b0c1fb1b961de7d6aa5ced573cb9132aa";

struct node {
    std::string serial, par = "";
    std::set<std::pair<time_t, std::string>> branches;
};

std::vector<std::string> bots;
std::vector<std::vector<node>> backups;

std::string gen_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::string s;
    for (int i = 0; i < 64; ++i) {
        char c;
        int dig = dis(gen);
        if(dig < 10)
            c = '0' + dig;
        else
            c = 'a' + dig - 10;
        s += c;
    }
    return s;
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

bool aes256_encrypt(const std::string& plaintext, std::string& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len;
    int ciphertext_len;
    unsigned char outbuf[plaintext.size() + EVP_MAX_BLOCK_LENGTH];
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.assign(reinterpret_cast<char*>(outbuf), ciphertext_len);
    return true;
}

bool aes256_decrypt(const std::string& ciphertext, std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len;
    int plaintext_len;
    unsigned char outbuf[ciphertext.size() + EVP_MAX_BLOCK_LENGTH];
    if (1 != EVP_DecryptUpdate(ctx, outbuf, &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.assign(reinterpret_cast<char*>(outbuf), plaintext_len);
    return true;
}

crow::response request_backup(const crow::request& req) {
    auto type = req.url_params.get("code");
    bool found = false;
    int bot_index;
    for (int i = 0; i < bots.size(); ++i)
        if (bots[i] == type) {
            bot_index = i;
            found = true;
            break;
        }    
    if (!found)
        return crow::response(404, "{\"status\":\"error\",\"message\":\"Bot not found\"}");
    if (backups[bot_index].empty())
        return crow::response(404, "{\"status\":\"error\",\"message\":\"No backups\"}");
    auto& backup_vec = backups[bot_index];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> disn(0, backup_vec.size() - 1);
    node& selected = backup_vec[disn(gen)];
    time_t epoch = time(nullptr);
    std::string password = gen_token();
    std::string backup_dir = "backups/" + std::string(type) + "/" + selected.serial;
    std::string metadata = std::string(type) + "," + selected.serial + "," + std::to_string(epoch) + "," + password;
    std::string encrypted;
    if (!aes256_encrypt(metadata, encrypted))
        return crow::response(500, "{\"status\":\"error\",\"message\":\"Encryption failed\"}");
    std::ofstream meta_file(backup_dir + "/metadata.enc");
    meta_file << encrypted;
    meta_file.close();
    std::string zip_name = gen_token() + ".zip";
    create_zip(zip_name, backup_dir + "/*");
    std::ifstream zip_file(zip_name, std::ios::binary);
    std::string zip_content((std::istreambuf_iterator<char>(zip_file)), std::istreambuf_iterator<char>());
    zip_file.close();
    fs::remove(zip_name);
    std::string password_hash = sha256(password);
    selected.branches.insert({epoch, password_hash});
    crow::response res;
    res.set_header("Content-Type", "application/zip");
    res.set_header("Content-Disposition", "attachment; filename=\"backup.zip\"");
    res.body = zip_content;
    return res;
}

crow::response return_backup(const crow::request& req) {
    if (req.body.empty()) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"No file uploaded\"}");
    }
    std::string temp_token = gen_token();
    std::string updated_backup_zip = temp_token + ".zip";
    std::string updated_backup_dir = temp_token;
    std::ofstream out(updated_backup_zip, std::ios::binary);
    out.write(req.body.c_str(), req.body.size());
    out.close();
    extract_zip(updated_backup_zip, updated_backup_dir);
    fs::remove(updated_backup_zip);
    std::ifstream meta_file(updated_backup_dir + "/metadata.enc");
    std::string encrypted((std::istreambuf_iterator<char>(meta_file)), std::istreambuf_iterator<char>());
    meta_file.close();
    std::string decrypted;
    if (!aes256_decrypt(encrypted, decrypted)) {
        fs::remove_all(updated_backup_dir);
        return crow::response(500, "{\"status\":\"error\",\"message\":\"Decryption failed\"}");
    }
    std::stringstream ss(decrypted);
    std::string token;
    std::vector<std::string> parts;
    while (std::getline(ss, token, ','))
        parts.push_back(token);
    if (parts.size() != 4) {
        fs::remove_all(updated_backup_dir);
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Invalid metadata\"}");
    }
    time_t rec_epoch = std::stoll(parts[2]);
    std::string rec_type = parts[0];
    std::string rec_serial = parts[1];
    std::string password_hash = sha256(parts[3]);
    bool found = false;
    int bot_index;
    for (int i = 0; i < bots.size(); ++i)
        if (bots[i] == rec_type) {
            bot_index = i;
            found = true;
            break;
        }
    if (!found) {
        fs::remove_all(updated_backup_dir);
        return crow::response(200, "{\"status\":\"success\",\"message\":\"No match, no change\"}");
    }
    found = false;
    int backup_index;
    for (int i = 0; i < backups[bot_index].size(); ++i)
        if (backups[bot_index][i].serial == rec_serial) {
            backup_index = i;
            found = true;
            break;
        }
    if (!found) {
        fs::remove_all(updated_backup_dir);
        return crow::response(200, "{\"status\":\"success\",\"message\":\"No match, no change\"}");
    }
    auto& branches = backups[bot_index][backup_index].branches;
    auto branch = std::pair<time_t, std::string>{rec_epoch, password_hash};
    auto pos = std::lower_bound(branches.begin(), branches.end(), branch);
    if (pos == branches.end() || *pos != branch) {
        fs::remove_all(updated_backup_dir);
        return crow::response(200, "{\"status\":\"success\",\"message\":\"No match, no change\"}");
    }
    branches.erase(pos);
    std::ifstream origin_meta("backups/" + rec_type + "/" + rec_serial + "/metadata.enc");
    std::string origin_encrypted((std::istreambuf_iterator<char>(origin_meta)), std::istreambuf_iterator<char>());
    origin_meta.close();
    if (origin_encrypted == encrypted) {
        fs::remove_all("backups/" + rec_type + "/" + rec_serial);
        fs::rename(updated_backup_dir, "backups/" + rec_type + "/" + rec_serial);
    } else {
        fs::rename(updated_backup_dir, "backups/" + rec_type + "/" + temp_token);
        node backup;
        backup.serial = temp_token;
        backup.par = backups[bot_index][backup_index].serial;
        backups[bot_index].push_back(backup);
    }
    return crow::response(200, "{\"status\":\"success\",\"message\":\"Backup processed\"}");
}

crow::response admin_add_bot(const crow::request& req) {
    auto admin_key = req.url_params.get("admin_key");
    if (!admin_key || sha256(admin_key) != admin_key_hash) {
        return crow::response(401, "{\"status\":\"error\",\"message\":\"Unauthorized\"}");
    }
    auto name = req.url_params.get("name");
    if (!name) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Missing name\"}");
    }
    std::regex valid_chars("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(name, valid_chars)) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Invalid characters in name\"}");
    }
    if (std::find(bots.begin(), bots.end(), name) != bots.end()) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Bot already exists\"}");
    }
    bots.push_back(name);
    backups.push_back({});
    return crow::response(200, "{\"status\":\"success\",\"message\":\"Bot added\"}");
}

crow::response admin_add_backup(const crow::request& req) {
    auto admin_key = req.url_params.get("admin_key");
    if (!admin_key || sha256(admin_key) != admin_key_hash) {
        return crow::response(401, "{\"status\":\"error\",\"message\":\"Unauthorized\"}");
    }
    auto bot = req.url_params.get("bot");
    auto serial = req.url_params.get("serial");
    auto par = req.url_params.get("par");
    if (!bot || !serial || !par) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Missing parameters\"}");
    }
    std::regex valid_chars("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(bot, valid_chars) || !std::regex_match(serial, valid_chars) || !std::regex_match(par, valid_chars)) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Invalid characters in parameters\"}");
    }
    auto it = std::find(bots.begin(), bots.end(), bot);
    if (it == bots.end()) {
        return crow::response(404, "{\"status\":\"error\",\"message\":\"Bot not found\"}");
    }
    size_t index = std::distance(bots.begin(), it);
    for (const auto& node : backups[index]) {
        if (node.serial == serial) {
            return crow::response(400, "{\"status\":\"error\",\"message\":\"Serial already exists\"}");
        }
    }
    std::string backup_dir = "backups/" + std::string(bot) + "/" + serial;
    fs::create_directories(backup_dir);
    std::string password = gen_token();
    std::string metadata = std::string(bot) + "," + std::string(serial) + "," + std::to_string(time(nullptr)) + "," + password;
    std::string encrypted;
    if (!aes256_encrypt(metadata, encrypted)) {
        fs::remove_all(backup_dir);
        return crow::response(500, "{\"status\":\"error\",\"message\":\"Encryption failed\"}");
    }
    std::ofstream meta_file(backup_dir + "/metadata.enc");
    meta_file << encrypted;
    meta_file.close();
    node new_node;
    new_node.serial = serial;
    new_node.par = par;
    backups[index].push_back(new_node);
    return crow::response(200, "{\"status\":\"success\",\"message\":\"Backup registered\"}");
}

crow::response admin_delete_backup(const crow::request& req) {
    auto admin_key = req.url_params.get("admin_key");
    if (!admin_key || sha256(admin_key) != admin_key_hash) {
        return crow::response(401, "{\"status\":\"error\",\"message\":\"Unauthorized\"}");
    }
    auto bot = req.url_params.get("bot");
    auto serial = req.url_params.get("serial");
    if (!bot || !serial) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Missing parameters\"}");
    }
    std::regex valid_chars("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(bot, valid_chars) || !std::regex_match(serial, valid_chars)) {
        return crow::response(400, "{\"status\":\"error\",\"message\":\"Invalid characters in parameters\"}");
    }
    auto it = std::find(bots.begin(), bots.end(), bot);
    if (it == bots.end()) {
        return crow::response(404, "{\"status\":\"error\",\"message\":\"Bot not found\"}");
    }
    size_t index = std::distance(bots.begin(), it);
    auto& b_set = backups[index];
    bool found = false;
    for (auto node_it = b_set.begin(); node_it != b_set.end(); ++node_it) {
        if (node_it->serial == serial) {
            b_set.erase(node_it);
            found = true;
            break;
        }
    }
    if (!found) {
        return crow::response(404, "{\"status\":\"error\",\"message\":\"Backup not found\"}");
    }
    std::string backup_dir = "backups/" + std::string(bot) + "/" + serial;
    fs::remove_all(backup_dir);
    return crow::response(200, "{\"status\":\"success\",\"message\":\"Backup deleted\"}");
}

int main() {
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    
    crow::SimpleApp app;

    CROW_ROUTE(app, "/StrikeForce/api/request_backup")(request_backup);

    CROW_ROUTE(app, "/StrikeForce/api/return_backup").methods("POST"_method)(return_backup);

    CROW_ROUTE(app, "/StrikeForce/admin/add_bot").methods("POST"_method)(admin_add_bot);

    CROW_ROUTE(app, "/StrikeForce/admin/add_backup").methods("POST"_method)(admin_add_backup);

    CROW_ROUTE(app, "/StrikeForce/admin/delete_backup").methods("POST"_method)(admin_delete_backup);

    app.port(8080).multithreaded().run();
    return 0;
}