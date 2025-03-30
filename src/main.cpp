#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/websocket.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

std::unordered_map<std::string, std::shared_ptr<boost::beast::websocket::stream<tcp::socket>>> user_map;
std::unordered_map<std::string, std::string> user_keys;
std::unordered_map<std::string, std::string> user_public_keys;
std::mutex user_map_mutex;

std::string base64_encode(const std::string& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string encoded_data(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);
    return encoded_data;
}

std::string base64_decode(const std::string& encoded_data) {
    BIO* bio = BIO_new_mem_buf(encoded_data.data(), encoded_data.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    std::string decoded_data(encoded_data.size(), '\0');
    int decoded_length = BIO_read(bio, &decoded_data[0], encoded_data.size());
    decoded_data.resize(decoded_length);

    BIO_free_all(bio);
    return decoded_data;
}

std::string encrypt_message(const std::string& plaintext, const std::string& key) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), iv);

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len;
    EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string combined_message((char*)iv, sizeof(iv));
    combined_message += ciphertext.substr(0, ciphertext_len);

    std::string encoded_message = base64_encode(combined_message);

    std::cout << "Encrypting message: " << plaintext << std::endl;
    std::cout << "Generated IV (hex): ";
    for (unsigned char c : iv) std::cout << std::hex << (int)c;
    std::cout << std::endl;
    std::cout << "Ciphertext (hex): ";
    for (unsigned char c : ciphertext.substr(0, ciphertext_len)) std::cout << std::hex << (int)c;
    std::cout << std::endl;
    std::cout << "Encoded message (Base64): " << encoded_message << std::endl;

    return encoded_message;
}

void log_shared_key(const std::string& shared_key) {
    std::cout << "Shared key (hex): ";
    for (unsigned char c : shared_key) std::cout << std::hex << (int)c;
    std::cout << std::endl;
}

std::string decrypt_message(const std::string& encoded_ciphertext, const std::string& key) {
    std::string ciphertext = base64_decode(encoded_ciphertext);

    if (ciphertext.size() < 16) {
        throw std::runtime_error("Ciphertext too short to contain IV.");
    }

    unsigned char iv[16];
    std::memcpy(iv, ciphertext.data(), sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), iv);

    std::string plaintext;
    plaintext.resize(ciphertext.size() - sizeof(iv));

    int len;
    EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, (unsigned char*)ciphertext.data() + sizeof(iv), ciphertext.size() - sizeof(iv));
    int plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Decrypting message..." << std::endl;
    std::cout << "Extracted IV (hex): ";
    for (unsigned char c : iv) std::cout << std::hex << (int)c;
    std::cout << std::endl;
    std::cout << "Decrypted plaintext: " << plaintext.substr(0, plaintext_len) << std::endl;

    return plaintext.substr(0, plaintext_len);
}

std::string generate_hmac(const std::string& message, const std::string& key) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    HMAC(EVP_sha256(), key.data(), key.size(), (unsigned char*)message.data(), message.size(), hmac, &hmac_len);

    return std::string((char*)hmac, hmac_len);
}

bool verify_hmac(const std::string& message, const std::string& hmac, const std::string& key) {
    return generate_hmac(message, key) == hmac;
}

void handle_request(tcp::socket& socket) {
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    http::read(socket, buffer, req);

    std::ifstream file("index.html");
    if (!file) {
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::server, "Boost.Beast HTTP Server");
        res.set(http::field::content_type, "text/plain");
        res.body() = "404 - Not Found";
        res.prepare_payload();
        http::write(socket, res);
        return;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "Boost.Beast HTTP Server");
    res.set(http::field::content_type, "text/html");
    res.body() = content;
    res.prepare_payload();
    http::write(socket, res);
}

void handle_websocket(tcp::socket socket) {
    std::string username;

    try {
        auto ws = std::make_shared<boost::beast::websocket::stream<tcp::socket>>(std::move(socket));
        ws->accept();
        std::cout << "WebSocket connection accepted." << std::endl;

        for (;;) {
            beast::flat_buffer buffer;
            ws->read(buffer);

            std::string message = beast::buffers_to_string(buffer.data());
            std::cout << "Received: " << message << std::endl;

            if (message.rfind("REGISTER:", 0) == 0) {
                size_t first_colon = message.find(':', 9);
                if (first_colon != std::string::npos) {
                    username = message.substr(9, first_colon - 9);
                    std::string public_key = base64_decode(message.substr(first_colon + 1));

                    if (public_key.size() < 65 || public_key.size() > 91) {
                        ws->write(net::buffer("ERROR: Invalid public key length"));
                        continue;
                    }

                    {
                        std::lock_guard<std::mutex> lock(user_map_mutex);
                        user_map[username] = ws;
                        user_public_keys[username] = public_key;
                    }

                    std::cout << "User registered: " << username << std::endl;
                    ws->write(net::buffer("Welcome:" + username));
                } else {
                    ws->write(net::buffer("ERROR: Invalid registration format"));
                }
            } else if (message.rfind("REQUEST_PUBLIC_KEY:", 0) == 0) {
                std::string recipient = message.substr(19);
                std::lock_guard<std::mutex> lock(user_map_mutex);
                if (user_map.find(recipient) != user_map.end()) {
                    std::string recipient_public_key = user_public_keys[recipient];
                    std::string encoded_key = base64_encode(recipient_public_key);
                    ws->write(net::buffer("PUBLIC_KEY:" + encoded_key));
                } else {
                    ws->write(net::buffer("ERROR: User not found or not active"));
                }
            } else if (message.rfind("SEND:", 0) == 0) {
                size_t delimiter_pos = message.find(':', 5);
                if (delimiter_pos != std::string::npos) {
                    std::string recipient = message.substr(5, delimiter_pos - 5);
                    std::string encrypted_message = message.substr(delimiter_pos + 1);

                    std::lock_guard<std::mutex> lock(user_map_mutex);
                    if (user_map.find(recipient) != user_map.end()) {
                        user_map[recipient]->write(net::buffer(username + ": " + encrypted_message));
                    } else {
                        ws->write(net::buffer("ERROR: User not found"));
                    }
                }
            }
        }
    } catch (...) {
        if (!username.empty()) {
            std::lock_guard<std::mutex> lock(user_map_mutex);
            user_map.erase(username);
            user_keys.erase(username);
            user_public_keys.erase(username);
            std::cout << "User disconnected: " << username << std::endl;
        }
    }
}

void http_server() {
    try {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 8080));
        
        while (true) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);
            handle_request(socket);
        }
    } catch (std::exception& e) {
        std::cerr << "HTTP Server Error: " << e.what() << std::endl;
    }
}

void websocket_server() {
    try {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 8081));
        
        while (true) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);

            std::thread(&handle_websocket, std::move(socket)).detach();
        }
    } catch (std::exception& e) {
        std::cerr << "WebSocket Server Error: " << e.what() << std::endl;
    }
}

int main() {
    try {
        std::thread http_thread(http_server);
        std::thread websocket_thread(websocket_server);

        http_thread.join();
        websocket_thread.join();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}