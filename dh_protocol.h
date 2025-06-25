#ifndef DH_PROTOCOL_H
#define DH_PROTOCOL_H

#include <openssl/bn.h>

// 定义 Diffie-Hellman 协议相关结构体
typedef struct {
    BIGNUM* p; // 大素数
    BIGNUM* g; // 生成元
    BIGNUM* private_key; // 私钥
    BIGNUM* public_key; // 公钥
    BIGNUM* shared_secret; // 共享密钥
} DH_CTX;

// 初始化 Diffie-Hellman 上下文
void dh_init(DH_CTX* ctx, const char* p_str, const char* g_str);

// 生成密钥对
void dh_generate_keypair(DH_CTX* ctx);

// 计算共享密钥
void dh_compute_shared_secret(DH_CTX* ctx, const char* peer_public_key_str);

// 清理资源
void dh_cleanup(DH_CTX* ctx);

// 打印大整数
void print_bignum(const char* label, const BIGNUM* bn);

#endif // DH_PROTOCOL_H