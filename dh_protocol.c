#include "dh_protocol.h"
#include <stdio.h>
#include <stdlib.h>

// 初始化 Diffie-Hellman 上下文
void dh_init(DH_CTX* ctx, const char* p_str, const char* g_str) {
    ctx->p = BN_new();
    ctx->g = BN_new();
    ctx->private_key = BN_new();
    ctx->public_key = BN_new();
    ctx->shared_secret = BN_new();

    BN_dec2bn(&ctx->p, p_str);
    BN_dec2bn(&ctx->g, g_str);
}

// 生成密钥对
void dh_generate_keypair(DH_CTX* ctx) {
    // 生成随机私钥（范围：2 <= private_key <= p-2）
    BN_rand_range(ctx->private_key, ctx->p);
    BN_sub_word(ctx->private_key, 1); // 确保私钥不小于 2
    BN_add_word(ctx->private_key, 1);

    // 计算公钥：public_key = g^private_key mod p
    BN_CTX* ctx_temp = BN_CTX_new();
    if (ctx_temp == NULL) {
        fprintf(stderr, "BN_CTX_new failed\n");
        // 清理前面分配的资源
        BN_free(ctx->p);
        BN_free(ctx->g);
        BN_free(ctx->private_key);
        BN_free(ctx->public_key);
        BN_free(ctx->shared_secret);
        exit(-1); // 或者适当的错误处理
    }
    BN_mod_exp(ctx->public_key, ctx->g, ctx->private_key, ctx->p, ctx_temp);
    BN_CTX_free(ctx_temp);
}

// 计算共享密钥
void dh_compute_shared_secret(DH_CTX* ctx, const char* peer_public_key_str) {
    BIGNUM* peer_public_key = BN_new();
    BN_dec2bn(&peer_public_key, peer_public_key_str);

    // 计算共享密钥：shared_secret = peer_public_key^private_key mod p
    BN_CTX* ctx_temp = BN_CTX_new();
    if (ctx_temp == NULL) {
        fprintf(stderr, "BN_CTX_new failed\n");
        BN_free(peer_public_key);
        // 清理前面分配的资源
        BN_free(ctx->p);
        BN_free(ctx->g);
        BN_free(ctx->private_key);
        BN_free(ctx->public_key);
        BN_free(ctx->shared_secret);
        exit(-1); // 或者适当的错误处理
    }
    BN_mod_exp(ctx->shared_secret, peer_public_key, ctx->private_key, ctx->p, ctx_temp);
    BN_CTX_free(ctx_temp);
    BN_free(peer_public_key);
}

// 清理资源
void dh_cleanup(DH_CTX* ctx) {
    BN_free(ctx->p);
    BN_free(ctx->g);
    BN_free(ctx->private_key);
    BN_free(ctx->public_key);
    BN_free(ctx->shared_secret);
}

// 打印大整数
void print_bignum(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2dec(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}