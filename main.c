#include "dh_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

int main() {
    // 初始化 OpenSSL（在 OpenSSL 3.0 及以上版本中，此步骤通常是自动的）
    ERR_load_crypto_strings(); // 用于错误信息

    // 初始化 Diffie-Hellman 参数（大素数 p 和生成元 g）
    const char* p_str = "23"; // 简单示例，实际应使用更大的素数
    const char* g_str = "5";

    DH_CTX alice_ctx, bob_ctx;

    // 初始化 Alice 和 Bob 的 Diffie-Hellman 上下文
    dh_init(&alice_ctx, p_str, g_str);
    dh_init(&bob_ctx, p_str, g_str);

    // 生成 Alice 和 Bob 的密钥对
    dh_generate_keypair(&alice_ctx);
    dh_generate_keypair(&bob_ctx);

    // 打印 Alice 和 Bob 的公钥和私钥
    print_bignum("Alice's Public Key", alice_ctx.public_key);
    print_bignum("Bob's Public Key", bob_ctx.public_key);
    print_bignum("Alice's Private Key", alice_ctx.private_key);
    print_bignum("Bob's Private Key", bob_ctx.private_key);

    // Alice 计算共享密钥
    dh_compute_shared_secret(&alice_ctx, BN_bn2dec(bob_ctx.public_key));

    // Bob 计算共享密钥
    dh_compute_shared_secret(&bob_ctx, BN_bn2dec(alice_ctx.public_key));

    // 打印共享密钥（应该相同）
    print_bignum("Alice's Shared Secret", alice_ctx.shared_secret);
    print_bignum("Bob's Shared Secret", bob_ctx.shared_secret);

    // 清理资源
    dh_cleanup(&alice_ctx);
    dh_cleanup(&bob_ctx);

    // 清理 OpenSSL
    ERR_free_strings();

    return 0;
}