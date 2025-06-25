#include "dh_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

int main() {
    // ��ʼ�� OpenSSL���� OpenSSL 3.0 �����ϰ汾�У��˲���ͨ�����Զ��ģ�
    ERR_load_crypto_strings(); // ���ڴ�����Ϣ

    // ��ʼ�� Diffie-Hellman ������������ p ������Ԫ g��
    const char* p_str = "23"; // ��ʾ����ʵ��Ӧʹ�ø��������
    const char* g_str = "5";

    DH_CTX alice_ctx, bob_ctx;

    // ��ʼ�� Alice �� Bob �� Diffie-Hellman ������
    dh_init(&alice_ctx, p_str, g_str);
    dh_init(&bob_ctx, p_str, g_str);

    // ���� Alice �� Bob ����Կ��
    dh_generate_keypair(&alice_ctx);
    dh_generate_keypair(&bob_ctx);

    // ��ӡ Alice �� Bob �Ĺ�Կ��˽Կ
    print_bignum("Alice's Public Key", alice_ctx.public_key);
    print_bignum("Bob's Public Key", bob_ctx.public_key);
    print_bignum("Alice's Private Key", alice_ctx.private_key);
    print_bignum("Bob's Private Key", bob_ctx.private_key);

    // Alice ���㹲����Կ
    dh_compute_shared_secret(&alice_ctx, BN_bn2dec(bob_ctx.public_key));

    // Bob ���㹲����Կ
    dh_compute_shared_secret(&bob_ctx, BN_bn2dec(alice_ctx.public_key));

    // ��ӡ������Կ��Ӧ����ͬ��
    print_bignum("Alice's Shared Secret", alice_ctx.shared_secret);
    print_bignum("Bob's Shared Secret", bob_ctx.shared_secret);

    // ������Դ
    dh_cleanup(&alice_ctx);
    dh_cleanup(&bob_ctx);

    // ���� OpenSSL
    ERR_free_strings();

    return 0;
}