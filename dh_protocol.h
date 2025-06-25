#ifndef DH_PROTOCOL_H
#define DH_PROTOCOL_H

#include <openssl/bn.h>

// ���� Diffie-Hellman Э����ؽṹ��
typedef struct {
    BIGNUM* p; // ������
    BIGNUM* g; // ����Ԫ
    BIGNUM* private_key; // ˽Կ
    BIGNUM* public_key; // ��Կ
    BIGNUM* shared_secret; // ������Կ
} DH_CTX;

// ��ʼ�� Diffie-Hellman ������
void dh_init(DH_CTX* ctx, const char* p_str, const char* g_str);

// ������Կ��
void dh_generate_keypair(DH_CTX* ctx);

// ���㹲����Կ
void dh_compute_shared_secret(DH_CTX* ctx, const char* peer_public_key_str);

// ������Դ
void dh_cleanup(DH_CTX* ctx);

// ��ӡ������
void print_bignum(const char* label, const BIGNUM* bn);

#endif // DH_PROTOCOL_H