/**
 * prove a/b=c
 * commitment: pedersen commitment with EC
 * protocol: schnorr protocol using Fiat-shamir heurstic
 * hash function: sha256
 * ec: NID_X9_62_prime256v1
 */
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "function.h"

//alpha,beta,_gamma,r_b,r_s,r_beta<-random number
BIGNUM *alpha,*beta,*_gamma;
BIGNUM *r_b,*r_s,*r_beta;
BIGNUM *m_b,*m_s,*m_beta,*e,*s;
//init group g
EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
BIGNUM *order;
EC_POINT *G,*H;
EC_POINT *A,*B,*C,*D1,*D2;

char hex_a[65];
char hex_b[65];
char hex_c[65];

class Prover {
public:
	BIGNUM *a, *b, *c;
	Prover () {
		this->a = BN_new();
		this->b = BN_new();
		this->c = BN_new();
	}
	~Prover () {
		BN_free(this->a);
		BN_free(this->b);
		BN_free(this->c);
	}
};

/**
 * Message : a transport message, containing D1,D2,m_b,m_s,m_beta
 */
class Message {
public:
	//(D1||D2||m_b||m_s||m_beta)
	unsigned char message_str[5][bignum_bytes_len+5];
	int message_num;//the number of GIGNUM
	int str_len[7];//the length of each bignum

	EC_POINT *D1,*D2;
	BIGNUM *m_b,*m_s,*m_beta,*e;

	Message (EC_GROUP *g) {
		message_num = 5;
		memset(this->message_str, 0, sizeof(this->message_str));
		for (int i=0;i<message_num;i++) {
			this->str_len[i] = 0;
		}
		this->D1 = EC_POINT_new(g);
		this->D2 = EC_POINT_new(g);
		this->m_b = BN_new();
		this->m_s = BN_new();
		this->m_beta = BN_new();
		this->e = BN_new();
	}
	~Message () {
		EC_POINT_free(this->D1);
		EC_POINT_free(this->D2);
		BN_free(this->m_b);
		BN_free(this->m_s);
		BN_free(this->m_beta);
		BN_free(this->e);
	}
};

/**
 * verifier reconstruct D,u,v from string(D1||D2||m_b||m_s||m_beta)
 */
int reconstruct_from_message(EC_GROUP *g, Message *message, const EC_POINT *G, const EC_POINT *H) {
	BIGNUM *Dx = BN_new();
	BIGNUM *Dy = BN_new();
	char str_hash[7*2*bignum_bytes_len+5] = {0};
	unsigned char str_e[bignum_bytes_len+5] = {0};

	//reconstruct D1,D2,m_b,m_s,m_beta
	EC_POINT_oct2point(g, message->D1, message->message_str[0], message->str_len[0], NULL);
	EC_POINT_oct2point(g, message->D2, message->message_str[1], message->str_len[1], NULL);
	BN_bin2bn(message->message_str[2], message->str_len[2], message->m_b);
	BN_bin2bn(message->message_str[3], message->str_len[3], message->m_s);
	BN_bin2bn(message->message_str[4], message->str_len[4], message->m_beta);

	//reconstruct e=hash(G,H,A,B,C,D1,D2)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, C, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, message->D1, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, message->D2, &str_hash[hash_str_len]);
		
	//sha256 hash
	sha256_hash(str_hash, hash_str_len, str_e);
	BN_bin2bn(str_e,bignum_bytes_len,message->e);

	BN_free(Dx);
	BN_free(Dy);

	return 0;
}

void prover(EC_GROUP *g, const EC_POINT *G, const EC_POINT *H, Message *message)
{
	Prover prover;
    m_b = BN_new();
    m_s = BN_new();
	m_beta = BN_new();
    e = BN_new();
	s = BN_new();
	alpha = BN_new();
	beta = BN_new();
	_gamma = BN_new();
	r_b = BN_new();
	r_s = BN_new();
	r_beta = BN_new();

	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	unsigned char str_e[bignum_bytes_len+5] = {0};
	char str_hash[7*2*bignum_bytes_len+5] = {0};

	//hex convert to BIGNUM
	BN_hex2bn(&prover.a, hex_a);
	BN_hex2bn(&prover.b, hex_b);
	BN_hex2bn(&prover.c, hex_c);
	//generate random number
	BN_rand_range(r_b, order);
	BN_rand_range(r_s, order);
	BN_rand_range(r_beta, order);
	BN_rand_range(alpha, order);
	BN_rand_range(beta, order);
	BN_rand_range(_gamma, order);

	//compute commitment
	//A=a*G+alpha*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.a,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,alpha,NULL);
	EC_POINT_add(g,A,ec_point_tmp1,ec_point_tmp2,NULL);
	//B=b*G+beta*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,beta,NULL);
	EC_POINT_add(g,B,ec_point_tmp1,ec_point_tmp2,NULL);
	//C=c*G+_gamma*H
	//BN_mod_mul(bn_tmp1, prover.a, prover.b, order, ctx);
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.c,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,_gamma,NULL);
	EC_POINT_add(g,C,ec_point_tmp1,ec_point_tmp2,NULL);
	//s = alpha - _gamma*b
	BN_mod_mul(bn_tmp1, _gamma, prover.b, order, ctx);
	BN_mod_sub(s, alpha, bn_tmp1, order, ctx);

	//compute D1=r_b*A+r_s*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,C,r_b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,r_s,NULL);
	EC_POINT_add(g,D1,ec_point_tmp1,ec_point_tmp2,NULL);
	//compute D2=r_b*G+r_beta*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,r_b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,r_beta,NULL);
	EC_POINT_add(g,D2,ec_point_tmp1,ec_point_tmp2,NULL);
	//e = hash(G,H,A,B,C,D1,D2)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, C, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, D1, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, D2, &str_hash[hash_str_len]);
	sha256_hash(str_hash, hash_str_len, str_e);//sha256 hash
	BN_bin2bn(str_e,bignum_bytes_len,e);
	
	//m_b=r_b+b*e
	BN_mod_mul(bn_tmp1, prover.b, e, order, ctx);
	BN_mod_add(m_b, bn_tmp1, r_b, order, ctx);
	//m_s=r_s+s*e
	BN_mod_mul(bn_tmp1, s, e, order, ctx);
	BN_mod_add(m_s, bn_tmp1, r_s, order, ctx);
	//m_beta=r_beta+beta*e
	BN_mod_mul(bn_tmp1, beta, e, order, ctx);
	BN_mod_add(m_beta, bn_tmp1, r_beta, order, ctx);

	//send str(D1||D2||m_b||m_s||m_beta)
	message->str_len[0] = EC_POINT_point2oct(g, D1, POINT_CONVERSION_COMPRESSED, message->message_str[0], bignum_bytes_len+5, NULL);
	message->str_len[1] = EC_POINT_point2oct(g, D2, POINT_CONVERSION_COMPRESSED, message->message_str[1], bignum_bytes_len+5, NULL);
	message->str_len[2] = BN_bn2bin(m_b, message->message_str[2]);
	message->str_len[3] = BN_bn2bin(m_s, message->message_str[3]);
	message->str_len[4] = BN_bn2bin(m_beta, message->message_str[4]);

	//free resource
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	BN_free(alpha);
	BN_free(beta);
	BN_free(_gamma);
	BN_free(r_b);
	BN_free(r_s);
	BN_free(r_beta);
	BN_free(m_b);
	BN_free(m_s);
	BN_free(m_beta);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_free(s);
    BN_free(e);
	BN_CTX_free(ctx);

	return;
}

bool verifier_verify(EC_GROUP *g, const EC_POINT *G, const EC_POINT *H, Message *message) {
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp3 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp4 = EC_POINT_new(g);
	int flag1,flag2;

	//reconstruct e=hash(G,H,A,B,C,D1,D2)
	if (reconstruct_from_message(g, message, G, H)==-1)
		return false;

	//D1+e*A
	EC_POINT_mul(g,ec_point_tmp1,NULL,A,message->e,NULL);
	EC_POINT_add(g,ec_point_tmp3,message->D1,ec_point_tmp1,NULL);
	//m_b*C+m_s*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,C,message->m_b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,message->m_s,NULL);
	EC_POINT_add(g,ec_point_tmp4,ec_point_tmp1,ec_point_tmp2,NULL);
	//D1+e*A=m_b*C+m_s*H?
	flag1 = EC_POINT_cmp(g,ec_point_tmp3,ec_point_tmp4,NULL);

	//D2+e*B
	EC_POINT_mul(g,ec_point_tmp1,NULL,B,message->e,NULL);
	EC_POINT_add(g,ec_point_tmp3,message->D2,ec_point_tmp1,NULL);
	//m_b*G+m_beta*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,message->m_b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,message->m_beta,NULL);
	EC_POINT_add(g,ec_point_tmp4,ec_point_tmp1,ec_point_tmp2,NULL);
	//D2+e*B=m_b*G+m_beta*H?
	flag2 = EC_POINT_cmp(g,ec_point_tmp3,ec_point_tmp4,NULL);

	//free
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	EC_POINT_free(ec_point_tmp3);
	EC_POINT_free(ec_point_tmp4);

	if (flag1 || flag2) {
		return false;
	}
	return true;
};