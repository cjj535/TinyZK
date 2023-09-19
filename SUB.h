/**
 * prove a-b=c
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

//alpha,beta,x,y<-random number
BIGNUM *alpha,*beta,*x,*y;
BIGNUM *u,*v,*e;
//init group g
EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
BIGNUM *order;
EC_POINT *G,*H;
EC_POINT *A,*B,*C,*D;

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

class Message {
public:
	//(D||u||v)
	unsigned char message_str[3][bignum_bytes_len+5];
	int str_len[4];

	EC_POINT *D;
	BIGNUM *u,*v,*e;

	Message (EC_GROUP *g) {
		memset(this->message_str, 0, sizeof(this->message_str));
		for (int i=0;i<4;i++) this->str_len[i]=0;
		this->D = EC_POINT_new(g);
		this->u = BN_new();
		this->v = BN_new();
		this->e = BN_new();
	}
	~Message () {
		EC_POINT_free(this->D);
		BN_free(this->u);
		BN_free(this->v);
		BN_free(this->e);
	}
};

/**
 * verifier reconstruct D,u,v from string(D||u||v)
 */
int reconstruct_from_message(EC_GROUP *g, Message *message, const EC_POINT *G, const EC_POINT *H) {
	//reconstruct D,u,v
	BIGNUM *Dx = BN_new();
	BIGNUM *Dy = BN_new();
	char str_hash[6*2*bignum_bytes_len+3] = {0};
	unsigned char str_e[bignum_bytes_len+3] = {0};

	EC_POINT_oct2point(g, message->D, message->message_str[0], message->str_len[0], NULL);
	BN_bin2bn(message->message_str[1], message->str_len[1], message->u);
	BN_bin2bn(message->message_str[2], message->str_len[2], message->v);

	//reconstruct e=hash(G,H,A,B,C,D)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, C, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, message->D, &str_hash[hash_str_len]);
		
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
    u = BN_new();
    v = BN_new();
    e = BN_new();
	alpha = BN_new();
	beta = BN_new();
	x = BN_new();
	y = BN_new();
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BN_CTX *ctx = BN_CTX_new();//BN_mod_mul need it
	unsigned char str_e[bignum_bytes_len+5] = {0};
	char str_hash[6*2*bignum_bytes_len+15] = {0};

	//hex convert to BIGNUM
	BN_hex2bn(&prover.a, hex_a);
	BN_hex2bn(&prover.b, hex_b);
	BN_hex2bn(&prover.c, hex_c);
	//generate random number alpha,beta,x,y
	BN_rand_range(alpha, order);
	BN_rand_range(beta, order);
	BN_rand_range(x, order);
	BN_rand_range(y, order);

	//compute commitment
	//A=aG+r1H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.a,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,alpha,NULL);
	EC_POINT_add(g,A,ec_point_tmp1,ec_point_tmp2,NULL);
	//B=bG+r2H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,beta,NULL);
	EC_POINT_add(g,B,ec_point_tmp1,ec_point_tmp2,NULL);
	//C=cG+(alpha-beta)H
	BN_mod_sub(bn_tmp2, alpha, beta, order, ctx);
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.c,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,bn_tmp2,NULL);
	EC_POINT_add(g,C,ec_point_tmp1,ec_point_tmp2,NULL);

	//compute D=xG+yH
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,x,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,y,NULL);
	EC_POINT_add(g,D,ec_point_tmp1,ec_point_tmp2,NULL);
	//e = hash(G,H,A,B,C,D)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, C, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, D, &str_hash[hash_str_len]);
	sha256_hash(str_hash, hash_str_len, str_e);
	BN_bin2bn(str_e,bignum_bytes_len,e);

	//u=x+(a-b)e
	BN_mod_sub(bn_tmp1, prover.a, prover.b, order, ctx);
	BN_mod_mul(bn_tmp2, bn_tmp1, e, order, ctx);
	BN_mod_add(u, bn_tmp2, x, order, ctx);
	//v=y+(alpha-beta)e
	BN_mod_sub(bn_tmp1, alpha, beta, order, ctx);
	BN_mod_mul(bn_tmp2, bn_tmp1, e, order, ctx);
	BN_mod_add(v, bn_tmp2, y, order, ctx);

	//send str(D||u||v)
	message->str_len[0] = EC_POINT_point2oct(g, D, POINT_CONVERSION_COMPRESSED, message->message_str[0], bignum_bytes_len+5, NULL);
	message->str_len[1] = BN_bn2bin(u, message->message_str[1]);
	message->str_len[2] = BN_bn2bin(v, message->message_str[2]);

	//free resource
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	BN_free(alpha);
	BN_free(beta);
	BN_free(x);
	BN_free(y);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
    BN_free(u);
	BN_free(v);
    BN_free(e);
	BN_CTX_free(ctx);

	return;
}

bool verifier_verify(EC_GROUP *g, const EC_POINT *G, const EC_POINT *H, Message *message) {
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp3 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp4 = EC_POINT_new(g);
	int flag = 0;
	
	//A=B+C?
	EC_POINT_add(g,ec_point_tmp1,B,C,NULL);
	if (EC_POINT_cmp(g,ec_point_tmp1,A,NULL)) return false;

	//reconstruct (d,u,v), e=hash(G,H,A,B,C,D)
	if (reconstruct_from_message(g, message, G, H)==-1)
		return false;

	//D+eC
	EC_POINT_mul(g,ec_point_tmp1,NULL,C,message->e,NULL);
	EC_POINT_add(g,ec_point_tmp3,message->D,ec_point_tmp1,NULL);
	//uG+vH
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,message->u,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,message->v,NULL);
	EC_POINT_add(g,ec_point_tmp4,ec_point_tmp1,ec_point_tmp2,NULL);
	//D+eC=uG+vH?
	flag = EC_POINT_cmp(g,ec_point_tmp3,ec_point_tmp4,NULL);

	//free
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	EC_POINT_free(ec_point_tmp3);
	EC_POINT_free(ec_point_tmp4);

	if (flag) {
		return false;
	}
	return true;
};