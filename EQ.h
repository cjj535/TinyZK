/**
 * prove a=b
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
BIGNUM *alpha,*beta;
BIGNUM *t,*x,*u,*e;
//init group g
EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
BIGNUM *order;
EC_POINT *G,*H;
EC_POINT *A,*B,*D;

char hex_a[65];
char hex_b[65];

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
 * Message : a transport message, containing D,u
 */
class Message {
public:
	//(D.x||D.y||u)
	unsigned char message_str[2][bignum_bytes_len+5];
	int message_num;//the number of GIGNUM
	int str_len[4];//the length of each bignum

	EC_POINT *D;
	BIGNUM *u,*e;

	Message (EC_GROUP *g) {
		message_num = 2;
		memset(this->message_str, 0, sizeof(this->message_str));
		for (int i=0;i<message_num;i++) {
			this->str_len[i] = 0;
		}
		this->D = EC_POINT_new(g);
		this->u = BN_new();
		this->e = BN_new();
	}
	~Message () {
		EC_POINT_free(this->D);
		BN_free(this->u);
		BN_free(this->e);
	}
};

/**
 * verifier reconstruct D,u,v from string(D1||D2||m_b||m_s||m_beta)
 */
int reconstruct_from_message(EC_GROUP *g, Message *message, const EC_POINT *G, const EC_POINT *H) {
	BIGNUM *Dx = BN_new();
	BIGNUM *Dy = BN_new();
	char str_hash[5*2*bignum_bytes_len+5] = {0};
	unsigned char str_e[bignum_bytes_len+5] = {0};

	//reconstruct D,u
	EC_POINT_oct2point(g, message->D, message->message_str[0], message->str_len[0], NULL);
	BN_bin2bn(message->message_str[1], message->str_len[1], message->u);

	//reconstruct e=hash(G,H,A,B,D)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
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
    t = BN_new();
    u = BN_new();
	x = BN_new();
    e = BN_new();
	alpha = BN_new();
	beta = BN_new();

	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	unsigned char str_e[bignum_bytes_len+5] = {0};
	char str_hash[5*2*bignum_bytes_len+5] = {0};

	//hex convert to BIGNUM
	BN_hex2bn(&prover.a, hex_a);
	BN_hex2bn(&prover.b, hex_b);
	//generate random number
	BN_rand_range(x, order);
	BN_rand_range(alpha, order);
	BN_rand_range(beta, order);

	//compute commitment
	//A=a*G+alpha*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.a,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,alpha,NULL);
	EC_POINT_add(g,A,ec_point_tmp1,ec_point_tmp2,NULL);
	//B=b*G+beta*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.b,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,beta,NULL);
	EC_POINT_add(g,B,ec_point_tmp1,ec_point_tmp2,NULL);
	//t = alpha-beta
	BN_mod_sub(t, alpha, beta, order, ctx);

	//compute D=x*H
	EC_POINT_mul(g,D,NULL,H,x,NULL);

	//e = hash(G,H,A,B,C,D1,D2)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, A, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, B, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, D, &str_hash[hash_str_len]);
	sha256_hash(str_hash, hash_str_len, str_e);
	BN_bin2bn(str_e,bignum_bytes_len,e);
	
	//u=x+t*e
	BN_mod_mul(bn_tmp1, t, e, order, ctx);
	BN_mod_add(u, bn_tmp1, x, order, ctx);

	//send str(D||u)
	message->str_len[0] = EC_POINT_point2oct(g, D, POINT_CONVERSION_COMPRESSED, message->message_str[0], bignum_bytes_len+5, NULL);
	message->str_len[1] = BN_bn2bin(u, message->message_str[1]);

	//free resource
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	BN_free(alpha);
	BN_free(beta);
	BN_free(x);
	BN_free(u);
	BN_free(t);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
    BN_free(e);
	BN_CTX_free(ctx);

	return;
}

bool verifier_verify(EC_GROUP *g, const EC_POINT *G, const EC_POINT *H, Message *message) {
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp3 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp4 = EC_POINT_new(g);
	int flag;

	//reconstruct e=hash(G,H,A,B,D)
	if (reconstruct_from_message(g, message, G, H)==-1)
		return false;

	//D+e*[a]
	EC_POINT_mul(g,ec_point_tmp1,NULL,A,message->e,NULL);
	EC_POINT_add(g,ec_point_tmp3,message->D,ec_point_tmp1,NULL);
	//uH+e*[b]
	EC_POINT_mul(g,ec_point_tmp1,NULL,H,message->u,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,B,message->e,NULL);
	EC_POINT_add(g,ec_point_tmp4,ec_point_tmp2,ec_point_tmp1,NULL);
	//D+e*([a]-[b])=uH?
	flag = EC_POINT_cmp(g,ec_point_tmp3,ec_point_tmp4,NULL);
	
	//free
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	EC_POINT_free(ec_point_tmp3);
	EC_POINT_free(ec_point_tmp4);
	
	if (flag) {
		return false;
	}
	else {
		return true;
	}
};