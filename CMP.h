/**
 * prove x >= 0
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

//r_u,r_r,r_b<-random number
BIGNUM *r_u,*m_u;
BIGNUM *r_r,*m_r;
BIGNUM *e,*s;
//init group g
EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
BIGNUM *order;
EC_POINT *G,*H;
EC_POINT *X,*D1,*D2;

char hex_x[65];//x
char hex_two[65] = "2";

class Prover {
public:
	BIGNUM *a, *b, *c, *x;
	Prover () {
		this->a = BN_new();
		this->b = BN_new();
		this->c = BN_new();
		this->x = BN_new();
	}
	~Prover () {
		BN_free(this->a);
		BN_free(this->b);
		BN_free(this->c);
		BN_free(this->x);
	}
};

//EC_POINT
struct BitPoint {
	EC_POINT *B;
};

//BIGNUM
struct BitBignum {
	BIGNUM *bn;
};

//EC_POINT array; BIGNUM array
class Commitment {
public:
	int bit_num;
	BitPoint bit[33];
	BitBignum m_b[33];
	BitBignum b[33];
	BitBignum r_b[33];
	BitBignum r[33];

	Commitment (EC_GROUP *g) {
		this->bit_num = 32;
		for (int i=0;i<this->bit_num;i++) {
			(this->bit)[i].B = EC_POINT_new(g);
			(this->m_b)[i].bn = BN_new();
			(this->b)[i].bn = BN_new();
			(this->r)[i].bn = BN_new();
			(this->r_b)[i].bn = BN_new();
		}
	}

	~Commitment () {
		for (int i=0;i<this->bit_num;i++) {
			EC_POINT_free(bit[i].B);
			BN_free((this->m_b)[i].bn);
			BN_free((this->b)[i].bn);
			BN_free((this->r)[i].bn);
			BN_free((this->r_b)[i].bn);
		}
	}
};

/**
 * Message : a transport message, containing ([b_1],...,[b_(l-1)],D1,D2,m_u,m_b_0,...,m_b_(l-1),m_r)
 */
class Message {
public:
	//([b_1],...,[b_(l-1)],D1,D2,m_u,m_b_0,...,m_b_(l-1),m_r)
	unsigned char message_str[67][bignum_bytes_len+5];
	int message_num;//the number of GIGNUM
	int str_len[68];//the length of each bignum

	EC_POINT *D1,*D2;
	BIGNUM *m_u,*m_r,*e;
	BitPoint bit[33];
	BitBignum m_b[33];

	Message (EC_GROUP *g) {
		message_num = 67;
		memset(this->message_str, 0, sizeof(this->message_str));
		for (int i=0;i<message_num;i++) {
			this->str_len[i] = 0;
		}
		for (int i=0;i<32;i++) {
			(this->m_b)[i].bn = BN_new();
			(this->bit)[i].B = EC_POINT_new(g);
		}
		this->D1 = EC_POINT_new(g);
		this->D2 = EC_POINT_new(g);
		this->m_u = BN_new();
		this->m_r = BN_new();
		this->e = BN_new();
	}
	~Message () {
		for (int i=0;i<32;i++) {
			BN_free((this->m_b)[i].bn);
			EC_POINT_free((this->bit)[i].B);
		}
		EC_POINT_free(this->D1);
		EC_POINT_free(this->D2);
		BN_free(this->m_u);
		BN_free(this->m_r);
		BN_free(this->e);
	}
};

/**
 * verifier reconstruct [b_1],..,[b_(l-1)],D1,D2,m_u,b_0,...,b_(l-1),m_r from string, then construct [b_0],e
 */
int reconstruct_from_message(EC_GROUP *g, Message *message, const EC_POINT *G, const EC_POINT *H) {
	BIGNUM *Dx = BN_new();
	BIGNUM *Dy = BN_new();
	char str_hash[37*2*bignum_bytes_len+5] = {0};
	unsigned char str_e[bignum_bytes_len+5] = {0};

	int str_cnt = 0;
	//reconstruct B_1,...,B_(l-1)
	for (int i=1;i<32;i++) {
		EC_POINT_oct2point(g, message->bit[i].B, message->message_str[str_cnt], message->str_len[str_cnt], NULL); str_cnt++;
	}
	//reconstruct D1,D2
	EC_POINT_oct2point(g, message->D1, message->message_str[str_cnt], message->str_len[str_cnt], NULL); str_cnt++;
	EC_POINT_oct2point(g, message->D2, message->message_str[str_cnt], message->str_len[str_cnt], NULL); str_cnt++;
	//m_u
	BN_bin2bn(message->message_str[str_cnt], message->str_len[str_cnt], message->m_u); str_cnt++;
	//m_b_0,...,m_b_l-1
	for (int i=0;i<32;i++) {
		BN_bin2bn(message->message_str[str_cnt], message->str_len[str_cnt], message->m_b[i].bn); str_cnt++;
	}
	//m_r
	BN_bin2bn(message->message_str[str_cnt], message->str_len[str_cnt], message->m_r); str_cnt++;

	//reconstruct [b_0] = [x] + (-sum(2^i*[b_i]))
	//sum(2^i*[b_i])
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	BIGNUM *two_power = BN_new();
	BIGNUM *two = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_hex2bn(&two_power, hex_two);
	BN_hex2bn(&two, hex_two);
	EC_POINT_mul(g,ec_point_tmp2,NULL,message->bit[1].B,two_power,NULL);
	for (int i=2;i<32;i++) {
		BN_mod_mul(two_power, two_power, two, order, ctx);//2^i
		EC_POINT_mul(g,ec_point_tmp1,NULL,message->bit[i].B,two_power,NULL);
		EC_POINT_add(g,ec_point_tmp2,ec_point_tmp2,ec_point_tmp1,NULL);
	}
	//-sum(2^i*[b_i])
	EC_POINT_invert(g, ec_point_tmp2, NULL);
	//[x] + (-sum(2^i*[b_i]))
	EC_POINT_add(g,message->bit[0].B,X,ec_point_tmp2,NULL);
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	BN_free(two_power);
	BN_free(two);
	BN_CTX_free(ctx);

	//reconstruct e=hash(G,H,X,[b_0],...,[b_(l-1)],D1,D2)
	int hash_str_len = 0;
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, X, &str_hash[hash_str_len]);
	for (int i=0;i<32;i++) {
		hash_str_len += point2str(g, message->bit[i].B, &str_hash[hash_str_len]);
	}
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
	Commitment commitment(g);
	BIGNUM *two = BN_new();
	BIGNUM *two_power = BN_new();
	BIGNUM *e_power = BN_new();
	BIGNUM *zero = BN_new();
    m_u = BN_new();
    m_r = BN_new();
    e = BN_new();
	s = BN_new();
	r_u = BN_new();
	r_r = BN_new();

	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BIGNUM *bn_tmp3 = BN_new();
	BIGNUM *bn_tmp4 = BN_new();
	BIGNUM *bn_tmp5 = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	unsigned char str_e[bignum_bytes_len+5] = {0};
	char str_hash[37*2*bignum_bytes_len+5] = {0};

	//hex convert to BIGNUM
	BN_hex2bn(&prover.x, hex_x);
	//generate random number
	BN_rand_range(r_u, order);
	BN_rand_range(r_r, order);
	BN_rand_range(s, order);
	BN_rand_range(commitment.r_b[0].bn, order);
	BN_hex2bn(&two, hex_two);
	BN_hex2bn(&two_power, hex_one);
	BN_hex2bn(&e_power, hex_one);
	for(int i=1;i<32;i++) {
		BN_rand_range(commitment.r[i].bn, order);
		BN_rand_range(commitment.r_b[i].bn, order);
		BN_hex2bn(&commitment.b[i].bn, hex_bit[i]);
	}
	//compute r_0,b_0
	BN_hex2bn(&bn_tmp2, hex_x);
	bncpy(bn_tmp3,s);
	for(int i=1;i<32;i++) {
		BN_mod_mul(two_power, two_power, two, order, ctx);//2*2^(i-1)
		BN_mod_mul(bn_tmp1, commitment.b[i].bn, two_power, order, ctx);//(2^i)*b_i
		BN_mod_sub(bn_tmp2, bn_tmp2, bn_tmp1, order, ctx);//-
		BN_mod_mul(bn_tmp1, commitment.r[i].bn, two_power, order, ctx);//(2^i)*r_i
		BN_mod_sub(bn_tmp3, bn_tmp3, bn_tmp1, order, ctx);//-
	}
	bncpy(commitment.b[0].bn, bn_tmp2);
	bncpy(commitment.r[0].bn, bn_tmp3);

	//compute commitment
	//X=x*G+s*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,prover.x,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,s,NULL);
	EC_POINT_add(g,X,ec_point_tmp1,ec_point_tmp2,NULL);
	//B_i=b_i*G+r_i*H
	for(int i=0;i<32;i++) {
		EC_POINT_mul(g,ec_point_tmp1,NULL,G,commitment.b[i].bn,NULL);
		EC_POINT_mul(g,ec_point_tmp2,NULL,H,commitment.r[i].bn,NULL);
		EC_POINT_add(g,commitment.bit[i].B,ec_point_tmp1,ec_point_tmp2,NULL);
	}

	//compute D1,D2
	BN_hex2bn(&bn_tmp1, hex_zero);
	BN_hex2bn(&bn_tmp2, hex_zero);
	for (int i=0;i<32;i++) {
		BN_mod_add(bn_tmp1, bn_tmp1, commitment.r_b[i].bn, order, ctx);//sum(r_b_i)
		BN_mod_mul(bn_tmp3, commitment.b[i].bn, commitment.r_b[i].bn, order, ctx);//b_i*r_b_i
		BN_mod_add(bn_tmp2, bn_tmp2, bn_tmp3, order, ctx);
	}
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,bn_tmp1,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,r_r,NULL);
	EC_POINT_add(g,D1,ec_point_tmp1,ec_point_tmp2,NULL);
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,bn_tmp2,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,r_u,NULL);
	EC_POINT_add(g,D2,ec_point_tmp1,ec_point_tmp2,NULL);

	//e = hash(G,H,X,[b_0],...,[b_(l-1)],D1,D2)
	int hash_str_len = 0;
	
	hash_str_len += point2str(g, G, str_hash);
	hash_str_len += point2str(g, H, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, X, &str_hash[hash_str_len]);
	for (int i=0;i<32;i++) {
		hash_str_len += point2str(g, commitment.bit[i].B, &str_hash[hash_str_len]);
	}
	hash_str_len += point2str(g, D1, &str_hash[hash_str_len]);
	hash_str_len += point2str(g, D2, &str_hash[hash_str_len]);

	sha256_hash(str_hash, hash_str_len, str_e);//sha256 hash
	BN_bin2bn(str_e,bignum_bytes_len,e);
	
	//m_b_i,m_u,m_r
	BN_hex2bn(&bn_tmp4, hex_zero);
	BN_hex2bn(&bn_tmp5, hex_zero);
	for (int i=0;i<32;i++) {
		//m_b_i
		BN_mod_mul(bn_tmp1, e_power, commitment.b[i].bn, order, ctx);
		BN_mod_add(commitment.m_b[i].bn, bn_tmp1, commitment.r_b[i].bn, order, ctx);
		//m_u
		BN_mod_mul(bn_tmp1, e_power, commitment.r[i].bn, order, ctx);
		BN_mod_mul(bn_tmp2, commitment.m_b[i].bn, commitment.r[i].bn, order, ctx);
		BN_mod_sub(bn_tmp3, bn_tmp1, bn_tmp2, order, ctx);
		BN_mod_add(bn_tmp4, bn_tmp4, bn_tmp3, order, ctx);
		//m_r
		BN_mod_add(bn_tmp5, bn_tmp5, bn_tmp1, order, ctx);

		BN_mod_mul(e_power, e_power, e, order, ctx);//e*e^i
	}
	BN_mod_add(m_u, bn_tmp4, r_u, order, ctx);
	BN_mod_add(m_r, bn_tmp5, r_r, order, ctx);
	
	//send str([b_1],...,[b_(l-1)],D1,D2,m_u,m_b_0,...,m_b_(l-1),m_r)
	int cnt = 0;
	for (int i=1;i<32;i++) {
		message->str_len[cnt] = EC_POINT_point2oct(g, commitment.bit[i].B, POINT_CONVERSION_COMPRESSED, message->message_str[cnt], bignum_bytes_len+5, NULL); cnt++;
	}
	message->str_len[cnt] = EC_POINT_point2oct(g, D1, POINT_CONVERSION_COMPRESSED, message->message_str[cnt], bignum_bytes_len+5, NULL); cnt++;
	message->str_len[cnt] = EC_POINT_point2oct(g, D2, POINT_CONVERSION_COMPRESSED, message->message_str[cnt], bignum_bytes_len+5, NULL); cnt++;

	message->str_len[cnt] = BN_bn2bin(m_u, message->message_str[cnt]); cnt++;
	for (int i=0;i<32;i++) {
		message->str_len[cnt] = BN_bn2bin(commitment.m_b[i].bn, message->message_str[cnt]); cnt++;
	}
	message->str_len[cnt] = BN_bn2bin(m_r, message->message_str[cnt]); cnt++;

	//free resource
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	BN_free(r_u);
	BN_free(r_r);
	BN_free(m_u);
	BN_free(m_r);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_free(bn_tmp3);
	BN_free(bn_tmp4);
	BN_free(bn_tmp5);
	BN_free(s);
    BN_free(e);

	return;
}

bool verifier_verify(EC_GROUP *g, const EC_POINT *G, const EC_POINT *H, Message *message) {
	EC_POINT *ec_point_tmp1 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp2 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp3 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp4 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp5 = EC_POINT_new(g);
	EC_POINT *ec_point_tmp6 = EC_POINT_new(g);
	BIGNUM *bn_tmp1 = BN_new();
	BIGNUM *bn_tmp2 = BN_new();
	BIGNUM *e_power = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	int flag1,flag2;

	BN_hex2bn(&e_power, hex_one);

	//reconstruct e
	if (reconstruct_from_message(g, message, G, H) == -1)
		return false;

	//sum(m_b_i),sum(m_b_i*[b_i]),sum(e^i*[b_i])
	bncpy(bn_tmp1, message->m_b[0].bn);
	EC_POINT_mul(g,ec_point_tmp3,NULL,message->bit[0].B,message->m_b[0].bn,NULL);
	EC_POINT_mul(g,ec_point_tmp4,NULL,message->bit[0].B,e_power,NULL);
	for (int i=1;i<32;i++) {
		//sum(m_b_i)
		BN_mod_add(bn_tmp1, bn_tmp1, message->m_b[i].bn, order, ctx);
		//sum(m_b_i*[b_i])
		EC_POINT_mul(g,ec_point_tmp1,NULL,message->bit[i].B,message->m_b[i].bn,NULL);
		EC_POINT_add(g,ec_point_tmp3,ec_point_tmp3,ec_point_tmp1,NULL);
		//sum(e^i*[b_i])
		BN_mod_mul(e_power, e_power, message->e, order, ctx);//e^i
		EC_POINT_mul(g,ec_point_tmp1,NULL,message->bit[i].B,e_power,NULL);
		EC_POINT_add(g,ec_point_tmp4,ec_point_tmp4,ec_point_tmp1,NULL);
	}
	//D1+sum(e^i*[b_i])
	EC_POINT_add(g,ec_point_tmp5,message->D1,ec_point_tmp4,NULL);
	//sum(m_b_i)*G+m_r*H
	EC_POINT_mul(g,ec_point_tmp1,NULL,G,bn_tmp1,NULL);
	EC_POINT_mul(g,ec_point_tmp2,NULL,H,message->m_r,NULL);
	EC_POINT_add(g,ec_point_tmp6,ec_point_tmp1,ec_point_tmp2,NULL);
	//D1+sum(e^i*[b_i])=sum(m_b_i)*G+m_r*H?
	flag1 = EC_POINT_cmp(g,ec_point_tmp5,ec_point_tmp6,NULL);

	//D2+sum(e^i*[b_i])
	EC_POINT_add(g,ec_point_tmp5,message->D2,ec_point_tmp4,NULL);
	//m_u*H+sum(m_b_i*[b_i])
	EC_POINT_mul(g,ec_point_tmp1,NULL,H,message->m_u,NULL);
	EC_POINT_add(g,ec_point_tmp6,ec_point_tmp1,ec_point_tmp3,NULL);
	//D2+e*B=m_b*G+m_beta*H?
	flag2 = EC_POINT_cmp(g,ec_point_tmp5,ec_point_tmp6,NULL);

	//free
	EC_POINT_free(ec_point_tmp1);
	EC_POINT_free(ec_point_tmp2);
	EC_POINT_free(ec_point_tmp3);
	EC_POINT_free(ec_point_tmp4);
	EC_POINT_free(ec_point_tmp5);
	EC_POINT_free(ec_point_tmp6);
	BN_free(bn_tmp1);
	BN_free(bn_tmp2);
	BN_CTX_free(ctx);

	if (flag1 || flag2) {
		return false;
	}
	return true;
};