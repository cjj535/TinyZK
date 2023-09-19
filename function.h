#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

const int bignum_bytes_len = 32;

char hex_zero[65] = "0";
char hex_one[65] = "1";
char hex_bit[32][65];//x=sum(b_i*2^i),small endian

/**
 * print str && unsigned str
 */
void print_str(const char *str, int _len) {
	for(int i = 0; i < _len; ++i) printf("%u|", (uint8_t)str[i]);// print in char
	printf("\n");
}
void print_unsigned_str(const unsigned char *str, int _len) {
	for(int i = 0; i < _len; ++i) printf("%u|", (uint8_t)str[i]);// print in char
	printf("\n");
}

/**
 * bignum cpy: b->a
 */
void bncpy(BIGNUM *a, BIGNUM *b) {
    BIGNUM *zero = BN_new();
    BN_hex2bn(&zero, hex_zero);
    BN_add(a, b, zero);
}

/**
 * EC_POINT cpy: b->a
 */
void pointcpy(EC_GROUP *g, EC_POINT *a, EC_POINT *b) {
    BIGNUM *one = BN_new();
    BN_hex2bn(&one, hex_one);
    EC_POINT_mul(g, a, NULL, b, one, NULL);
}

/**
 * my hash function : the length of output of h() is 32 bytes
 */
int sha256_hash(const char *input, size_t len, unsigned char *output){// 32 bytes = 256 bits
	SHA256_CTX sha256_ctx;

	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, input, len);
	SHA256_Final(output, &sha256_ctx);
	
	return 1;
}

/**
 * EC_POINT to string
 * the string is char, because the hash input need be char, can't be unsigned char
 */
int point2str(EC_GROUP *g, const EC_POINT *_A, char *str) {
	BIGNUM *_x = BN_new();
	BIGNUM *_y = BN_new();
	int len_x = 0;
	int len_y = 0;
	unsigned char str_tmp[2*bignum_bytes_len+5] = {0};
	if (!EC_POINT_get_affine_coordinates_GFp(g,_A,_x,_y,NULL)) {
		return -1;
	}
	len_x = BN_bn2bin(_x, str_tmp);
	len_y = BN_bn2bin(_y, &str_tmp[len_x]);

	memcpy(str, str_tmp, len_x+len_y);

	BN_free(_x);
	BN_free(_y);

	return len_x + len_y;
}

void dec2hex(char *dst, char *src) {
	int tmp;
	//printf("%s\n",res);
	sscanf(src, "%d", &tmp);
	//printf("%d\n",tmp);
	sprintf(dst, "%x", tmp);
	//printf("%s\n",dst);
}

void dec2hex_bit(char *src) {
	int tmp;
	int bit;
	sscanf(src, "%d", &tmp);
	for (int i=0;i<32;i++) {
		bit = tmp % 2;
		tmp = tmp / 2;
		sprintf(hex_bit[i], "%x", bit);
	}
}