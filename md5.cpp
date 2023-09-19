/**
 * prove a+b=c
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
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>




int main() {
    char str[32]="asdfghjklasdfghjasdfghjklasdfgh";
    unsigned char out[16]={0};
    memset(str,1,sizeof(str));

    //test running time
    size_t T = 1;
    long long p_time_sum = 0;
    bool res = true;
    auto start = std::chrono::high_resolution_clock::now();
    //while(T--) {
    MD5_CTX md5_ctx;

    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, str, 32);
    MD5_Final(out, &md5_ctx);
    //}
	long long t = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    printf("verifier running time: %d us\n",t);
    

	return 0;
}