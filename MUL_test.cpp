// test Multiplication protocol
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "MUL.h"

int main(int argc, char **argv) {
    //input
    if (argc < 4){
        printf("wrong input!\n");
        return 0;
    }
    dec2hex(hex_a,argv[1]);
    dec2hex(hex_b,argv[2]);
    dec2hex(hex_c,argv[3]);
	//init
	const EC_POINT *G = EC_GROUP_get0_generator(group);//G: generator
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);//set key with group
	EC_KEY_generate_key(ec_key);//generate key
	EC_KEY_check_key(ec_key);//check key
	const EC_POINT *H = EC_KEY_get0_public_key(ec_key);//H: public key(= sk * G) 
	order = BN_new();
    EC_GROUP_get_order(group, order, NULL);//get order

    /*for(int i=0;i<30;i++) {

        A = EC_POINT_new(group);
        B = EC_POINT_new(group);
        C = EC_POINT_new(group);
        D1 = EC_POINT_new(group);
        D2 = EC_POINT_new(group);
        Message message(group);//init commitment

        printf("Prover running...\n");
        auto start_p = std::chrono::high_resolution_clock::now();
        prover(group, G, H, &message);//prover generate message
        long long t_p = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_p).count();
        printf("prover running time: %.3lf ms\n", t_p/1000.0);

        printf("\nVerifier running...\n");
        auto start_v = std::chrono::high_resolution_clock::now();
        bool result = verifier_verify(group, G, H, &message);//verify commitment
        long long t_v = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_v).count();
        printf("verifier running time: %.3lf ms\n",t_v/1000.0);

        if (result) printf("AC\n");
        else printf("RE\n");

        EC_POINT_free(A);
        EC_POINT_free(B);
        EC_POINT_free(C);
        EC_POINT_free(D1);
        EC_POINT_free(D2);
    }*/

    //test running time
    size_t T = 100;
    long long p_time_sum = 0;
    long long v_time_sum = 0;
    bool res = true;
    //auto start = std::chrono::high_resolution_clock::now();
    while(T--) {
        A = EC_POINT_new(group);
        B = EC_POINT_new(group);
        C = EC_POINT_new(group);
        D1 = EC_POINT_new(group);
        D2 = EC_POINT_new(group);
        Message message(group);//init commitment

        auto start_p = std::chrono::high_resolution_clock::now();
        prover(group, G, H, &message);//prover make commitment
        long long t_p = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_p).count();
        p_time_sum += t_p;

        auto start_v = std::chrono::high_resolution_clock::now();
        bool result = verifier_verify(group, G, H, &message);//verify commitment
        long long t_v = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_v).count();
        v_time_sum += t_v;

        res = res && result;

        EC_POINT_free(A);
        EC_POINT_free(B);
        EC_POINT_free(C);
        EC_POINT_free(D1);
        EC_POINT_free(D2);
    }
	//long long t = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    //std::cout << "running time: " << t << " us" << std::endl;
    printf("Prover average running time: %.3lf ms\n",p_time_sum/100000.0);
    printf("Verifier average running time: %.3lf ms\n",v_time_sum/100000.0);
    if (res) printf("Verifier: AC\n");
    else printf("Verifier: RE\n");

	BN_free(order);

	return 0;
}