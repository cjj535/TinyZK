#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

int main() {
	
    //test running time
    size_t T = 100;
    auto start = std::chrono::high_resolution_clock::now();
    while(T--) {
        
    }
	long long t = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    printf("verifier running time: %.3lf ms\n",t/10000000.0);
    
	return 0;
}