#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <stdlib.h>

long ecall_main(int x, int lim){
    long s, e, t;
    mpz_t  a, b;
    mpz_init_set_si(a, 78839);
    mpz_init(b);
    uint8_t *mem;
    int size = 1000000; // 10,000,000
    mem = (uint8_t *) malloc(size);
    mem[lim] = 1;
    int q = (int)1e9 + 7;

    ocall_get_time(&s);
    while(lim--) {
//        mpz_pow_ui(b, a, x);
//        mpz_mod_ui(b, b, q);
        ocall_get_time(&t);
    }
    ocall_get_time(&e);
    return e - s;
}


long ecall_test_large_input(long input_size, uint8_t *input) {
    long s, e, ret;
    ocall_get_time(&s);
    long sum = 0;
    for (long i = 0; i < input_size; ++i) {
        sum += input[i];
        sum %= input_size;
    }
    ocall_get_time(&e);
    ret = sum + e;
    ret -= sum + s;
    return ret;
}

long ecall_test_large_epc(int size) {
    long s, e, ret;
    ocall_get_time(&s);
    long sum = 0;

    uint8_t *arr = (uint8_t*) malloc(size);

    for (int i = 0; i < size; ++i) {
        arr[i] = arr[size - i] = i & 7;
    }

    ocall_get_time(&e);
    ret = e - s;
    return ret;
}


long ecall_test_parallel(int size, unsigned int *input, unsigned int *output) {

    int n = size / 4;
    mpz_t a, b;
    mpz_init(a);
    mpz_init(b);
    unsigned int q = UINT32_MAX;

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < 1000; ++j) {
            mpz_set_ui(a, input[i]);
            mpz_pow_ui(b, a, 100000);
            mpz_mod_ui(b, b, q);
            mpz_export(&output[i], 0, -1, sizeof output[i], 0, 0, b);
        }
    }

    return 0;
}


unsigned int ecall_test_non_parallel(unsigned int uia) {

    mpz_t a, b;
    mpz_init(b);
    unsigned int q = UINT32_MAX, out;

    for (int j = 0; j < 1000; ++j) {
        mpz_init_set_ui(a, uia);
        mpz_pow_ui(b, a, 100000);
        mpz_mod_ui(b, b, q);
        mpz_export(&out, 0, -1, sizeof out, 0, 0, b);
    }

    return out;
}

void ecall_empty(){
    int a = 1 + 2;
}