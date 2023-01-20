#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
#include <time.h>
#include "sgx_tgmp.h"

# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    printf("Starting initialize enclave\n");
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    printf("Creating enclave succeed\n");

    return 0;
}

/* OCall functions */
long ocall_get_time(){
    long t = clock();
//    printf("ocall: %ld\n", t);
    return t;
}


void test_large_input(){
    sgx_status_t ret;
    clock_t s, e, t;
    long inside_t;

    long begin, end;
    begin = 10, end = 30;

    printf("ecall_test_large_input(μs): \n");
    printf("input size(bytes),enclave transition(μs)\n");

    long input_size = 1 << end;

    uint8_t *input;
    input = (uint8_t*) malloc(input_size);
    for (long i = 0; i < input_size; ++i) {
        input[i] = i % 128;
    }
    s = clock();
    ecall_test_large_input(global_eid, &inside_t, input_size, input);
    e = clock();
    t = e - s;
    printf("%d,%ld\n", input_size, t - inside_t);

    for (long j = begin; j <= end; ++j) {
        input_size = 1 << j;
//        printf("%d\n", input_size);

        s = clock();

        ret = ecall_test_large_input(global_eid, &inside_t, input_size, input);

        e = clock();
        t = e - s;

        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
        } else {
//            printf("ecall_test_large_input(μs): (outside)%ld - (inside)%ld = %ld\n", t, inside_t, t - inside_t);
            printf("%d,%ld\n", input_size, t - inside_t);
        }
    }
}

// more enclaves? large enclave?
void test_large_epc(){

    sgx_status_t ret;
    clock_t s, e, t;
    long inside_t;

    int begin, end, delt, size;
    begin = delt = 1e7, end = 2e8;

    printf("ecall_test_large_input(μs): \n");

    size = end;
    ret = ecall_test_large_epc(global_eid, &inside_t, size);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
    } else {
//            printf("size=%d: (inside)%ld - (outside)%ld = %ld\n", size, inside_t, t, inside_t - t);
        printf("%d,%ld,%ld,%ld\n", size, inside_t, t, inside_t - t);
    }

    for (int j = begin; j <= end; j += delt) {
        size = j;
//        printf("%d\n", size);

        s = clock();
        uint8_t *arr = (uint8_t*) malloc(size);

        for (int i = 0; i < size; ++i) {
            arr[i] = arr[size - i] = (unsigned char)i % 128;
        }
        e = clock();
        t = e - s;

        ret = ecall_test_large_epc(global_eid, &inside_t, size);

        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
        } else {
//            printf("size=%d: (inside)%ld - (outside)%ld = %ld\n", size, inside_t, t, inside_t - t);
            printf("%d,%ld,%ld,%ld\n", size, inside_t, t, inside_t - t);
        }

    }

}

long net_overload = 1000000;

void test_parallel(){
    sgx_status_t ret;
    clock_t s, e, t;

    int begin, end, delt;
    begin = delt = 1, end = 10;

    printf("ecall_test_parallel(ms): \n");
    printf("input size,enclave transition(ms)\n");

    int n = end;
    long v;

    unsigned int input[n + 10], output[n + 10];
    for (int i = 0; i < n; ++i) {
        input[i] = i + 10;
    }
//    s = clock();
//    ecall_test_parallel(global_eid, &v, n * 4, input, output);
//    e = clock();
//    t = e - s;
//    printf("%d,%ld\n", n, t + net_overload);

    for (int j = begin; j <= end; j += delt) {
        n = j;
//        printf("%d\n", n);

        s = clock();

        ret = ecall_test_parallel(global_eid, &v, n * 4, input, output);

        e = clock();
        t = e - s;

        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
        } else {
//            printf("ecall_test_large_input(μs): (outside)%ld - (inside)%ld = %ld\n", t, inside_t, t - inside_t);
            printf("(%d,%lf)\n", n, n / (((double)t + net_overload) / CLOCKS_PER_SEC));
        }
    }
}

void test_non_parallel(){
    sgx_status_t ret;
    clock_t s, e, t;

    int begin, end, delt;
    begin = delt = 1, end = 10;

    printf("ecall_test_non_parallel(ms): \n");
    printf("input size,enclave transition(ms)\n");

    int n = end;

    unsigned int input[n + 10], output[n + 10];
    for (int i = 0; i < n; ++i) {
        input[i] = i + 10;
    }

    for (int j = begin; j <= end; j += delt) {
        n = j;

        t = 0;
        for (int i = 0; i < n; ++i) {
            s = clock();
            ret = ecall_test_non_parallel(global_eid, &output[i], input[i]);
            e = clock();
            t += e - s + net_overload;
        }


        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
        } else {
//            printf("ecall_test_large_input(μs): (outside)%ld - (inside)%ld = %ld\n", t, inside_t, t - inside_t);
            printf("(%d,%lf)\n", n, n / ((double)t / CLOCKS_PER_SEC));
        }
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

//    test_large_input();
//    test_large_epc();
    test_parallel();
    test_non_parallel();
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    return 0;
}

