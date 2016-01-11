#include "config.h"
#include "common.h"
#include "rsa/rsa.h"
#include "rsa/dumb_padding.h"
#include "rsa/rsa_util.h"
#include "skein/skein.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif
// XXX: move to config
#define HASH_BIT_SIZE 1024

static void print_usage()
{
    const char *usage_str = "usage: rsa-skein-sign {sign|verify} "
        "<key file> <document file> <signature file>";
    puts(usage_str);
}

static int fsize(const char *path, size_t *size)
{
    struct stat buffer;    
    if (stat(path, &buffer))
        return 1;
    *size = buffer.st_size;
    return 0;
}
// mode = s|v
static int load_data(bigint_t *n, bigint_t *exp, FILE **doc, FILE **sign,
    char *key_file, char *doc_file, char *sign_file, char mode)
{
    FILE *key = fopen(key_file, "rb");
    if (!key)
    {
        puts("can't open key file.");
        return 1;
    }
    if (rsa_load_key(key, n, exp))
    {
        fclose(key);
        puts("invalid key file.");
        return 1;
    }
    *doc = fopen(doc_file, "rb");
    if (!*doc)
    {
        puts("can't open document file.");
        return 1;
    }
    *sign = fopen(sign_file, mode=='s' ? "wb+" : "rb");
    if (!*sign)
    {
        puts("can't open signature file.");
        return 1;
    }
    return 0;
}

static int get_file_hash(FILE *f, uint8_t hash[HASH_BIT_SIZE/8])
{
    int ret = 1;
    Skein1024_Ctxt_t ctx;
    if (Skein1024_Init(&ctx, HASH_BIT_SIZE))
        goto Error;
    uint8_t chunk[HASH_BIT_SIZE/8];
    for (size_t r; (r = fread(chunk, 1, sizeof(chunk), f));)
    {
        if (Skein1024_Update(&ctx, chunk, r))
            goto Error;
    }
    if (Skein1024_Final(&ctx, hash))
        goto Error;
    ret = 0;
Error:
    return ret;
}

static int rssign_sign(int argc, char *argv[])
{
    // 0       1      2   3   4
    // rssign 'sign' key doc signature
    bigint_t *n = bigint_alloc();
    bigint_t *exp = bigint_alloc();
    FILE *doc = NULL, *sign = NULL;
    uint8_t *rsa_buf = NULL;
    int ret = 1;
    if (load_data(n, exp, &doc, &sign, argv[2], argv[3], argv[4], 's'))
        goto Error;
    // 1] compute document hash
    uint8_t comp_hash[HASH_BIT_SIZE/8];
    if (get_file_hash(doc, comp_hash))
    {
        puts("cannot calculate document hash.");
        goto Error;
    }
    // 2] encrypt hash using private key and save it to signature file
    size_t src_block_size, dst_block_size;
    rsa_get_block_sizes('e', n, &src_block_size, &dst_block_size);
    size_t rsa_buf_sz = max(src_block_size, dst_block_size);
    rsa_buf = malloc(rsa_buf_sz);
    size_t zbytes = dst_block_size-src_block_size;
    assert(zbytes<=sizeof(uint32_t));
    size_t bytes_done = 0;
    for (; bytes_done<sizeof(comp_hash)-src_block_size;
        bytes_done += src_block_size)
    {
        // XXX: valid for little endian only!
        memcpy(rsa_buf, comp_hash+bytes_done, src_block_size);
        memset(rsa_buf+rsa_buf_sz-zbytes, 0, zbytes);
        rsa_transform(rsa_buf, rsa_buf_sz, rsa_buf, exp, n);
        fwrite(rsa_buf, 1, dst_block_size, sign);
    }
    // process last rsa block
    memcpy(rsa_buf, comp_hash+bytes_done, sizeof(comp_hash)-bytes_done);
    size_t pad_param = 0;
    int pad_result = dp_pad(rsa_buf, src_block_size,
        sizeof(comp_hash)-bytes_done, &pad_param);
    if (pad_result!=DP_OK)
    {
        if (pad_result!=DP_MORE)
        {
            puts("cannot apply padding.");
            goto Error;
        }
        rsa_transform(rsa_buf, rsa_buf_sz, rsa_buf, exp, n);
        fwrite(rsa_buf, 1, dst_block_size, sign);
        if (dp_pad(rsa_buf, src_block_size, 0, &pad_param)!=DP_OK)
        {
            puts("cannot apply padding.");
            goto Error;
        }
    }
    rsa_transform(rsa_buf, rsa_buf_sz, rsa_buf, exp, n);
    fwrite(rsa_buf, 1, dst_block_size, sign);
    // 4] signature = public key + encrypted hash
    printf("document signature files: (your public key file), %s\n", argv[4]);
    ret = 0;
Error:
    if (doc)
        fclose(doc);
    if (sign)
        fclose(sign);
    if (rsa_buf)
        free(rsa_buf);
    bigint_free(n);
    bigint_free(exp);
    return ret;
}

static int rssign_verify(int argc, char *argv[])
{
    // 0       1        2   3   4
    // rssign 'verify' key doc signature
    bigint_t *n = bigint_alloc();
    bigint_t *exp = bigint_alloc();
    FILE *doc = NULL, *sign = NULL;
    uint8_t *rsa_buf = NULL, *sign_hash = NULL;
    int v_result = 1;
    int ret = 1;
    if (load_data(n, exp, &doc, &sign, argv[2], argv[3], argv[4], 'v'))
        goto Error;
    // 1] compute document hash
    uint8_t comp_hash[HASH_BIT_SIZE/8];
    if (get_file_hash(doc, comp_hash))
    {
        puts("cannot calculate document hash.");
        goto Error;
    }
    // 2] load encrypted hash from signature file and
    // decrypt it using public key
    size_t src_block_size, dst_block_size;
    rsa_get_block_sizes('d', n, &src_block_size, &dst_block_size);
    size_t sign_size;
    if (fsize(argv[4], &sign_size))
    {
        printf("can't stat %s.\n", argv[4]);
        goto Error;
    }
    size_t sign_hash_size = sign_size/src_block_size*dst_block_size;
    sign_hash = malloc(sign_hash_size);
    size_t sign_hash_pos = 0;
    size_t rsa_buf_sz = max(src_block_size, dst_block_size);
    rsa_buf = malloc(rsa_buf_sz);
    size_t bytes_done = 0;
    while (1)
    {
        // XXX: valid for little endian only!
        bytes_done = fread(rsa_buf, 1, src_block_size, sign);
        if (bytes_done!=src_block_size)
            break;
        rsa_transform(rsa_buf, rsa_buf_sz, rsa_buf, exp, n);
        memcpy(sign_hash+sign_hash_pos, rsa_buf, dst_block_size);
        sign_hash_pos += dst_block_size;
    }
    // remove padding
    size_t padding = 0;
    if (dp_depad(rsa_buf, dst_block_size, &padding)!=DP_OK ||
        padding>sign_hash_size)
    {
        puts("padding is invalid and cannot be removed. wrong key?");
        v_result = 0;
        goto Error;
    }
    // trim to the actual plaintext size
    sign_hash_size -= padding;
    v_result = !memcmp(comp_hash, sign_hash, sign_hash_size);
    if (v_result)
        puts("verification succeeded.");
    ret = 0;
Error:
    if (!v_result)
        puts("verification failed.");
    if (doc)
        fclose(doc);
    if (sign)
        fclose(sign);
    if (rsa_buf)
        free(rsa_buf);
    if (sign_hash)
        free(sign_hash);
    bigint_free(n);
    bigint_free(exp);
    return ret;
}

int main(int argc, char *argv[])
{
    if (argc==5)
    {
        if (!strcmp(argv[1], "sign"))
            return rssign_sign(argc, argv);
        if (!strcmp(argv[1], "verify"))
            return rssign_verify(argc, argv);
    }
    print_usage();
    return 1;
}
