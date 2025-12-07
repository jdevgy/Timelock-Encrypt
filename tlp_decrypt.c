#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>

#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

/* Faster tlp decryption using C 
Usage:
  ./tlp_unlock_tlp FILE --index J [--password PASS] > plaintext.out
*/

#define CURRENT_VERSION 5
static const char* VERSION_TAG = "v5enc";
#define VERSION_TAG_LEN 5

#define MAGIC_TLP "TIME_TLP_LAYER_5enc"
#define MAGIC_PASSWORD_CHECK "ENCRYPTED_WITH_PASSWORD_MAGIC"
#define AES_KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16


// ---------- Utilities ----------
static int read_all(FILE* f, unsigned char** out, size_t* out_len) {
    unsigned char* buf = NULL;
    size_t cap = 0, len = 0;
    for (;;) {
        if (len == cap) {
            size_t ncap = cap ? cap * 2 : 65536;
            unsigned char* nb = (unsigned char*)realloc(buf, ncap);
            if (!nb) { free(buf); return -1; }
            buf = nb; cap = ncap;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            if (feof(f)) break;
            free(buf); return -1;
        }
    }
    *out = buf; *out_len = len; return 0;
}

static int is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int looks_like_hex(const unsigned char* b, size_t n) {
    if (n < 2) return 0;
    for (size_t i = 0; i < n; i++) {
        if (b[i] == '\n' || b[i] == '\r' || b[i] == ' ' || b[i] == '\t') continue;
        if (!is_hex_char(b[i])) return 0;
    }
    return 1;
}

static int hex_to_bin(const unsigned char* hex, size_t hex_len, unsigned char** out, size_t* out_len) {
    unsigned char* tmp = (unsigned char*)malloc(hex_len);
    if (!tmp) return -1;
    size_t k = 0;
    for (size_t i = 0; i < hex_len; i++) {
        unsigned char c = hex[i];
        if (c=='\n'||c=='\r'||c==' '||c=='\t') continue;
        tmp[k++] = c;
    }
    if (k % 2 != 0) { free(tmp); return -1; }
    size_t bl = k/2;
    unsigned char* outb = (unsigned char*)malloc(bl);
    if (!outb) { free(tmp); return -1; }
    for (size_t i = 0; i < bl; i++) {
        unsigned char c1 = tmp[2*i], c2 = tmp[2*i+1];
        unsigned v1 = (c1>='0'&&c1<='9')?c1-'0':(c1>='a'&&c1<='f')?c1-'a'+10:(c1>='A'&&c1<='F')?c1-'A'+10:255;
        unsigned v2 = (c2>='0'&&c2<='9')?c2-'0':(c2>='a'&&c2<='f')?c2-'a'+10:(c2>='A'&&c2<='F')?c2-'A'+10:255;
        if (v1>15||v2>15) { free(tmp); free(outb); return -1; }
        outb[i] = (unsigned char)((v1<<4)|v2);
    }
    free(tmp);
    *out = outb; *out_len = bl; return 0;
}

static uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]);
}
static uint64_t be64(const unsigned char* p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
           ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|((uint64_t)p[7]);
}

static int unpad_pkcs7(unsigned char* buf, size_t* len_io) {
    size_t len = *len_io;
    if (len == 0) return -1;
    unsigned pad = buf[len-1];
    if (pad == 0 || pad > 16) return -1;
    if (pad > len) return -1;
    for (size_t i = 0; i < pad; i++) {
        if (buf[len-1-i] != pad) return -1;
    }
    *len_io = len - pad;
    return 0;
}

// ---------- Crypto helpers ----------
static void sha256_bytes(const unsigned char* in, size_t in_len, unsigned char out[32]) {
    SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, in, in_len); SHA256_Final(out, &c);
}
static void md5_bytes(const unsigned char* in, size_t in_len, unsigned char out[16]) {
    MD5_CTX c; MD5_Init(&c); MD5_Update(&c, in, in_len); MD5_Final(out, &c);
}

static int aes256cbc_decrypt(const unsigned char key[32], const unsigned char iv[16],
                             const unsigned char* ct, size_t ct_len,
                             unsigned char** out, size_t* out_len) {
    int ok = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    unsigned char* buf = (unsigned char*)malloc(ct_len + 16);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return -1; }
    int len1=0, len2=0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, buf, &len1, ct, (int)ct_len) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, buf+len1, &len2) != 1) goto done;
    *out_len = (size_t)(len1+len2);
    *out = buf; buf = NULL;
    ok = 0;
done:
    if (buf) free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes256cbc_encrypt(const unsigned char key[32], const unsigned char iv[16],
                             const unsigned char* pt, size_t pt_len,
                             unsigned char** out, size_t* out_len) {
    int ok = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    unsigned char* buf = (unsigned char*)malloc(pt_len + 32);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return -1; }
    int len1=0, len2=0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, buf, &len1, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, buf+len1, &len2) != 1) goto done;
    *out_len = (size_t)(len1+len2);
    *out = buf; buf = NULL;
    ok = 0;
done:
    if (buf) free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// PBKDF2-HMAC-SHA256
static int pbkdf2_hmac_sha256(const unsigned char* pw, size_t pw_len,
                              const unsigned char* salt, size_t salt_len,
                              uint32_t iters,
                              unsigned char* out, size_t dkLen) {
    return PKCS5_PBKDF2_HMAC((const char*)pw, (int)pw_len, salt, (int)salt_len, (int)iters, EVP_sha256(), (int)dkLen, out) == 1 ? 0 : -1;
}

// ---------- Hex helpers ----------
static void to_hex(const unsigned char* in, size_t n, char* out) {
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i] = hexd[in[i]>>4];
        out[2*i+1] = hexd[in[i]&0xF];
    }
    out[2*n] = 0;
}

// ---------- Password/index derivation helpers ----------
/*
compute_pw_in replicates your Python logic:

indexhash_hex = hex(sha256(str(index)))
hexhmac = hex(HMAC_SHA256(seed, indexhash_hex))
pass_pone = hex(MD5(hexhmac))
passwordpart = hex(SHA1(hex(key_part_encoded)))
password = pass_pone + passwordpart (ASCII concat)
passwordfinal_hex = hex(sha256(password))
Return UTF-8 bytes of passwordfinal_hex (to feed PBKDF2)
*/
static int compute_pw_in(const unsigned char key_part_encoded[32], uint64_t idx, const unsigned char seed[32],
                         unsigned char** out_bytes, size_t* out_len) {
    char decbuf[32];
    snprintf(decbuf, sizeof(decbuf), "%llu", (unsigned long long)idx);

    unsigned char shabuf[32];
    sha256_bytes((const unsigned char*)decbuf, strlen(decbuf), shabuf);
    char indexhash_hex[65];
    to_hex(shabuf, 32, indexhash_hex);

    unsigned int hm_len = 0;
    unsigned char* hmacbuf = HMAC(EVP_sha256(),
                                  seed, 32,
                                  (unsigned char*)indexhash_hex, strlen(indexhash_hex),
                                  NULL, &hm_len);
    if (!hmacbuf || hm_len != 32) return -1;

    char hexhmac[65];
    to_hex(hmacbuf, 32, hexhmac);

    unsigned char md5tmp[16];
    md5_bytes((unsigned char*)hexhmac, strlen(hexhmac), md5tmp);
    char pass_pone[33];
    to_hex(md5tmp, 16, pass_pone);

    char keypart_hex[65];
    to_hex(key_part_encoded, 32, keypart_hex);
    unsigned char sha1tmp[20];
    {
        SHA_CTX sc; SHA1_Init(&sc); SHA1_Update(&sc, keypart_hex, strlen(keypart_hex)); SHA1_Final(sha1tmp, &sc);
    }
    char passwordpart[41];
    to_hex(sha1tmp, 20, passwordpart);

    size_t cat_len = strlen(pass_pone) + strlen(passwordpart);
    char* password_cat = (char*)malloc(cat_len + 1);
    if (!password_cat) return -1;
    strcpy(password_cat, pass_pone);
    strcat(password_cat, passwordpart);

    unsigned char shafinal[32];
    sha256_bytes((unsigned char*)password_cat, strlen(password_cat), shafinal);
    free(password_cat);
    char passwordfinal_hex[65];
    to_hex(shafinal, 32, passwordfinal_hex);

    unsigned char* ret = (unsigned char*)malloc(strlen(passwordfinal_hex));
    if (!ret) return -1;
    memcpy(ret, passwordfinal_hex, strlen(passwordfinal_hex));
    *out_bytes = ret;
    *out_len = strlen(passwordfinal_hex);
    return 0;
}

// Parse big-endian length-prefixed mpz from buffer
static int parse_be_mpz(const unsigned char* buf, size_t buf_len, size_t* off_io, mpz_t z) {
    if (*off_io + 4 > buf_len) return -1;
    uint32_t n = be32(buf + *off_io); *off_io += 4;
    if (*off_io + n > buf_len) return -1;
    mpz_import(z, n, 1, 1, 1, 0, buf + *off_io);
    *off_io += n;
    return 0;
}

static int starts_with(const unsigned char* p, size_t n, const char* s) {
    size_t m = strlen(s);
    if (n < m) return 0;
    return memcmp(p, s, m) == 0;
}

// ---------- Timing and progress ----------
static double now_sec(void) {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void fmt_hms(double sec, char out[32]) {
    if (sec < 0) sec = 0;
    int h = (int)(sec / 3600); sec -= h * 3600;
    int m = (int)(sec / 60);   sec -= m * 60;
    double s = sec;
    if (h > 0) {
        snprintf(out, 32, "%02d:%02d:%05.2f", h, m, s);
    } else {
        snprintf(out, 32, "%02d:%05.2f", m, s);
    }
}

// v = a^(2^T) mod N using repeated squaring with progress output
static void sequential_squarings_with_progress(mpz_t v, const mpz_t a, uint64_t T, const mpz_t N) {
    mpz_set(v, a);

    double t0 = now_sec();
    double last_print = t0;
    uint64_t last_pct = (uint64_t)-1;

    gmp_printf("[TLP] Starting %" PRIu64 " squarings mod N (|N|=%lu bits)\n",
               T, (unsigned long)mpz_sizeinbase(N, 2));

    for (uint64_t i = 1; i <= T; i++) {
        mpz_mul(v, v, v);
        mpz_mod(v, v, N);

        double t = now_sec();
        uint64_t pct = (T ? (i * 100) / T : 100);

        bool hit_new_percent = (pct != last_pct);
        bool time_tick = (t - last_print) >= 1.0;  // about once per second

        if (hit_new_percent || time_tick || (i == T)) {
            double elapsed = t - t0;
            double eta = (i > 0) ? (elapsed * ((double)T - (double)i) / (double)i) : 0.0;

            char eta_buf[32], el_buf[32];
            fmt_hms(eta, eta_buf);
            fmt_hms(elapsed, el_buf);

            fprintf(stderr, "\r[TLP] %3" PRIu64 "%%  (step %" PRIu64 "/%" PRIu64 ")  elapsed %s  ETA %s",
                    pct, i, T, el_buf, eta_buf);

            fflush(stderr);
            last_print = t;
            last_pct = pct;
        }
    }

    double t1 = now_sec();
    char total_buf[32];
    fmt_hms(t1 - t0, total_buf);

    fprintf(stderr, "\n[TLP] complete in %s\n", total_buf);
    fflush(stderr);
}

// ---------- TLP decrypt ----------
static int decrypt_tlp_then_print(const unsigned char* tlp_blob, size_t tlp_len,
                                  const unsigned char key_part_encoded[32]) {
    size_t off = 0;
    if (!starts_with(tlp_blob, tlp_len, MAGIC_TLP)) {
        fprintf(stderr, "Not a TLP blob (bad magic)\n");
        return -1;
    }
    off += strlen(MAGIC_TLP);

    if (off + 4 + 4 > tlp_len) return -1;
    uint32_t version = be32(tlp_blob + off); off += 4;
    if (version != CURRENT_VERSION) { fprintf(stderr, "Bad TLP version: %u\n", version); return -1; }
    uint32_t mod_bits = be32(tlp_blob + off); off += 4; (void)mod_bits;

    mpz_t N, a;
    mpz_init(N); mpz_init(a);
    if (parse_be_mpz(tlp_blob, tlp_len, &off, N)) { mpz_clear(N); mpz_clear(a); return -1; }
    if (parse_be_mpz(tlp_blob, tlp_len, &off, a)) { mpz_clear(N); mpz_clear(a); return -1; }

    if (off + 8 + AES_KEY_LEN + IV_LEN > tlp_len) { mpz_clear(N); mpz_clear(a); return -1; }
    uint64_t T = be64(tlp_blob + off); off += 8;
    const unsigned char* capsule = tlp_blob + off; off += AES_KEY_LEN;
    const unsigned char* iv = tlp_blob + off; off += IV_LEN;
    const unsigned char* ciphertext = tlp_blob + off;
    size_t ciphertext_len = tlp_len - off;

    // v = a^(2^T) via repeated squaring with progress
    mpz_t v; mpz_init(v);
    sequential_squarings_with_progress(v, a, T, N);

    // v bytes (big-endian)
    size_t v_len = (size_t) (mpz_sizeinbase(v, 2) + 7) / 8;
    if (v_len == 0) v_len = 1;
    unsigned char* v_bytes = (unsigned char*)malloc(v_len);
    if (!v_bytes) { mpz_clear(N); mpz_clear(a); mpz_clear(v); return -1; }
    size_t count = 0;
    mpz_export(v_bytes, &count, 1, 1, 1, 0, v);
    v_len = count;

    // mask = SHA256(v_bytes || key_part_encoded)
    unsigned char mask[32];
    unsigned char* tmp = (unsigned char*)malloc(v_len + 32);
    if (!tmp) { free(v_bytes); mpz_clear(N); mpz_clear(a); mpz_clear(v); return -1; }
    memcpy(tmp, v_bytes, v_len);
    memcpy(tmp + v_len, key_part_encoded, 32);
    sha256_bytes(tmp, v_len + 32, mask);
    free(tmp);
    free(v_bytes);

    unsigned char K[32];
    for (int i = 0; i < 32; i++) K[i] = capsule[i] ^ mask[i];

    unsigned char* plain = NULL; size_t plain_len = 0;
    if (aes256cbc_decrypt(K, iv, ciphertext, ciphertext_len, &plain, &plain_len)) {
        fprintf(stderr, "AES decrypt failed (TLP)\n");
        mpz_clear(N); mpz_clear(a); mpz_clear(v);
        return -1;
    }

    // Output plaintext to stdout
    fwrite(plain, 1, plain_len, stdout);
    free(plain);

    mpz_clear(N); mpz_clear(a); mpz_clear(v);
    return 0;
}

// Exported library function for Python
// Returns 0 on success, nonzero on failure.
int tlp_unlock_tlp_run(const char* file, uint64_t index, const char* password_opt,
                       unsigned char** plaintext_out, size_t* plaintext_len_out) {

    FILE* f = fopen(file, "rb");
    if (!f) { perror("fopen"); return 1; }

    unsigned char* data = NULL; size_t data_len = 0;
    if (read_all(f, &data, &data_len)) { perror("read"); fclose(f); return 1; }
    fclose(f);

    unsigned char* bin = NULL; size_t bin_len = 0;
    if (looks_like_hex(data, data_len)) {
        if (hex_to_bin(data, data_len, &bin, &bin_len)) {
            fprintf(stderr, "Invalid hex file\n"); free(data); return 1;
        }
        free(data);
    } else {
        bin = data; bin_len = data_len;
    }

    size_t off = 0;
    if (bin_len < VERSION_TAG_LEN + 4) { free(bin); return 1; }
    if (memcmp(bin + off, VERSION_TAG, VERSION_TAG_LEN) != 0) { free(bin); return 1; }
    off += VERSION_TAG_LEN;

    if (off + 4 > bin_len) { free(bin); return 1; }
    uint32_t version = be32(bin + off); off += 4;
    if (version != CURRENT_VERSION) { free(bin); return 1; }

    if (off + 4 + 8 > bin_len) { free(bin); return 1; }
    uint32_t iters = be32(bin + off); off += 4;
    uint64_t max_index = be64(bin + off); off += 8; (void)max_index;

    if (off + SALT_LEN + 32 + 32 + 16 + 1 > bin_len) { free(bin); return 1; }
    const unsigned char* salt = bin + off; off += SALT_LEN;
    const unsigned char* seed = bin + off; off += 32;
    const unsigned char* key_part_encoded = bin + off; off += 32;
    const unsigned char* iv_pbkdf = bin + off; off += 16;
    unsigned char len_pass_magic = bin[off++];

    const unsigned char* ciphertext = bin + off;
    size_t ciphertext_len = bin_len - off;

    unsigned char* inner_ct = NULL; size_t inner_ct_len = 0;

    if (len_pass_magic > 0) {
        if (!password_opt) {
            fprintf(stderr, "Password required but not provided\n"); free(bin); return 1;
        }
        unsigned char pw_hash[32];
        sha256_bytes((const unsigned char*)password_opt, strlen(password_opt), pw_hash);

        unsigned char key_opt[32];
        if (pbkdf2_hmac_sha256(pw_hash, 32, salt, SALT_LEN, iters, key_opt, 32)) { free(bin); return 1; }

        unsigned char iv_pass[16];
        md5_bytes(iv_pbkdf, 16, iv_pass);

        unsigned char* dec = NULL; size_t dec_len = 0;
        if (aes256cbc_decrypt(key_opt, iv_pass, ciphertext, ciphertext_len, &dec, &dec_len)) {
            free(bin); return 1;
        }

        if (dec_len < len_pass_magic ||
            memcmp(dec, MAGIC_PASSWORD_CHECK, len_pass_magic) != 0) {
            free(dec); free(bin); return 1;
        }

        inner_ct_len = dec_len - len_pass_magic;
        inner_ct = (unsigned char*)malloc(inner_ct_len);
        memcpy(inner_ct, dec + len_pass_magic, inner_ct_len);
        free(dec);
    } else {
        inner_ct = (unsigned char*)malloc(ciphertext_len);
        memcpy(inner_ct, ciphertext, ciphertext_len);
        inner_ct_len = ciphertext_len;
    }

    unsigned char* pw_in = NULL; size_t pw_in_len = 0;
    if (compute_pw_in(key_part_encoded, index, seed, &pw_in, &pw_in_len)) {
        free(inner_ct); free(bin); return 1;
    }

    unsigned char key_pbkdf[32];
    if (pbkdf2_hmac_sha256(pw_in, pw_in_len, salt, SALT_LEN, iters, key_pbkdf, 32)) {
        free(pw_in); free(inner_ct); free(bin); return 1;
    }
    free(pw_in);

    unsigned char* tlp_blob = NULL; size_t tlp_blob_len = 0;
    if (aes256cbc_decrypt(key_pbkdf, iv_pbkdf, inner_ct, inner_ct_len, &tlp_blob, &tlp_blob_len)) {
        free(inner_ct); free(bin); return 1;
    }
    free(inner_ct);

    if (!starts_with(tlp_blob, tlp_blob_len, MAGIC_TLP)) {
        free(tlp_blob); free(bin); return 1;
    }

    // Instead of printing, capture plaintext
    FILE* memstream = open_memstream((char**)plaintext_out, plaintext_len_out);
    if (!memstream) { free(tlp_blob); free(bin); return 1; }
    fflush(memstream);
    fclose(memstream);

    int rc = decrypt_tlp_then_print(tlp_blob, tlp_blob_len, key_part_encoded);

    free(tlp_blob);
    free(bin);
    return rc;
}
