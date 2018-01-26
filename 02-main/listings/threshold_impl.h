/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_THRESHOLD_MAIN_H
#define SECP256K1_MODULE_THRESHOLD_MAIN_H

#include "include/secp256k1_threshold.h"
#include "src/modules/threshold/der_impl.h"

void secp256k1_threshold_params_clear(secp256k1_threshold_signature_params *p) {
    secp256k1_scalar_clear(&p->k);
    secp256k1_scalar_clear(&p->z);
    memset(&p->r.data, 0, 64);
}

void secp256k1_threshold_init_call_msg(secp256k1_threshold_call_msg *m) {
    m->alpha = secp256k1_paillier_message_create();
    m->zeta = secp256k1_paillier_message_create();
}

void secp256k1_threshold_init_challenge_msg(secp256k1_threshold_challenge_msg *m) {
    memset(&m->r2.data, 0, 64);
}

void secp256k1_threshold_init_response_challenge_msg(secp256k1_threshold_response_challenge_msg *m) {
    m->pi = secp256k1_eczkp_pi_create();
}

void secp256k1_threshold_init_terminate_msg(secp256k1_threshold_terminate_msg *m) {
    m->mu = secp256k1_paillier_message_create();
    m->mu2 = secp256k1_paillier_message_create();
    m->pi2 = secp256k1_eczkp_pi2_create();
}

int secp256k1_threshold_params_parse(const secp256k1_context *ctx, secp256k1_threshold_signature_params *p, const unsigned char *input, size_t inputlen) {
    unsigned char buf32[32], buf65[65];
    size_t start = 0, offset = 0, lenght = 0;
    int ret = 0;
    int overflow = 0;
    ret = secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset);
    if (ret) {
        ret = secp256k1_der_parse_octet_string(input, inputlen, 32, &start, buf32, &lenght, &offset);
        secp256k1_scalar_set_b32(&p->k, buf32, &overflow);
        if (ret && !overflow) {
            ret = secp256k1_der_parse_octet_string(input, inputlen, 32, &start, buf32, &lenght, &offset);
            secp256k1_scalar_set_b32(&p->z, buf32, &overflow);
            if (ret && !overflow) {
                ret = secp256k1_der_parse_octet_string(input, inputlen, 65, &start, buf65, &lenght, &offset);
                if (!secp256k1_ec_pubkey_parse(ctx, &p->r, buf65, lenght)) {
                    /* Erase data in the pubkey */
                    memset(&p->r.data, 0, 64);
                }
            }
        }
    }
    memset(buf32, 0, 32);
    memset(buf65, 0, 65);
    return ret;
}

unsigned char* secp256k1_threshold_params_serialize(const secp256k1_context *ctx, size_t *outputlen, const secp256k1_threshold_signature_params *p, int flag) {
    unsigned char *data = NULL, *kdata = NULL, *zdata = NULL, pub[65], *rdata = NULL, buf32[32];
    size_t len, klen, zlen, rpub = 65, rlen;    
    secp256k1_scalar_get_b32(buf32, &p->k);
    kdata = secp256k1_der_serialize_octet_string(&klen, buf32, 32);
    secp256k1_scalar_get_b32(buf32, &p->z);
    zdata = secp256k1_der_serialize_octet_string(&zlen, buf32, 32);
    if (flag == SECP256K1_THRESHOLD_PARAMS_FULL) {
        secp256k1_ec_pubkey_serialize(ctx, pub, &rpub, &p->r, SECP256K1_EC_UNCOMPRESSED);
        rdata = secp256k1_der_serialize_octet_string(&rlen, pub, rpub);
    } else {
        rdata = secp256k1_der_serialize_empty_octet_string(&rlen);
    }
    len = klen + zlen + rlen;
    data = malloc(len * sizeof(unsigned char));
    memcpy(data, kdata, klen);
    memcpy(&data[klen], zdata, zlen);
    memcpy(&data[klen + zlen], rdata, rlen);
    memset(buf32, 0, 32);
    return secp256k1_der_serialize_sequence(outputlen, data, len);
}

unsigned char* secp256k1_threshold_call_msg_serialize(size_t *outputlen, const secp256k1_threshold_call_msg *m) {
    unsigned char *data = NULL, *alpha = NULL, *zeta = NULL;
    size_t len, alen, zlen;
    alpha = secp256k1_paillier_message_serialize(&alen, m->alpha);
    zeta = secp256k1_paillier_message_serialize(&zlen, m->zeta);
    len = alen + zlen;
    data = malloc(len * sizeof(unsigned char));
    memcpy(data, alpha, alen);
    memcpy(&data[alen], zeta, zlen);
    return secp256k1_der_serialize_sequence(outputlen, data, len);
}

int secp256k1_threshold_call_msg_parse(secp256k1_threshold_call_msg *m, const unsigned char *input, size_t inputlen) {
    size_t start = 0, offset = 0, lenght = 0, inlen = 0;
    int ret = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        secp256k1_der_parse_struct_len(&input[start], &inlen);
        ret = secp256k1_paillier_message_parse(m->alpha, &input[start], inlen);
        if (ret) {
            start += inlen;
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            ret = secp256k1_paillier_message_parse(m->zeta, &input[start], inlen);
        }
    }
    return ret;
}

unsigned char* secp256k1_threshold_challenge_msg_serialize(const secp256k1_context *ctx, size_t *outputlen, const secp256k1_threshold_challenge_msg *m) {
    unsigned char *data = NULL, pub[65];
    size_t len = 65, rlen = 0;
    secp256k1_ec_pubkey_serialize(ctx, pub, &len, &m->r2, SECP256K1_EC_UNCOMPRESSED);
    data = secp256k1_der_serialize_octet_string(&rlen, pub, len);
    return secp256k1_der_serialize_sequence(outputlen, data, rlen);
}

int secp256k1_threshold_challenge_msg_parse(const secp256k1_context *ctx, secp256k1_threshold_challenge_msg *m, const unsigned char *input, size_t inputlen) {
    unsigned char buf65[65];
    unsigned long start, offset, lenght;
    int ret = 0;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        ret = secp256k1_der_parse_octet_string(input, inputlen, 65, &start, buf65, &lenght, &offset);
        if (!secp256k1_ec_pubkey_parse(ctx, &m->r2, buf65, lenght)) {
            /* Erase data in the pubkey */
            memset(&m->r2.data, 0, 64);
        }
    }
    memset(buf65, 0, 65);
    return ret;
}

int secp256k1_threshold_response_challenge_msg_parse(const secp256k1_context *ctx, secp256k1_threshold_response_challenge_msg *m, const unsigned char *input, size_t inputlen) {
    unsigned char buf65[65];
    size_t start = 0, offset = 0, lenght = 0, inlen = 0;
    int ret = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        ret = secp256k1_der_parse_octet_string(input, inputlen, 65, &start, buf65, &lenght, &offset);
        if (ret && secp256k1_ec_pubkey_parse(ctx, &m->r, buf65, lenght)) {
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (secp256k1_eczkp_pi_parse(ctx, m->pi, &input[start], inlen)) {
                return 1;
            }
        }
    }
    return 0;
}

unsigned char* secp256k1_threshold_response_challenge_msg_serialize(const secp256k1_context *ctx, size_t *outputlen, const secp256k1_threshold_response_challenge_msg *m) {
    unsigned char *data = NULL, *r = NULL, *pi = NULL, pub[65];
    size_t len = 0, rlen = 65, plen = 0;
    secp256k1_ec_pubkey_serialize(ctx, pub, &rlen, &m->r, SECP256K1_EC_UNCOMPRESSED);
    r = secp256k1_der_serialize_octet_string(&rlen, pub, rlen);
    pi = secp256k1_eczkp_pi_serialize(ctx, &plen, m->pi);
    len = rlen + plen;
    data = malloc(len * sizeof(unsigned char));
    memcpy(data, r, rlen);
    memcpy(&data[rlen], pi, plen);
    free(r);
    free(pi);
    return secp256k1_der_serialize_sequence(outputlen, data, len);
}

int secp256k1_threshold_terminate_msg_parse(const secp256k1_context *ctx, secp256k1_threshold_terminate_msg *m, const unsigned char *input, size_t inputlen) {
    size_t start = 0, offset = 0, lenght = 0, inlen = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        secp256k1_der_parse_struct_len(&input[start], &inlen);
        if (secp256k1_paillier_message_parse(m->mu, &input[start], inlen)) {
            start += inlen;
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if(secp256k1_paillier_message_parse(m->mu2, &input[start], inlen)) {
                start += inlen;
                secp256k1_der_parse_struct_len(&input[start], &inlen);
                return secp256k1_eczkp_pi2_parse(ctx, m->pi2, &input[start], inlen);
            }
        }
    }
    return 0;
}

unsigned char* secp256k1_threshold_terminate_msg_serialize(const secp256k1_context *ctx, size_t *outputlen, const secp256k1_threshold_terminate_msg *m) {
    unsigned char *data = NULL, *mu = NULL, *mu2 = NULL, *pi2 = NULL;
    size_t len = 0, mulen = 0, mu2len = 0, pi2len = 0;
    mu = secp256k1_paillier_message_serialize(&mulen, m->mu);
    mu2 = secp256k1_paillier_message_serialize(&mu2len, m->mu2);
    pi2 = secp256k1_eczkp_pi2_serialize(ctx, &pi2len, m->pi2);
    len = mulen + mu2len + pi2len;
    data = malloc(len * sizeof(unsigned char));
    memcpy(data, mu, mulen);
    memcpy(&data[mulen], mu2, mu2len);
    memcpy(&data[mulen + mu2len], pi2, pi2len);
    free(mu);
    free(mu2);
    free(pi2);
    return secp256k1_der_serialize_sequence(outputlen, data, len);
}

int secp256k1_threshold_privkey_parse(const secp256k1_context *ctx, secp256k1_scalar *secshare, secp256k1_paillier_privkey *paillierkey, secp256k1_paillier_pubkey *pairedkey, secp256k1_eczkp_parameter *zkp, secp256k1_pubkey *pairedpubkey, secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    unsigned char data[65];
    unsigned long start, offset, lenght, inlen;
    mpz_t version;
    int overflow = 0;
    start = offset = lenght = inlen = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        mpz_init(version);
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, version, &offset) 
            && mpz_cmp_ui(version, 1) == 0) {
            mpz_clear(version);
            if (!secp256k1_der_parse_octet_string(input, inputlen, 32, &start, data, &lenght, &offset)) {
                return 0;
            }
            secp256k1_scalar_set_b32(secshare, data, &overflow);
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (!secp256k1_paillier_privkey_parse(paillierkey, NULL, &input[start], inlen)) {
                return 0;
            }
            start += inlen;
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (!secp256k1_paillier_pubkey_parse(pairedkey, &input[start], inlen)) {
                return 0;
            }
            start += inlen;
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (!secp256k1_eczkp_parameter_parse(zkp, &input[start], inlen)) {
                return 0;
            }
            start += inlen;
            if (!secp256k1_der_parse_octet_string(input, inputlen, 65, &start, data, &lenght, &offset)
                || !secp256k1_ec_pubkey_parse(ctx, pairedpubkey, data, lenght)) {
                return 0;
            }
            if (!secp256k1_der_parse_octet_string(input, inputlen, 65, &start, data, &lenght, &offset)
                || !secp256k1_ec_pubkey_parse(ctx, pubkey, data, lenght)) {
                return 0;
            }
            return 1;
        } else { mpz_clear(version); }
    }
    return 0;
}

int secp256k1_threshold_call_create(const secp256k1_context *ctx, secp256k1_threshold_call_msg *callmsg, secp256k1_threshold_signature_params *params, const secp256k1_scalar *secshare, const secp256k1_paillier_pubkey *paillierkey, const unsigned char *msg32, const secp256k1_nonce_function noncefp, const secp256k1_paillier_nonce_function pnoncefp) {
    int ret = 0;
    int overflow = 0;
    unsigned char nonce32[32];
    unsigned char sec32[32];
    unsigned int count = 0;
    secp256k1_scalar privinv;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(secshare != NULL);
    ARG_CHECK(paillierkey != NULL);
    ARG_CHECK(msg32 != NULL);
    secp256k1_scalar_get_b32(sec32, secshare);
    while (1) {
        ret = noncefp(nonce32, msg32, sec32, NULL, NULL, count);
        if (!ret) {
            break;
        }
        secp256k1_scalar_set_b32(&params->k, nonce32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&params->k)) {
            secp256k1_scalar_inverse(&params->z, &params->k); /* z1 */
            secp256k1_scalar_mul(&privinv, &params->z, secshare); /* x1z1 */
            if (secp256k1_paillier_encrypt_scalar(callmsg->alpha, &params->z, paillierkey, pnoncefp) 
                && secp256k1_paillier_encrypt_scalar(callmsg->zeta, &privinv, paillierkey, pnoncefp)) {
                break;
            }
        }
        count++;
    }
    memset(nonce32, 0, 32);
    memset(sec32, 0, 32);
    secp256k1_scalar_clear(&privinv);
    return ret;
}

int secp256k1_threshold_call_received(const secp256k1_context *ctx, secp256k1_threshold_challenge_msg *challengemsg, secp256k1_threshold_signature_params *params, const secp256k1_threshold_call_msg *callmsg, const secp256k1_scalar *secshare, const unsigned char *msg32, const secp256k1_nonce_function noncefp) {
    int ret = 0;
    int overflow = 0;
    unsigned int count = 0;
    unsigned char k32[32];
    unsigned char sec32[32];

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(challengemsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(secshare != NULL);
    ARG_CHECK(msg32 != NULL);
    secp256k1_scalar_get_b32(sec32, secshare);
    while (1) {
        ret = noncefp(k32, msg32, sec32, NULL, NULL, count);
        if (!ret) {
            break;
        }
        secp256k1_scalar_set_b32(&params->k, k32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&params->k)) {
            if (secp256k1_ec_pubkey_create(ctx, &params->r, k32)) {
                memcpy(&challengemsg->r2, &params->r, sizeof(secp256k1_pubkey));
                break;
            }
        }
        count++;
    }
    memset(k32, 0, 32);
    memset(sec32, 0, 32);
    return ret;
}

int secp256k1_threshold_challenge_received(const secp256k1_context *ctx, secp256k1_threshold_response_challenge_msg *respmsg, secp256k1_threshold_signature_params *params, const secp256k1_scalar *secshare, const secp256k1_threshold_challenge_msg *challengemsg, const secp256k1_threshold_call_msg *callmsg, const secp256k1_eczkp_parameter *zkp, const secp256k1_paillier_pubkey *paillierkey, const secp256k1_eczkp_rdn_function rdnfp) {
    int ret = 0;
    unsigned char k32[32];
    secp256k1_pubkey y1;
    secp256k1_scalar privinv;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(respmsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(challengemsg != NULL);
    secp256k1_scalar_get_b32(k32, &params->k);
    memcpy(&respmsg->r, &challengemsg->r2, sizeof(secp256k1_pubkey));
    ret = secp256k1_ec_pubkey_tweak_mul(ctx, &respmsg->r, k32);
    secp256k1_scalar_get_b32(k32, secshare);
    if (ret && secp256k1_ec_pubkey_create(ctx, &y1, k32)) {
        memcpy(&params->r, &respmsg->r, sizeof(secp256k1_pubkey));        
        secp256k1_scalar_mul(&privinv, &params->z, secshare);
        VERIFY_CHECK(secp256k1_eczkp_pi_generate(
            ctx,
            respmsg->pi,
            zkp,
            callmsg->alpha,
            callmsg->zeta,
            &params->z,
            &privinv,
            &params->r,
            &challengemsg->r2,
            &y1,
            paillierkey,
            rdnfp
        ) == 1);
    }
    memset(k32, 0, 32);
    secp256k1_scalar_clear(&privinv);
    return ret;
}

int secp256k1_threshold_response_challenge_received(const secp256k1_context *ctx, secp256k1_threshold_terminate_msg *termsg, secp256k1_threshold_signature_params *params, const secp256k1_scalar *secshare, const secp256k1_threshold_call_msg *callmsg, const secp256k1_threshold_challenge_msg *challengemsg, const secp256k1_threshold_response_challenge_msg *respmsg, const unsigned char *msg32, const secp256k1_eczkp_parameter *zkp, const secp256k1_paillier_pubkey *pairedkey, const secp256k1_paillier_pubkey *p2, const secp256k1_pubkey *pairedshare, const secp256k1_paillier_nonce_function noncefp, const secp256k1_eczkp_rdn_function rdnfp) {
    unsigned char b[32];
    unsigned char sec32[32], n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    int ret = 0;
    int overflow = 0;
    secp256k1_pubkey y2;
    secp256k1_scalar privinv, msg, sigr;
    secp256k1_ge r;
    mpz_t m1, m2, c, n5, n, nc, m, z, rsig, inv;
    secp256k1_paillier_encrypted_message *enc = secp256k1_paillier_message_create();
    secp256k1_paillier_encrypted_message *m3 = secp256k1_paillier_message_create();
    secp256k1_paillier_encrypted_message *m4 = secp256k1_paillier_message_create();
    secp256k1_paillier_encrypted_message *m5 = secp256k1_paillier_message_create();

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(termsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pairedkey != NULL);
    ARG_CHECK(p2 != NULL);
    ARG_CHECK(noncefp != NULL);
    ret = secp256k1_eczkp_pi_verify(
        ctx,
        respmsg->pi,
        zkp,
        callmsg->alpha,
        callmsg->zeta,
        &respmsg->r,
        &challengemsg->r2,
        pairedshare,
        pairedkey
    );
    if (ret) {
        mpz_inits(m1, m2, c, n5, n, nc, m, z, rsig, inv, NULL);
        secp256k1_scalar_inverse(&params->z, &params->k); /* z2 */
        secp256k1_scalar_mul(&privinv, &params->z, secshare); /* x2z2 */
        mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);
        secp256k1_scalar_set_b32(&msg, msg32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&msg)) {
            secp256k1_pubkey_load(ctx, &r, &respmsg->r);
            secp256k1_fe_normalize(&r.x);
            secp256k1_fe_normalize(&r.y);
            secp256k1_fe_get_b32(b, &r.x);
            secp256k1_scalar_set_b32(&sigr, b, &overflow);
            /* These two conditions should be checked before calling */
            VERIFY_CHECK(!secp256k1_scalar_is_zero(&sigr));
            VERIFY_CHECK(overflow == 0);
            mpz_import(rsig, 32, 1, sizeof(b[0]), 1, 0, b);
            secp256k1_scalar_get_b32(b, &params->z);
            mpz_import(z, 32, 1, sizeof(b[0]), 1, 0, b);
            secp256k1_scalar_get_b32(b, &privinv);
            mpz_import(inv, 32, 1, sizeof(b[0]), 1, 0, b);
            secp256k1_scalar_get_b32(b, &msg);
            mpz_import(m, 32, 1, sizeof(msg32[0]), 1, 0, msg32);
            mpz_mul(m1, m, z); /* m'z2 */
            mpz_mul(m2, rsig, inv); /* r'x2z2 */
            mpz_pow_ui(n5, n, 5);
            noncefp(c, n5);
            mpz_mul(nc, c, n); /* cn */
            secp256k1_paillier_mult(m3, callmsg->alpha, m1, pairedkey);
            secp256k1_paillier_mult(m4, callmsg->zeta, m2, pairedkey);
            secp256k1_paillier_add(m5, m3, m4, pairedkey);
            ret = secp256k1_paillier_encrypt_mpz(enc, nc, pairedkey, noncefp);
            secp256k1_scalar_get_b32(sec32, secshare);
            if (ret && secp256k1_ec_pubkey_create(ctx, &y2, sec32)) {
                secp256k1_paillier_add(termsg->mu, m5, enc, pairedkey);
                ret = secp256k1_paillier_encrypt_mpz(termsg->mu2, z, p2, noncefp);
                VERIFY_CHECK(secp256k1_eczkp_pi2_generate(
                    ctx,                    /* ctx */
                    termsg->pi2,            /* pi2 */
                    zkp,                    /* zkp */
                    termsg->mu2,            /* m1 */
                    termsg->mu,             /* m2 */
                    callmsg->alpha,         /* m3 */
                    callmsg->zeta,          /* m4 */
                    enc,                    /* r */
                    z,                      /* x1 */
                    inv,                    /* x2 */
                    c,                      /* x3 */
                    m,                      /* x4 */
                    rsig,                   /* x5 */
                    &challengemsg->r2,      /* c */
                    &y2,                    /* w2 */
                    pairedkey,              /* pairedkey */
                    p2,                     /* pubkey */
                    rdnfp                   /* rdnfp */
                ) == 1);
            }
        }
        mpz_clears(m1, m2, c, n5, n, nc, m, z, rsig, inv, NULL);
        secp256k1_scalar_clear(&privinv);
        secp256k1_scalar_clear(&msg);
        secp256k1_scalar_clear(&sigr);
    }
    secp256k1_paillier_message_destroy(enc);
    secp256k1_paillier_message_destroy(m3);
    secp256k1_paillier_message_destroy(m4);
    secp256k1_paillier_message_destroy(m5);
    return ret;
}

int secp256k1_threshold_terminate_received(const secp256k1_context *ctx, secp256k1_ecdsa_signature* sig, const secp256k1_threshold_call_msg *callmsg, const secp256k1_threshold_challenge_msg *challengemsg, const secp256k1_threshold_terminate_msg *termsg, const secp256k1_threshold_signature_params *params, const secp256k1_eczkp_parameter *zkp, const secp256k1_paillier_privkey *p, const secp256k1_paillier_pubkey *pairedkey, const secp256k1_pubkey *pub, const secp256k1_pubkey *pairedpub, const unsigned char *msg32) {
    unsigned char n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    unsigned char b[32];
    void *ser;
    int ret = 0;
    int overflow = 0;
    size_t size;
    mpz_t m, n, sigs;
    secp256k1_ge sigr, pge;
    secp256k1_paillier_pubkey *p1;
    secp256k1_scalar r, s, mes;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(termsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(p != NULL);
    ARG_CHECK(pub != NULL);
    ARG_CHECK(msg32 != NULL);
    p1 = secp256k1_paillier_pubkey_get(p);
    ret = secp256k1_eczkp_pi2_verify(
        ctx,                     /* ctx */
        termsg->pi2,             /* pi2 */
        zkp,                     /* zkp */
        termsg->mu2,             /* m1 */
        termsg->mu,              /* m2 */
        callmsg->alpha,          /* m3 */
        callmsg->zeta,           /* m4 */
        &challengemsg->r2,       /* c */
        pairedpub,               /* w2 */
        p1,                      /* pubkey */
        pairedkey                /* pairedkey */
    );
    if (ret) {
        secp256k1_scalar_set_b32(&mes, msg32, &overflow);
        ret = !overflow && secp256k1_pubkey_load(ctx, &pge, pub);
        if (ret) {
            secp256k1_pubkey_load(ctx, &sigr, &params->r);
            secp256k1_fe_normalize(&sigr.x);
            secp256k1_fe_normalize(&sigr.y);
            secp256k1_fe_get_b32(b, &sigr.x);
            secp256k1_scalar_set_b32(&r, b, &overflow);
            VERIFY_CHECK(!secp256k1_scalar_is_zero(&r));
            VERIFY_CHECK(overflow == 0);
            mpz_inits(m, n, sigs, NULL);
            secp256k1_paillier_decrypt(m, termsg->mu, p);
            mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);
            mpz_mod(sigs, m, n);
            ser = mpz_export(NULL, &size, 1, sizeof(unsigned char), 1, 0, sigs);
            secp256k1_scalar_set_b32(&s, ser, &overflow);
            if (!overflow 
                && !secp256k1_scalar_is_zero(&s)
                && secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &pge, &mes)) {
                secp256k1_ecdsa_signature_save(sig, &r, &s);
            } else {
                memset(sig, 0, sizeof(*sig));
            }
        }
        mpz_clears(m, n, sigs, NULL);
        secp256k1_scalar_clear(&r);
        secp256k1_scalar_clear(&s);
        secp256k1_scalar_clear(&mes);
    }
    secp256k1_paillier_pubkey_destroy(p1);
    return ret;
}

#endif /* SECP256K1_MODULE_THRESHOLD_MAIN_H */
