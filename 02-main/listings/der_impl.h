/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_THRESHOLD_DER_MAIN_H
#define SECP256K1_MODULE_THRESHOLD_DER_MAIN_H

void secp256k1_der_parse_len(const unsigned char *data, unsigned long *pos, unsigned long *lenght, unsigned long *offset) {
    unsigned long op, i;
    op = data[*pos] & 0x7F;
    if ((data[*pos] & 0x80) == 0x80) {
        for (i = 0; i < op; i++) {
            *lenght += data[*pos+1+i]<<8*(op-i-1);
        }
        *offset = op + 1;
    } else {
        *lenght = op;
        *offset = 1;
    }
    *pos += *offset;
}

int secp256k1_der_parse_struct(const unsigned char *data, size_t datalen, unsigned long *pos, unsigned long *lenght, unsigned long *offset) {
    unsigned long loffset;
    if (data[*pos] == 0x30) {
        *pos += 1;
        secp256k1_der_parse_len(data, pos, lenght, &loffset);
        *offset = 1 + loffset;
        if (*lenght + *offset != datalen) { return 0; }
        else { return 1; }
    }
    return 0;
}

int secp256k1_der_parse_struct_len(const unsigned char *data, unsigned long *lenght) {
    unsigned long len, pos, off;
    len = pos = off = 0;
    if (data[pos] == 0x30) {
        pos += 1;
        secp256k1_der_parse_len(data, &pos, &len, &off);
        *lenght = len + off + 1;
        return 1;
    }
    return 0;
}

int secp256k1_der_parse_int(const unsigned char *data, size_t datalen, unsigned long *pos, mpz_t res, unsigned long *offset) {
    unsigned long lenght, loffset;
    lenght = 0;
    if (data[*pos] == 0x02) {
        *pos += 1;
        secp256k1_der_parse_len(data, pos, &lenght, &loffset);
        if (*pos + lenght <= datalen) {
            mpz_import(res, (size_t)lenght, 1, sizeof(data[0]), 1, 0, &data[*pos]);
            *offset = 1 + loffset + lenght;
            *pos += lenght;
            return 1;
        }
    }
    return 0;
}

int secp256k1_der_parse_octet_string(const unsigned char *data, size_t datalen, size_t maxlen, unsigned long *pos, unsigned char *res, unsigned long *lenght, unsigned long *offset) {
    unsigned long loffset;
    *lenght = 0;
    if (data[*pos] == 0x04) {
        *pos += 1;
        secp256k1_der_parse_len(data, pos, lenght, &loffset);
        if (*lenght <= maxlen && *pos + *lenght <= datalen) {
            memcpy(res, &data[*pos], (size_t)*lenght);
            *offset = 1 + loffset + *lenght;
            *pos += *lenght;
            return 1;
        }
    }
    return 0;
}

unsigned char* secp256k1_der_serialize_len(size_t *datalen, size_t lenght) {
    unsigned char *data = NULL; void *serialize; size_t longsize; mpz_t len;
    if (lenght >= 0x80) {
        mpz_init_set_ui(len, lenght);
        serialize = mpz_export(NULL, &longsize, 1, sizeof(unsigned char), 1, 0, len);
        mpz_clear(len);
        *datalen = longsize + 1;
    } else {
        *datalen = 1;
    }
    data = malloc(*datalen * sizeof(unsigned char));
    if (lenght >= 0x80) {
        data[0] = (uint8_t)longsize | 0x80;
        memcpy(&data[1], serialize, longsize);
        free(serialize);
    } else {
        data[0] = (uint8_t)lenght;
    }
    return data;
}

unsigned char* secp256k1_der_serialize_int(size_t *datalen, const mpz_t op) {
    unsigned char *data; void *res, *sizedata;
    size_t sizelen, countp = 0, headerlen = 1;
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, op);
    countp += (((uint8_t*) res)[0] >= 0x80) ? 1 : 0;
    sizedata = secp256k1_der_serialize_len(&sizelen, countp);
    *datalen = headerlen + countp + sizelen;
    data = malloc(*datalen * sizeof(unsigned char));
    data[0] = 0x02;
    memcpy(&data[1], sizedata, sizelen);
    if (((uint8_t*) res)[0] >= 0x80) {
        data[1 + sizelen] = 0x00;
        memcpy(&data[1 + sizelen + 1], res, countp);
    } else {
        memcpy(&data[1 + sizelen], res, countp);
    }
    free(res);
    free(sizedata);
    return data;
}

unsigned char* secp256k1_der_serialize_scalar(size_t *datalen, const secp256k1_scalar *op) {
    unsigned char *data = NULL;
    *datalen = 2 + 32;
    data = malloc(*datalen * sizeof(unsigned char));
    data[0] = 0x02;
    data[1] = 0x20;
    secp256k1_scalar_get_b32(&data[2], op);
    return data;
}

unsigned char* secp256k1_der_serialize_octet_string(size_t *outlen, const unsigned char *op, const size_t datalen) {
    unsigned char *data = NULL, *len = NULL;
    size_t lensize = 0;
    len = secp256k1_der_serialize_len(&lensize, datalen);
    *outlen = 1 + lensize + datalen;
    data = malloc(*outlen * sizeof(unsigned char));
    data[0] = 0x04;
    memcpy(&data[1], len, lensize);
    memcpy(&data[1 + lensize], op, datalen);
    free(len);
    return data;
}

unsigned char* secp256k1_der_serialize_empty_octet_string(size_t *outlen) {
    unsigned char *data = NULL;
    *outlen = 2;
    data = malloc(*outlen * sizeof(unsigned char));
    data[0] = 0x04;
    data[1] = 0x00;
    return data;
}

unsigned char* secp256k1_der_serialize_sequence(size_t *outlen, const unsigned char *op, const size_t datalen) {
    unsigned char *data = NULL, *len = NULL;
    size_t lensize = 0;
    len = secp256k1_der_serialize_len(&lensize, datalen);
    *outlen = 1 + lensize + datalen;
    data = malloc(*outlen * sizeof(unsigned char));
    data[0] = 0x30;
    memcpy(&data[1], len, lensize);
    memcpy(&data[1 + lensize], op, datalen);
    free(len);
    return data;
}

#endif /* SECP256K1_MODULE_THRESHOLD_DER_MAIN_H */
