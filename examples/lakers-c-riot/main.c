#include <stdio.h>
#include <string.h>
#include "od.h"
#include "ztimer.h"
#include "lakers.h"

static const uint8_t ID_U[] = {0xa1, 0x04, 0x41, 0x2b};
static const uint8_t ID_U_LEN = sizeof(ID_U) / sizeof(ID_U[0]);

static const BytesP256ElemLen G_W = {0xFF, 0xA4, 0xF1, 0x02, 0x13, 0x40, 0x29, 0xB3, 0xB1, 0x56, 0x89, 0x0B, 0x88, 0xC9, 0xD9, 0x61, 0x95, 0x01, 0x19, 0x65, 0x74, 0x17, 0x4D, 0xCB, 0x68, 0xA0, 0x7D, 0xB0, 0x58, 0x8E, 0x4D, 0x41};

static const uint8_t LOC_W[] = {0x6, 0x3, 0x6, 0xf, 0x6, 0x1, 0x7, 0x0, 0x3, 0xa, 0x2, 0xf, 0x2, 0xf, 0x6, 0x5, 0x6, 0xe, 0x7, 0x2, 0x6, 0xf, 0x6, 0xc, 0x6, 0xc, 0x6, 0xd, 0x6, 0x5, 0x6, 0xe, 0x7, 0x4, 0x2, 0xe, 0x7, 0x3, 0x6, 0x5, 0x7, 0x2, 0x7, 0x6, 0x6, 0x5, 0x7, 0x2};
static const uint8_t LOC_W_LEN = sizeof(LOC_W) / sizeof(LOC_W[0]);

static const uint8_t SS = 2;

// static const uint8_t CRED_I[] = {0xA2, 0x02, 0x77, 0x34, 0x32, 0x2D, 0x35, 0x30, 0x2D, 0x33, 0x31, 0x2D, 0x46, 0x46, 0x2D, 0x45, 0x46, 0x2D, 0x33, 0x37, 0x2D, 0x33, 0x32, 0x2D, 0x33, 0x39, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x2B, 0x20, 0x01, 0x21, 0x58, 0x20, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x22, 0x58, 0x20, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8};
// static const uint8_t CRED_R[] = {0xA2, 0x02, 0x60, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x0A, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72};
// static const uint8_t R[] = {0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac};
// static const uint8_t I[] = {0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b};

int main(void)
 {
    ztimer_sleep(ZTIMER_MSEC, 500); // wait for serial connection to become ready
    puts("Calling lakers from C!");

    puts("Begin test: generate key pair.");
    uint8_t out_private_key[32] = {0};
    uint8_t out_public_key[32] = {0};
    p256_generate_key_pair_from_c(out_private_key, out_public_key);
    puts("End test: generate key pair.");

    puts("creating edhoc initiator.");
    EdhocInitiatorC initiator = initiator_new();

    puts("creating ead-authz device.");
    ZeroTouchDevice device = authz_device_new(ID_U, ID_U_LEN, &G_W, LOC_W, LOC_W_LEN);

    puts("computing authz_secret.");
    BytesP256ElemLen authz_secret;
    initiator_compute_ephemeral_secret(&initiator, &G_W, &authz_secret);
    // od_hex_dump(authz_secret, 32, OD_WIDTH_DEFAULT);

    puts("computing ead_1.");
    ZeroTouchDeviceWaitEAD2 device_wait;
    EADItemC ead_1;
    authz_device_prepare_ead_1(&device, &authz_secret, SS, &device_wait, &ead_1);
    od_hex_dump(ead_1.value->content, ead_1.value->len, OD_WIDTH_DEFAULT);

    puts("Begin test: edhoc initiator.");
    EdhocMessageBuffer message_1;
    EdhocInitiatorWaitM2C initiator_wait_m2;
    // int res = initiator_prepare_message_1(&initiator, NULL, NULL, &initiator_wait_m2, &message_1); // if no EAD is used
    int res = initiator_prepare_message_1(&initiator, NULL, &ead_1, &initiator_wait_m2, &message_1);
    od_hex_dump(message_1.content, message_1.len, OD_WIDTH_DEFAULT);
    if (res != 0) printf("Error prep msg1: %d\n", res);

    puts("All went good.");
    return 0;
}