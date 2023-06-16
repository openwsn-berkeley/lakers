#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_MESSAGE_SIZE_LEN 64

#define MAX_EAD_SIZE_LEN 64

#define EAD_ZEROCONF_LABEL 1

#define ID_CRED_LEN 4

#define SUITES_LEN 9

#define SUPPORTED_SUITES_LEN 1

#define EDHOC_METHOD 3

#define P256_ELEM_LEN 32

#define SHA256_DIGEST_LEN 32

#define AES_CCM_KEY_LEN 16

#define AES_CCM_IV_LEN 13

#define AES_CCM_TAG_LEN 8

#define MAC_LENGTH_2 8

#define MAC_LENGTH_3 MAC_LENGTH_2

#define MAX_KDF_CONTEXT_LEN 150

#define MAX_KDF_LABEL_LEN 15

#define MAX_BUFFER_LEN 220

#define CBOR_BYTE_STRING 88

#define CBOR_UINT_1BYTE 24

#define CBOR_NEG_INT_1BYTE_START 32

#define CBOR_NEG_INT_1BYTE_END 55

#define CBOR_MAJOR_TEXT_STRING 96

#define CBOR_MAJOR_BYTE_STRING 64

#define CBOR_MAJOR_ARRAY 128

#define MAX_INFO_LEN ((((((2 + SHA256_DIGEST_LEN) + 1) + MAX_KDF_LABEL_LEN) + 1) + MAX_KDF_CONTEXT_LEN) + 1)

#define ENC_STRUCTURE_LEN ((8 + 5) + SHA256_DIGEST_LEN)

#define C_I 55

#define C_R 0

typedef enum EDHOCState {
  Start = 0,
  WaitMessage2 = 1,
  ProcessedMessage2 = 2,
  ProcessedMessage1 = 3,
  WaitMessage3 = 4,
  Completed = 5,
} EDHOCState;

typedef uint8_t U8;

typedef uint8_t BytesP256ElemLen[P256_ELEM_LEN];

typedef uint8_t BytesHashLen[SHA256_DIGEST_LEN];

typedef struct State {
  enum EDHOCState _0;
  BytesP256ElemLen _1;
  uint8_t _2;
  BytesP256ElemLen _3;
  BytesHashLen _4;
  BytesHashLen _5;
  BytesHashLen _6;
  BytesHashLen _7;
  BytesHashLen _8;
  BytesHashLen _9;
} State;

typedef struct State {
  enum EDHOCState _0;
  BytesP256ElemLen _1;
  U8 _2;
  BytesP256ElemLen _3;
  BytesHashLen _4;
  BytesHashLen _5;
  BytesHashLen _6;
  BytesHashLen _7;
  BytesHashLen _8;
  BytesHashLen _9;
} State;

typedef struct EdhocMessageBuffer {
  uint8_t content[MAX_MESSAGE_SIZE_LEN];
  uintptr_t len;
} EdhocMessageBuffer;




