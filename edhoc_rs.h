#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "edhoc_consts.h"

typedef struct RustEdhocInitiator {
  State state;
  const str *i;
  const str *g_r;
  const str *id_cred_i;
  const str *cred_i;
  const str *id_cred_r;
  const str *cred_r;
} RustEdhocInitiator;

typedef struct RustEdhocResponder {
  State state;
  const str *r;
  const str *g_i;
  const str *id_cred_i;
  const str *cred_i;
  const str *id_cred_r;
  const str *cred_r;
} RustEdhocResponder;

int32_t edhoc_add(int32_t a, int32_t b);

EdhocResponder new_edhoc_responder(State state,
                                   const uint8_t *r,
                                   uintptr_t r_len,
                                   const uint8_t *g_i,
                                   uintptr_t g_i_len,
                                   const uint8_t *id_cred_i,
                                   uintptr_t id_cred_i_len,
                                   const uint8_t *cred_i,
                                   uintptr_t cred_i_len,
                                   const uint8_t *id_cred_r,
                                   uintptr_t id_cred_r_len,
                                   const uint8_t *cred_r,
                                   uintptr_t cred_r_len);
