/*
 *   Copyright 2003-2004 The Apache Software Foundation.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <axutil_utils_defines.h>
#include <axis2_defines.h>
#include <axutil_env.h>
#include <oxs_buffer.h>
#include <oxs_key.h>

/**
  * @file openssl_hmac.h
  * @brief HMAC function implementations. Supports SHA1  
  */
#ifndef OPENSSL_HMAC
#define OPENSSL_HMAC

#ifdef __cplusplus
extern "C" {
#endif

    /**
      * @defgroup openssl_hmac OpenSSL Hmac 
      * @ingroup openssl
      * @{
      */

        AXIS2_EXTERN axis2_status_t AXIS2_CALL
        openssl_hmac_sha1(const axutil_env_t *env,
             oxs_key_t *secret,
             oxs_buffer_t *input,
             oxs_buffer_t *output); 

		AXIS2_EXTERN axis2_status_t AXIS2_CALL
		openssl_p_sha1(const axutil_env_t *env,
			 oxs_key_t *secret,
			 axis2_char_t *label,
			 axis2_char_t *seed,
			 oxs_key_t *derived_key);

        AXIS2_EXTERN axis2_status_t AXIS2_CALL
        openssl_p_hash(const axutil_env_t *env,
			unsigned char *secret,
            unsigned int secret_len,
			unsigned char *seed, 
			unsigned int seed_len, 
			unsigned char *output,
			unsigned int output_len);

    /* @} */
#ifdef __cplusplus
}
#endif

#endif    /* OPENSSL_HMAC */
