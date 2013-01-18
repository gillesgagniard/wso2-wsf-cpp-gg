/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <axutil_utils_defines.h>
#include <axis2_defines.h>
#include <axutil_env.h>

/**
  * @file rampart_crypto_util.h
  * @brief Crypto related utility module
  */
#ifndef RAMPART_CRYPTO_UTIL
#define RAMPART_CRYPTO_UTIL

#ifdef __cplusplus
extern "C" {
#endif

    /**
      * @defgroup rampart_crypto_util Rampart Crypto Util
      * @ingroup rampart_utils
      */


    /**
    * Calculate the hash of concatenated string of nonce+created+password
    * @param env pointer to environment variable
    * @param nonce randomly created bytes
    * @param created created time
    * @param password password to be hashed
    * @return calculated hash on success. NULL otherwise
    */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_crypto_sha1(
        const axutil_env_t *env,
        const axis2_char_t *nonce,
        const axis2_char_t *created,
        const axis2_char_t *password);


    /* @} */
#ifdef __cplusplus
}
#endif

#endif    /* !RAMPART_CRYPTO_UTIL */
