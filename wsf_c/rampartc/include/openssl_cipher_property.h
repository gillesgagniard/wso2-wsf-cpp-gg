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

#include<openssl/evp.h>
#include<oxs_buffer.h>

/**
  * @file openssl_cipher_property.h 
  * @brief The class to store cipher properties such as name, key size, block size etc
  */
#ifndef OPENSSL_CIPHER_PROPERTY_H
#define OPENSSL_CIPHER_PROPERTY_H

/**
 * @defgroup openssl_cipher_property OpenSSL Cipher Property
 * @ingroup openssl
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif


    /** Type name for struct  openssl_cipher_property */
    typedef struct openssl_cipher_property_t openssl_cipher_property_t;


    /**
     * Given the OpenSSL cipher property returns the cipher
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return the cipher 
     */
    EVP_CIPHER * AXIS2_CALL
    openssl_cipher_property_get_cipher(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Given the OpenSSL cipher property returns the name of the property
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return the name of the cipher property
     */
    axis2_char_t * AXIS2_CALL
    openssl_cipher_property_get_name(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Given the OpenSSL cipher property returns the URL
     * Which usually is an algorithm URL
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return the URL
     */
    axis2_char_t * AXIS2_CALL
    openssl_cipher_property_get_url(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Given the OpenSSL cipher property returns the size of the key
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return size of the key
     */
    int AXIS2_CALL
    openssl_cipher_property_get_key_size(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Given the OpenSSL cipher property returns the cipher block size 
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return the block size of the cipher
     */
    int AXIS2_CALL
    openssl_cipher_property_get_block_size(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Given the OpenSSL cipher property returns the size of the initial vector
     * @param cprop The OpenSSL cipher property 
     * @param env pointer to environment struct
     * @return the size of the initial vector 
     */
    int AXIS2_CALL
    openssl_cipher_property_get_iv_size(
        const openssl_cipher_property_t *cprop,
        const axutil_env_t *env);

    /**
     * Set the Cipher for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param cipher The cipher to be set in the property 
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_cipher(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        EVP_CIPHER *cipher);

    /**
     * Set the name for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param name of the OpenSSL cipher property
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_name(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        axis2_char_t *name);

    /**
     * Set the url for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param url The URL of the OpenSSL cipher property
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_url(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        axis2_char_t *url);

    /**
     * Set the the size of the key for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param key_size the size of the key 
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_key_size(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        int   key_size);


    /**
     * Set the size of the cipher block for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param block_size the size of the cipher block
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_block_size(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        int  block_size);

    /**
     * Set the size of the initial vector for the OpenSSL cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @param iv_size the size of the initial vector 
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_set_iv_size(
        openssl_cipher_property_t *cprop,
        const axutil_env_t *env,
        int   iv_size);

    /**
     * Free the cipher property
     * @param cprop The OpenSSL cipher property
     * @param env pointer to environment struct
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    openssl_cipher_property_free(openssl_cipher_property_t * cprop, 
        const axutil_env_t *env);


    /**
    * Create a fresh block cipher property
    * @param env pointer to environment struct
    * @return cipher_prop_ptr
    */
    AXIS2_EXTERN openssl_cipher_property_t *AXIS2_CALL
    openssl_cipher_property_create(const axutil_env_t *env);

    /** @} */

#ifdef __cplusplus
}
#endif

#endif    /* OPENSSL_CIPHER_PROPERTY_H */
