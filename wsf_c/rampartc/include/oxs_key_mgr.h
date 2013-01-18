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

#ifndef OXS_KEY_MGR_H
#define OXS_KEY_MGR_H


/**
  * @file oxs_key_mgr.h
  * @brief the Key Manager responsible for loading keys for OMXMLSecurity
  */

/**
* @defgroup oxs_key_mgr Key Manager
* @ingroup oxs
* @{
*/
#include <axis2_defines.h>
#include <oxs_ctx.h>
#include <oxs_asym_ctx.h>
#include <axutil_env.h>
#include <axutil_qname.h>
#include <oxs_x509_cert.h>
#include <openssl_pkey.h>
#include <openssl_x509.h>
#include <openssl_pkcs12.h>
#include <axis2_key_type.h>
#include <openssl_pkcs12.h>
#include <openssl_pkcs12_keystore.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct oxs_key_mgr_t oxs_key_mgr_t;
	/* Enum which is used to specify the key format. */
	typedef enum  {
	        OXS_KEY_MGR_FORMAT_UNKNOWN=0,
	        OXS_KEY_MGR_FORMAT_PEM,
	        OXS_KEY_MGR_FORMAT_PKCS12
	}oxs_key_mgr_format_t;
	
#if 0
    /**
     * Loads keys/certificates from a keystore or a PEm file depending on information available in the @ctx
     * @ctx pointer to the OMXMLSec asymmetric encryption context struct
     * @env pointer to environment struct
     * @password the password for the key store
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE	
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_load_key(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
	    oxs_asym_ctx_t *ctx);

#endif

    /**
     * Loads a private key from a string buffer @pem_buf which of PEM format.
     * -----BEGIN RSA PRIVATE KEY-----
     *  @pem_buf
     *  -----END RSA PRIVATE KEY-----
     * @env pointer to environment struct
     * @pem_buf the string buffer which of PEM format
     * @password the password for the key file
     * @return the generated key
     */
    AXIS2_EXTERN openssl_pkey_t* AXIS2_CALL
    oxs_key_mgr_load_private_key_from_string(const axutil_env_t *env,
            axis2_char_t *pem_buf, /*in PEM format*/
            axis2_char_t *password);
    /**
     * Loads a private key from a file (in PEM format)
     *  @env pointer to environment struct
     *  @file_name the name of the file
     *  @password the passowrd for the file
     *  @return the generated key
     */
    AXIS2_EXTERN openssl_pkey_t* AXIS2_CALL
    oxs_key_mgr_load_private_key_from_pem_file(const axutil_env_t *env,
            axis2_char_t *file_name,
            axis2_char_t *password);

    /**
     * Loads an X509 certificate from a string buffer @pem_buf 
     * -----BEGIN CERTIFICATE-----
     *  @pem_buf
     * -----END CERTIFICATE-----
     * @env pointer to environment struct
     * @pem_buf PEM formatted string buffer
     * @return the generated X509 certificate
     */
    AXIS2_EXTERN oxs_x509_cert_t* AXIS2_CALL
    oxs_key_mgr_load_x509_cert_from_string(const axutil_env_t *env,
                                           axis2_char_t *pem_buf);

    /**
     * Loads an X509 certificate from a file
     * @env pointer to environment struct
     * @file_name the name of the file
     * @return the generated X509 certificate
     */
    AXIS2_EXTERN oxs_x509_cert_t* AXIS2_CALL
    oxs_key_mgr_load_x509_cert_from_pem_file(const axutil_env_t *env,
            axis2_char_t *filename);

    /**
     * Read a PKCS12 key store and populate a key and a certificate.
     * @env pointer to environment struct
     * @pkcs12_file name of the pkcs12 file
     * @password password for the key/certificate pair in the key store
     * @cert the certificate
     * @prv_key the private key
     * @return the generated X509 certificate
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_key_mgr_read_pkcs12_key_store(const axutil_env_t *env,
                                      axis2_char_t *pkcs12_file,
                                      axis2_char_t *password,
                                      oxs_x509_cert_t **cert,
                                      openssl_pkey_t **prv_key);
	
	/**
	 * Creates the key manager strucutre.
	 * @env pointer to environment struct
	 * @return pointer to the key manager (oxs_key_mgr_t *)
	 */
	AXIS2_EXTERN oxs_key_mgr_t * AXIS2_CALL
	oxs_key_mgr_create(const axutil_env_t *env);

	/**
	 * Free the key manager struct
	 * @key_mgr pointer to key manager struct which is going to free
	 * @env pointer to environment struct
	 * @return status of the free operation
	 */
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_free(oxs_key_mgr_t *key_mgr, 
					const axutil_env_t *env);
	
	/**
	 * Set the password used to encrypt the private key (if any)
	 * @key_mgr Pointer to key manager struct
	 * @env pointer to environment struct
	 * @password password used to encrypt the private key
	 * @return status of the operation
	 */
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_prv_key_password(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_char_t *password);

	/**
	 * Return the private key file password
	 * @key_mgr pointer to key manager struct
	 * @env pointer to environment struct
	 * @return password of the private key file
	 */
	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	oxs_key_mgr_get_prv_key_password(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	/**
	 * Returns the private key file location
	 * @key_mgr pointer to key manager struct
	 * @env pointer to environment struct
	 * @return location of the private key file
	 */
	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	oxs_key_mgr_get_private_key_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	oxs_key_mgr_get_certificate_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	oxs_key_mgr_get_reciever_certificate_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_private_key_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_char_t *file_name);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_certificate_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_char_t *file_name);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_reciever_certificate_file(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_char_t *file_name);


	AXIS2_EXTERN void *AXIS2_CALL
	oxs_key_mgr_get_certificate(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
	oxs_key_mgr_get_certificate_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN void *AXIS2_CALL
	oxs_key_mgr_get_prv_key(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
	oxs_key_mgr_get_prv_key_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN void *AXIS2_CALL
	oxs_key_mgr_get_receiver_certificate(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
	oxs_key_mgr_get_receiver_certificate_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_certificate(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env, 
		void *certificate);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_certificate_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_key_type_t type);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_prv_key(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env, 
		void *key);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_prv_key_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_key_type_t type);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_receiver_certificate(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		void *certificate);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_receiver_certificate_type(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		axis2_key_type_t type);
	
	AXIS2_EXTERN oxs_key_mgr_format_t AXIS2_CALL
	oxs_key_mgr_get_format(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_format(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		oxs_key_mgr_format_t format);

	AXIS2_EXTERN void * AXIS2_CALL
	oxs_key_mgr_get_pem_buf(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_pem_buf(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		void *pem_buf);
	
	AXIS2_EXTERN pkcs12_keystore_t* AXIS2_CALL
	oxs_key_mgr_get_key_store(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env);
	
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	oxs_key_mgr_set_key_store(
		oxs_key_mgr_t *key_mgr,
		const axutil_env_t *env,
		pkcs12_keystore_t *key_store);
        
        AXIS2_EXTERN void * AXIS2_CALL
        oxs_key_mgr_get_key_store_buff(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env);
        
        AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL
        oxs_key_mgr_get_receiver_certificate_from_ski(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env,
            axis2_char_t *ski);
        
        AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL
        oxs_key_mgr_get_receiver_certificate_from_issuer_serial(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env,
            axis2_char_t *issuer,
            int serial);
        
        AXIS2_EXTERN int AXIS2_CALL
        oxs_key_mgr_get_key_store_buff_len(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env);
        
        AXIS2_EXTERN axis2_status_t AXIS2_CALL
        oxs_key_mgr_set_key_store_buff(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env,
            void *key_store_buf,
            int len);

        AXIS2_EXTERN axis2_status_t AXIS2_CALL
        oxs_key_mgr_increment_ref(
            oxs_key_mgr_t *key_mgr, 
            const axutil_env_t *env);

	
    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* OXS_KEY_MGR_H */
