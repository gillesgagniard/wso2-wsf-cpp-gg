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

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl_constants.h>
#include <openssl_pkey.h>
#include <axis2_util.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_pkcs12.h>
#include <oxs_error.h>
#include <oxs_x509_cert.h>
#include <openssl_pkey.h>
#include <openssl_x509.h>


/**
  * @file openssl_pkcs12_keystore.h 
  * @brief Key Store manager for keys that are in pkcs12 format
  */
#ifndef OPENSSL_PKCS12_KEYSTORE_H
#define OPENSSL_PKCS12_KEYSTORE_H

#ifdef __cplusplus
extern "C" {
#endif
    
    typedef struct pkcs12_keystore pkcs12_keystore_t;
    
    AXIS2_EXTERN pkcs12_keystore_t * AXIS2_CALL pkcs12_keystore_create(
        const axutil_env_t *env, 
        axis2_char_t *filename, 
        axis2_char_t *password);
    
    AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL pkcs12_keystore_populate_cert_array(
        const axutil_env_t *env,
        STACK_OF(X509) *other_certs);
    
    oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_populate_oxs_cert(
        const axutil_env_t *env, 
        X509 *cert_in);
    
    AXIS2_EXTERN openssl_pkey_t * AXIS2_CALL pkcs12_keystore_get_owner_private_key(
        pkcs12_keystore_t *keystore,
        const axutil_env_t *env);
    
    AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_owner_certificate(
        pkcs12_keystore_t *keystore, 
        const axutil_env_t *env);
    
    AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_issuer_serial(
        pkcs12_keystore_t *keystore,
        const axutil_env_t *env,
        axis2_char_t *issuer,
        int serial_number);
    
    AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_thumbprint(
        pkcs12_keystore_t *keystore, 
        const axutil_env_t *env, 
        axis2_char_t *thumbprint);
    
    AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_subject_key_id(
        pkcs12_keystore_t *keystore,
        const axutil_env_t *env,
        axis2_char_t *ski);

    AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL 
    pkcs12_keystore_get_other_certificate(
    	pkcs12_keystore_t *keystore,
    	const axutil_env_t *env);
     
    AXIS2_EXTERN pkcs12_keystore_t * AXIS2_CALL
    pkcs12_keystore_create_from_buffer(
        const axutil_env_t *env,
        axis2_char_t *buffer,
        axis2_char_t *password,
        int len);

    AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
	pkcs12_keystore_get_keystore_file(
		pkcs12_keystore_t* keystore);

	AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
	pkcs12_keystore_get_password(
		pkcs12_keystore_t* keystore);
    
	AXIS2_EXTERN PKCS12* AXIS2_CALL 
	pkcs12_keystore_get_keystore(
		pkcs12_keystore_t* keystore);

	AXIS2_EXTERN X509* AXIS2_CALL 
	pkcs12_keystore_get_cert(
		pkcs12_keystore_t* keystore);
    
    AXIS2_EXTERN STACK_OF(X509)* AXIS2_CALL 
	pkcs12_keystore_get_other_certs(
		pkcs12_keystore_t* keystore);

	AXIS2_EXTERN openssl_pkey_t* AXIS2_CALL 
	pkcs12_keystore_get_pvt_key(
		pkcs12_keystore_t* keystore);    
        
#ifdef __cplusplus
}
#endif

#endif    /* OPENSSL_PKCS12_KEYSTORE_H */
