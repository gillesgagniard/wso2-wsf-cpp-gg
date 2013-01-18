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

#include <stdio.h>
#include <axis2_util.h>
#include <axis2_key_type.h>
#include <openssl_pkcs12_keystore.h>
#include <oxs_error.h>
#include <oxs_key_mgr.h>
#include <openssl_pem.h>
#include <oxs_utility.h>

struct oxs_key_mgr_t 
{
	/* Location of the private key file */
    axis2_char_t *private_key_file;
    
    /*Pasword of the private key */
    axis2_char_t *prv_key_password;
    
    /*Location of the cert file of the private key owner */
    axis2_char_t *certificate_file;
    
    /*Location of the cert file of the user at the other end */
    axis2_char_t *reciever_certificate_file;
    
    /* Priate key */
    void *prv_key;
    
    /*Type of the private key */
    axis2_key_type_t prv_key_type;
    
    /*Owner certificate */
    void *certificate;
    
    /* type of the certificate */
    axis2_key_type_t certificate_type;
    
    /*Certificate of the enityt at the other end*/
    void *receiver_certificate;
    
    /*Type of Certificate at the other end*/
    axis2_key_type_t receiver_certificate_type;

    /* PKCS12 Key store */
    pkcs12_keystore_t *key_store;
    
    void *pkcs12_buf;
    
    int pkcs12_buff_len;
	
    /* Buffer holding keys and certs */
    void *pem_buf;
	
    /* Format of the current key */
    oxs_key_mgr_format_t format;

    /* ref count to monitor when to free */
    int ref;
}; 

AXIS2_EXTERN oxs_key_mgr_t * AXIS2_CALL
oxs_key_mgr_create(const axutil_env_t *env)
{
	oxs_key_mgr_t *key_mgr = NULL;    
	key_mgr = AXIS2_MALLOC(env->allocator, sizeof(oxs_key_mgr_t));
	if (key_mgr)
	{
            key_mgr->private_key_file = NULL;		
            key_mgr->certificate_file = NULL;
            key_mgr->reciever_certificate_file = NULL;
            key_mgr->prv_key_password = NULL;
            key_mgr->prv_key = NULL;
            key_mgr->prv_key_type = AXIS2_KEY_TYPE_UNKNOWN;
            key_mgr->certificate = NULL;
            key_mgr->certificate_type = AXIS2_KEY_TYPE_UNKNOWN;
            key_mgr->receiver_certificate = NULL;
            key_mgr->receiver_certificate_type = AXIS2_KEY_TYPE_UNKNOWN;
            key_mgr->key_store = NULL;                
            key_mgr->pem_buf = NULL;
            key_mgr->format = -1;
            key_mgr->pkcs12_buf = NULL;
            key_mgr->ref = 1;
	}
	return key_mgr; 
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_free(oxs_key_mgr_t *key_mgr, const axutil_env_t *env)
{
    if(--(key_mgr->ref) < 1)
    {
        if(key_mgr->certificate)
	    {
            if(key_mgr->certificate_type == AXIS2_KEY_TYPE_PEM)
            {
                AXIS2_FREE(env->allocator, key_mgr->certificate);
            }
            else
            {
                oxs_x509_cert_free(key_mgr->certificate, env);
            }
            key_mgr->certificate = NULL;
        }
        if(key_mgr->receiver_certificate)
	    {
            if(key_mgr->receiver_certificate_type == AXIS2_KEY_TYPE_PEM)
            {
                AXIS2_FREE(env->allocator, key_mgr->receiver_certificate);
            }
            else
            {
                oxs_x509_cert_free(key_mgr->receiver_certificate, env);
            }
            key_mgr->receiver_certificate = NULL;
        }
        /*if(key_mgr->prv_key)
	    {
            if(key_mgr->prv_key_type== AXIS2_KEY_TYPE_PEM)
            {
                AXIS2_FREE(env->allocator, key_mgr->prv_key);
            }
            else
            {
                openssl_pkey_free(key_mgr->prv_key, env);
            }
            key_mgr->receiver_certificate = NULL;
        }*/

        AXIS2_FREE(env->allocator, key_mgr);
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN pkcs12_keystore_t* AXIS2_CALL
oxs_key_mgr_get_key_store(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env)
{
	return key_mgr->key_store;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_mgr_get_prv_key_password(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->prv_key_password;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_prv_key_password(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_char_t *password)
{
    key_mgr->prv_key_password = password;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_mgr_get_private_key_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->private_key_file;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_mgr_get_certificate_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->certificate_file;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
oxs_key_mgr_get_reciever_certificate_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->reciever_certificate_file;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_private_key_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_char_t *file_name)
{
    key_mgr->private_key_file = file_name;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_certificate_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_char_t *file_name)
{
    key_mgr->certificate_file = file_name;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_reciever_certificate_file(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_char_t *file_name)
{
    key_mgr->reciever_certificate_file = file_name;
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN void *AXIS2_CALL
oxs_key_mgr_get_certificate(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	/*void *key_buf = NULL;*/
   /* axis2_key_type_t type = 0;*/
    oxs_x509_cert_t *cert = NULL;
    axis2_char_t *certificate_file = NULL;
    
    
	if (key_mgr->certificate)
	{
		if(key_mgr->certificate_type == AXIS2_KEY_TYPE_PEM)
		{
			cert = oxs_key_mgr_load_x509_cert_from_string(env, (axis2_char_t *)key_mgr->certificate);
			if(!cert)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature] Certificate cannot be loaded from the buffer.");
                return NULL;
            }
            else
            {
				key_mgr->certificate = cert;
                key_mgr->certificate_type = AXIS2_KEY_TYPE_CERT;
                return cert;
            }
		}
        else if(key_mgr->certificate_type == AXIS2_KEY_TYPE_CERT)
        {
            return key_mgr->certificate;
        }
		else 
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Key file type unknown.");
            return NULL;
		}		
	}
	
    certificate_file = oxs_key_mgr_get_certificate_file(key_mgr, env);
    if(certificate_file)
    {
        cert = oxs_key_mgr_load_x509_cert_from_pem_file(env, certificate_file);
        if(!cert)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Certificate cannot be loaded from the file.");
            return NULL;
        }
    }
	else if(oxs_key_mgr_get_key_store(key_mgr, env))
    {
    	cert = pkcs12_keystore_get_owner_certificate(key_mgr->key_store, env);
    	if(!cert)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Certificate cannot be loaded from the key store.");
            return NULL;
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Public key certificate file is not specified.");
        return NULL;
    }
   
	return cert;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
oxs_key_mgr_get_certificate_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->certificate_type;
}

AXIS2_EXTERN void * AXIS2_CALL
oxs_key_mgr_get_prv_key(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
    void *key_buf = NULL;
    openssl_pkey_t *prvkey = NULL;
	axis2_char_t *prv_key_file = NULL;
    axis2_char_t *password = NULL;    

    key_buf = key_mgr->prv_key;
    if(key_buf)
    {                 
        if(key_mgr->prv_key_type == AXIS2_KEY_TYPE_PEM)
        {
            prvkey = oxs_key_mgr_load_private_key_from_string( env, (axis2_char_t *)key_buf, NULL);
            if(!prvkey)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[oxs]Can't load the key from buffer");
                return NULL;
            }
            /*key_mgr->prv_key = prvkey;
            key_mgr->prv_key_type = AXIS2_KEY_TYPE_CERT;
        }
        else if(key_mgr->prv_key_type == AXIS2_KEY_TYPE_CERT)
        {
            prvkey = key_buf;*/
        }
		else 
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[oxs] Private key type is unknown.");
            return NULL;			
		}
    }
    else
    {   /*Buffer is null load from the file*/
        prv_key_file = key_mgr->private_key_file;
       
        /*Get the password to retrieve the key from key store*/
        password = key_mgr->prv_key_password;

        if(prv_key_file)
        {
	        if(oxs_util_get_format_by_file_extension(env, prv_key_file) ==OXS_ASYM_CTX_FORMAT_PEM)
	        {
	            prvkey = oxs_key_mgr_load_private_key_from_pem_file(env, prv_key_file, password);
	            if(!prvkey)
	            {
	                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                        "[oxs]Cannot load the private key from file.");
	                return NULL;
	            }
                /*key_mgr->prv_key = prvkey;
                key_mgr->prv_key_type = AXIS2_KEY_TYPE_CERT;*/
	        }  
        }
        else
        {
			if(key_mgr->key_store)
			{
        		prvkey =  pkcs12_keystore_get_owner_private_key(key_mgr->key_store, env);
			   	if(!prvkey)
            	{
        			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
        		                "[rampart][key_mgr] Cannot load the private key from pkcs12 key store.");
        			return NULL;
        		}
				key_mgr->prv_key_type = AXIS2_KEY_TYPE_PEM;
			}
			else
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
								"[rampart][key_mgr] Cannot find a way to load the private key.");
				return NULL;
			}
        }
    }
    return prvkey;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
oxs_key_mgr_get_prv_key_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->prv_key_type;
}

AXIS2_EXTERN void *AXIS2_CALL
oxs_key_mgr_get_receiver_certificate(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
    oxs_x509_cert_t *oxs_cert = NULL;  
	        
	if (key_mgr->receiver_certificate)
	{
		if(key_mgr->receiver_certificate_type == AXIS2_KEY_TYPE_PEM)
		{
			oxs_cert = oxs_key_mgr_load_x509_cert_from_string(env, (axis2_char_t *)key_mgr->receiver_certificate);
			if(!oxs_cert)
           	{
               	AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                               "[rampart][rampart_signature] Certificate cannot be loaded from the buffer.");
               	return NULL;
           	}
           	else
           	{
				key_mgr->receiver_certificate = oxs_cert;
                key_mgr->receiver_certificate_type = AXIS2_KEY_TYPE_CERT;
               	return oxs_cert;
           	}
		}
        else if(key_mgr->receiver_certificate_type == AXIS2_KEY_TYPE_CERT)
        {
            return key_mgr->receiver_certificate;
        }
		else
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                           "[rampart][rampart_signature] Key file type unknown.");
           	return NULL;
		}	
	}
	else
	{
		/* If user has specified the certificate/private key directly we will extract the information from it.
		 * Else we will look for a file name to load the certificate/private key*/
		if(key_mgr->reciever_certificate_file)
		{
			oxs_cert = oxs_key_mgr_load_x509_cert_from_pem_file(env, key_mgr->reciever_certificate_file);
            key_mgr->receiver_certificate = oxs_cert;
            key_mgr->receiver_certificate_type = AXIS2_KEY_TYPE_CERT;
		}
		else if(key_mgr->key_store)
		{
			oxs_cert = pkcs12_keystore_get_other_certificate(key_mgr->key_store, env);
		}
	}
	return oxs_cert;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
oxs_key_mgr_get_receiver_certificate_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
	return key_mgr->receiver_certificate_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_certificate(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env, 
	void *certificate)
{
	key_mgr->certificate = certificate;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_certificate_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_key_type_t type)
{
	key_mgr->certificate_type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_prv_key(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env, 
	void *key)
{
	key_mgr->prv_key = key;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_prv_key_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_key_type_t type)
{
	key_mgr->prv_key_type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_receiver_certificate(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	void *certificate)
{
	key_mgr->receiver_certificate = certificate;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_receiver_certificate_type(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
	axis2_key_type_t type)
{
	key_mgr->receiver_certificate_type = type;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_key_mgr_format_t AXIS2_CALL
oxs_key_mgr_get_format(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env)
{
	return key_mgr->format;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_format(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env,
	oxs_key_mgr_format_t format)
{
	key_mgr->format = format;
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN void * AXIS2_CALL
oxs_key_mgr_get_pem_buf(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env)
{
	return key_mgr->pem_buf;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_pem_buf(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env,
	void *pem_buf)
{
	key_mgr->pem_buf = pem_buf;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_key_store(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env,
	pkcs12_keystore_t *key_store)
{
	key_mgr->key_store = key_store;
	return AXIS2_SUCCESS;
}

#if 0
/**
 * Loads the key
 * 1. If the key buffer is specified, Take that as the source.
 * 2. Else if the key file name has specified, Take that as the source.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_load_key(
	oxs_key_mgr_t *key_mgr,
	const axutil_env_t *env,
    oxs_asym_ctx_t *ctx)
{
    axis2_char_t *filename = NULL;
    axis2_char_t *pem_buf = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    openssl_x509_format_t format;
    openssl_pkey_t *open_prvkey = NULL;
    openssl_pkey_t *open_pubkey = NULL;
    oxs_x509_cert_t *oxs_cert = NULL;

    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    EVP_PKEY *prvkey = NULL;
    EVP_PKEY *pubkey = NULL;

    /* If user has specified the certificate/private key directly we will extract the information from it.
     * Else we will look for a file name to load the certificate/private key*/
    pem_buf = oxs_key_mgr_get_pem_buf(key_mgr, env);
    if(pem_buf)
    {
        if( OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT == oxs_asym_ctx_get_operation(ctx, env) ||
                OXS_ASYM_CTX_OPERATION_PUB_DECRYPT == oxs_asym_ctx_get_operation(ctx, env))
        {

            /*load certificate from buf*/
            status = openssl_x509_load_from_buffer(env, pem_buf, &cert);
        }
        else
        {
            /*load private key from buf*/
            status = openssl_pem_buf_read_pkey(env, pem_buf, key_mgr->prv_key_password, OPENSSL_PEM_PKEY_TYPE_PRIVATE_KEY, &prvkey);
            if(status == AXIS2_FAILURE)
            {
                prvkey = NULL;
            }
        }
    }
    else
    {
        oxs_asym_ctx_operation_t operation = oxs_asym_ctx_get_operation(ctx, env);
        if((operation == OXS_ASYM_CTX_OPERATION_PRV_DECRYPT) || (operation == OXS_ASYM_CTX_OPERATION_PRV_ENCRYPT))
        {
	        filename = oxs_key_mgr_get_private_key_file(key_mgr, env);
        } 
        else if(operation == OXS_ASYM_CTX_OPERATION_PUB_DECRYPT) 
        {
            filename = oxs_key_mgr_get_reciever_certificate_file(key_mgr, env);
        }
        else if(operation == OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT)
        {
            filename = oxs_key_mgr_get_reciever_certificate_file(key_mgr, env);
        }       
        /* pem_buf is NULL. So we have to fetch the key in a file*/
        /* Get file to be loaded. Can be either in PEM or PKCS12 format*/        
        if(!filename){
            return AXIS2_FAILURE;
        }

        if(OXS_ASYM_CTX_FORMAT_PEM == oxs_key_mgr_get_format(key_mgr, env)){            
            format = OPENSSL_X509_FORMAT_PEM;


            /*First let's check if this is a file containing a certificate*/
            status = openssl_x509_load_from_pem(env, filename,  &cert);

            if((status == AXIS2_FAILURE) || (!cert)){

                /* If we cannot get the certificate then the file might contain either a public key or a private key*/
                /* The type depends on the operation*/
                operation = oxs_asym_ctx_get_operation(ctx, env);

                if((operation == OXS_ASYM_CTX_OPERATION_PRV_DECRYPT) || (operation == OXS_ASYM_CTX_OPERATION_PRV_ENCRYPT)){
                    status = openssl_pem_read_pkey(env, filename, key_mgr->prv_key_password, OPENSSL_PEM_PKEY_TYPE_PRIVATE_KEY, &prvkey);
                    if(status == AXIS2_FAILURE){
                        prvkey = NULL;
                    }
                } else if((operation == OXS_ASYM_CTX_OPERATION_PUB_DECRYPT) || (operation == OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT)){
                    status = openssl_pem_read_pkey(env, filename, key_mgr->prv_key_password, OPENSSL_PEM_PKEY_TYPE_PUBLIC_KEY, &pubkey);
                    if(status == AXIS2_FAILURE){
                        pubkey = NULL;
                    }
                }
            }
        }else if(OXS_ASYM_CTX_FORMAT_PKCS12 == oxs_key_mgr_get_format(key_mgr, env)){
            format = OPENSSL_X509_FORMAT_PKCS12;

            /* Here we load both key and the certificate*/
            status = openssl_x509_load_from_pkcs12(env, filename, key_mgr->prv_key_password, &cert, &prvkey, &ca);
            if(AXIS2_FAILURE == status){
                oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                          "Error reading the certificate");
                return AXIS2_FAILURE;
            }
        }

    }/*end of pem_buf*/

    /*Wht ever the way, right now we should have either the public key or the private key*/
    /*If the prvkey is available, populate the openssl_pkey*/
    if(prvkey){
        open_prvkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_prvkey, env, prvkey, filename, OPENSSL_PKEY_TYPE_PRIVATE_KEY);
        oxs_asym_ctx_set_private_key(ctx, env, open_prvkey);
    }

    /*If the public key is available populate*/
    if(pubkey){

        /*This scenario is not recommonded. This will be executed iff the file is a public key file in PEM format*/
        open_pubkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_pubkey, env, pubkey, filename, OPENSSL_PKEY_TYPE_PUBLIC_KEY);
        oxs_cert = oxs_x509_cert_create(env);
        oxs_x509_cert_set_public_key(oxs_cert, env, open_pubkey);
        oxs_asym_ctx_set_certificate(ctx, env, oxs_cert);
    }

    /*If the X509 certificate is available, populate oxs_x509_cert*/
    if(cert){
        axis2_char_t *x509_cert_data = NULL;
		axis2_char_t *x509_cert_date = NULL;
		axis2_char_t *x509_cert_issuer = NULL;
		axis2_char_t *x509_cert_subject = NULL;
		axis2_char_t *x509_cert_finger = NULL;
		axis2_char_t *x509_cert_key_id = NULL;
		axis2_char_t *x509_common_name = NULL;

        x509_cert_data = openssl_x509_get_cert_data(env, cert);
		x509_cert_date = openssl_x509_get_info(env, OPENSSL_X509_INFO_VALID_TO ,cert);
		x509_cert_issuer = openssl_x509_get_info(env, OPENSSL_X509_INFO_ISSUER ,cert);
		x509_cert_subject = openssl_x509_get_info(env, OPENSSL_X509_INFO_SUBJECT ,cert);
		x509_cert_finger = openssl_x509_get_info(env, OPENSSL_X509_INFO_FINGER,cert);
		x509_cert_key_id = openssl_x509_get_subject_key_identifier(env, cert);
		x509_common_name = openssl_x509_get_common_name(env,cert);

        /*Create certificate*/
        oxs_cert = oxs_x509_cert_create(env);

        /*And populate it*/
        oxs_x509_cert_set_data(oxs_cert, env, x509_cert_data);
        oxs_x509_cert_set_date(oxs_cert, env, x509_cert_date);
        oxs_x509_cert_set_issuer(oxs_cert, env, x509_cert_issuer);
        oxs_x509_cert_set_subject(oxs_cert, env, x509_cert_subject);
        oxs_x509_cert_set_fingerprint(oxs_cert, env, x509_cert_finger);
        oxs_x509_cert_set_serial_number(oxs_cert, env, openssl_x509_get_serial(env, cert));
        oxs_x509_cert_set_key_identifier(oxs_cert, env, x509_cert_key_id);
        oxs_x509_cert_set_common_name(oxs_cert, env, x509_common_name);

        /*Additionally we need to set the public key*/
        openssl_x509_get_pubkey(env, cert, &pubkey);
        open_pubkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_pubkey, env, pubkey, x509_cert_finger, OPENSSL_PKEY_TYPE_PUBLIC_KEY);
        /*Set the public key to the x509 certificate*/
        oxs_x509_cert_set_public_key(oxs_cert, env, open_pubkey);

        /*Set the x509 certificate to the asym ctx*/
        oxs_asym_ctx_set_certificate(ctx, env, oxs_cert);

        AXIS2_FREE(env->allocator, x509_cert_data);
        x509_cert_data = NULL;
		AXIS2_FREE(env->allocator, x509_cert_date);
        x509_cert_date = NULL;
		AXIS2_FREE(env->allocator, x509_cert_issuer);
        x509_cert_issuer = NULL;
		AXIS2_FREE(env->allocator, x509_cert_subject);
        x509_cert_subject = NULL;
		AXIS2_FREE(env->allocator, x509_cert_finger);
        x509_cert_finger = NULL;
		AXIS2_FREE(env->allocator, x509_cert_key_id);
        x509_cert_key_id = NULL;
        AXIS2_FREE(env->allocator, x509_common_name);
        x509_common_name = NULL;

		X509_free(cert);
        cert = NULL;
    }

    /*If this fails to get anything return failure*/
    if((!cert) && (!pubkey) && (!prvkey)){
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                  "Error reading the key");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

/********************************************************************************************/
/*These are new set of functions that break-up the complex logic in oxs_key_mgr_load_key()*/
#endif

AXIS2_EXTERN openssl_pkey_t* AXIS2_CALL
oxs_key_mgr_load_private_key_from_string(const axutil_env_t *env,
        axis2_char_t *pem_string, /*in PEM format*/
        axis2_char_t *password)
{
    openssl_pkey_t *open_prvkey = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    EVP_PKEY *prvkey = NULL;

    /*load private key from buf*/
    status = openssl_pem_buf_read_pkey(env, pem_string, password, OPENSSL_PEM_PKEY_TYPE_PRIVATE_KEY, &prvkey);

    /*Populate*/
    if(prvkey){
        open_prvkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_prvkey, env, prvkey, NULL, OPENSSL_PKEY_TYPE_PRIVATE_KEY);
    }else{
        return NULL;
    }

    return open_prvkey;
}

AXIS2_EXTERN openssl_pkey_t* AXIS2_CALL
oxs_key_mgr_load_private_key_from_pem_file(
		const axutil_env_t *env,
        axis2_char_t *filename,
        axis2_char_t *password)
{
    openssl_pkey_t *open_prvkey = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    EVP_PKEY *prvkey = NULL;

    /*Read EVP_PKEY*/
    status = openssl_pem_read_pkey(env, filename, password, OPENSSL_PEM_PKEY_TYPE_PRIVATE_KEY, &prvkey);

    /*Populate*/
    if(prvkey){
        open_prvkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_prvkey, env, prvkey, filename, OPENSSL_PKEY_TYPE_PRIVATE_KEY);
    }else{
        return NULL;
    }

    return open_prvkey;
}

/*Private function to convert X509* -> oxs_x509_cert_t* */
static oxs_x509_cert_t*
oxs_key_mgr_convert_to_x509(const axutil_env_t *env,
                            X509 *cert)
{
    oxs_x509_cert_t *oxs_cert = NULL;

    if(cert){
        EVP_PKEY *pubkey = NULL;
        openssl_pkey_t *open_pubkey = NULL;
        axis2_char_t *x509_cert_data = NULL;
		axis2_char_t *x509_cert_date = NULL;
		axis2_char_t *x509_cert_issuer = NULL;
		axis2_char_t *x509_cert_subject = NULL;
		axis2_char_t *x509_cert_fingerprint = NULL;
		axis2_char_t *x509_cert_key_id = NULL;
		axis2_char_t *x509_common_name = NULL;

        x509_cert_data = openssl_x509_get_cert_data(env, cert);
		x509_cert_date = openssl_x509_get_info(env, OPENSSL_X509_INFO_VALID_TO ,cert);
		x509_cert_issuer = openssl_x509_get_info(env, OPENSSL_X509_INFO_ISSUER ,cert);
		x509_cert_subject = openssl_x509_get_info(env, OPENSSL_X509_INFO_SUBJECT ,cert);
		x509_cert_fingerprint = openssl_x509_get_info(env, OPENSSL_X509_INFO_FINGER,cert);
		x509_cert_key_id = openssl_x509_get_subject_key_identifier(env, cert);
		x509_common_name = openssl_x509_get_common_name(env,cert);

        /*Create X509 certificate*/
        oxs_cert = oxs_x509_cert_create(env);
        oxs_x509_cert_set_data(oxs_cert, env, x509_cert_data);
        oxs_x509_cert_set_date(oxs_cert, env, x509_cert_date);
        oxs_x509_cert_set_issuer(oxs_cert, env, x509_cert_issuer);
        oxs_x509_cert_set_subject(oxs_cert, env, x509_cert_subject);
        oxs_x509_cert_set_fingerprint(oxs_cert, env, x509_cert_fingerprint);
        oxs_x509_cert_set_serial_number(oxs_cert, env, openssl_x509_get_serial(env, cert));
        oxs_x509_cert_set_key_identifier(oxs_cert, env, x509_cert_key_id);
        oxs_x509_cert_set_common_name(oxs_cert, env, x509_common_name);

        /*Additionally we need to set the public key*/
        openssl_x509_get_pubkey(env, cert, &pubkey);
        open_pubkey = openssl_pkey_create(env);
        openssl_pkey_populate(open_pubkey, env, pubkey,
                              x509_cert_fingerprint,
                              OPENSSL_PKEY_TYPE_PUBLIC_KEY);

        /*Set the public key to the x509 certificate*/
        oxs_x509_cert_set_public_key(oxs_cert, env, open_pubkey);

        /*Free*/
        AXIS2_FREE(env->allocator, x509_cert_data);
        x509_cert_data = NULL;
		AXIS2_FREE(env->allocator, x509_cert_date);
        x509_cert_date = NULL;
		AXIS2_FREE(env->allocator, x509_cert_issuer);
        x509_cert_issuer = NULL;
		AXIS2_FREE(env->allocator, x509_cert_subject);
        x509_cert_subject = NULL;
		AXIS2_FREE(env->allocator, x509_cert_fingerprint);
        x509_cert_fingerprint = NULL;
		AXIS2_FREE(env->allocator, x509_cert_key_id);
        x509_cert_key_id = NULL;
        AXIS2_FREE(env->allocator, x509_common_name);
        x509_common_name = NULL;
        /*Free the certificate*/
        X509_free(cert);
        cert = NULL;
    }

    return oxs_cert;
}

AXIS2_EXTERN oxs_x509_cert_t* AXIS2_CALL
oxs_key_mgr_load_x509_cert_from_pem_file(const axutil_env_t *env,
        axis2_char_t *filename)
{
    X509 *cert = NULL;
    oxs_x509_cert_t *oxs_cert = NULL;

    openssl_x509_load_from_pem(env, filename,  &cert);
    oxs_cert = oxs_key_mgr_convert_to_x509(env, cert);
    return oxs_cert;
}

AXIS2_EXTERN oxs_x509_cert_t* AXIS2_CALL
oxs_key_mgr_load_x509_cert_from_string(const axutil_env_t *env,
                                       axis2_char_t *pem_string)
{
    X509 *cert = NULL;
    oxs_x509_cert_t *oxs_cert = NULL;

    openssl_x509_load_from_buffer(env, pem_string, &cert);
    oxs_cert = oxs_key_mgr_convert_to_x509(env, cert);

    return oxs_cert;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_read_pkcs12_key_store(const axutil_env_t *env,
                                  axis2_char_t *filename,
                                  axis2_char_t *password,
                                  oxs_x509_cert_t **cert,
                                  openssl_pkey_t **prv_key)
{
    X509 *c = NULL;
    STACK_OF(X509) *ca = NULL;
    EVP_PKEY *pkey = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    status = openssl_x509_load_from_pkcs12(env, filename, password, &c, &pkey, &ca);
    if(AXIS2_FAILURE == status){
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                  "Error reading the PKCS12 Key Store");
        return AXIS2_FAILURE;
    }
    if(*prv_key){
        if(pkey){
            *prv_key = openssl_pkey_create(env);
            openssl_pkey_populate(*prv_key, env, pkey, filename, OPENSSL_PKEY_TYPE_PRIVATE_KEY);
        }
    }

    if(*cert){
        if(c){
            *cert = oxs_key_mgr_convert_to_x509(env, c);
        }
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void * AXIS2_CALL
oxs_key_mgr_get_key_store_buff(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env)
{
    return key_mgr->pkcs12_buf;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_key_mgr_get_key_store_buff_len(
            oxs_key_mgr_t *key_mgr,
            const axutil_env_t *env)
{
        return key_mgr->pkcs12_buff_len;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_set_key_store_buff(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
    void *key_store_buf,
    int len)
{
    AXIS2_PARAM_CHECK(env->error, key_store_buf, AXIS2_FAILURE);
        
    key_mgr->pkcs12_buf = key_store_buf;
    key_mgr->pkcs12_buff_len = len;
    
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL
oxs_key_mgr_get_receiver_certificate_from_ski(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
    axis2_char_t *ski)
{
    AXIS2_PARAM_CHECK(env->error, ski, NULL);
    
    if(key_mgr->key_store)
    {
        return pkcs12_keystore_get_certificate_for_subject_key_id(key_mgr->key_store, env, ski);
    }
    
    return NULL;
}

AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL
oxs_key_mgr_get_receiver_certificate_from_issuer_serial(
    oxs_key_mgr_t *key_mgr,
    const axutil_env_t *env,
    axis2_char_t *issuer,
    int serial)
{
    AXIS2_PARAM_CHECK(env->error, issuer, NULL);
    AXIS2_PARAM_CHECK(env->error, serial, NULL)
    
    if(key_mgr->key_store)
        return pkcs12_keystore_get_certificate_for_issuer_serial(key_mgr->key_store, env, issuer, serial);
    
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_key_mgr_increment_ref(
    oxs_key_mgr_t *key_mgr, 
    const axutil_env_t *env)
{
    key_mgr->ref++;
    return AXIS2_SUCCESS;
}
