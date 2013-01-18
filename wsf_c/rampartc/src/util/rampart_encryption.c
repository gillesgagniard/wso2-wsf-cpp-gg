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
#include <axutil_utils.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <rampart_encryption.h>
#include <oxs_key.h>
#include <rampart_constants.h>
#include <rampart_handler_util.h>
#include <oxs_tokens.h>
#include <axutil_array_list.h>
#include <oxs_axiom.h>
#include <oxs_asym_ctx.h>
#include <oxs_xml_encryption.h>
#include <oxs_derivation.h>
#include <axis2_key_type.h>
#include <oxs_derivation.h>
#include <rampart_sct_provider_utility.h>
#include <axiom_util.h>

static axis2_status_t AXIS2_CALL
rampart_enc_get_nodes_to_encrypt(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt)
{
    axis2_status_t status1 = AXIS2_SUCCESS;
    axis2_status_t status2 = AXIS2_SUCCESS;
    
    status1 = rampart_context_get_nodes_to_encrypt(
        rampart_context, env, soap_envelope, nodes_to_encrypt);

    status2 = rampart_context_get_elements_to_encrypt(
        rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status1 == AXIS2_SUCCESS || status2 == AXIS2_SUCCESS)
    {
        return AXIS2_SUCCESS;
    }
    else
    {
        return AXIS2_FAILURE;
    }
}

/**
 * Encrypts the session key using assymmetric encription
 * @param env pointer to environment struct
 * @param session_key the session key to be encrypted
 * @param msg_ctx message context
 * @param rampart_context the rampart context
 * @param sec_node The security element
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_session_key(
    const axutil_env_t *env,
    oxs_key_t *session_key,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_node_t *sec_node,
    axutil_array_list_t *id_list)
{
    oxs_asym_ctx_t *asym_ctx = NULL;	
    axis2_char_t *enc_asym_algo = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    axis2_char_t *eki = NULL;
	oxs_x509_cert_t *certificate = NULL; 
    
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_TRUE, server_side, AXIS2_FALSE);
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Specified token type not supported.");
        return AXIS2_FAILURE;
    }
    
    /* Get the asymmetric key encryption algorithm */
    enc_asym_algo = rampart_context_get_enc_asym_algo(rampart_context, env);
 
    /* Get encryption key identifier. This identifier depends on whether we include the token in 
     * the message. */
    if(rampart_context_is_token_include(
        rampart_context, token, token_type, server_side, AXIS2_FALSE, env))
    {
        eki = RAMPART_STR_DIRECT_REFERENCE;
    }
    else
    {
        eki = rampart_context_get_key_identifier(rampart_context, token, env);
    }

    if(!eki)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] No mechanism for attaching the certificate information.");
        return AXIS2_FAILURE;
    }

    /* Receiver certificate can be in the received message. In that case, we should use it. 
       If it is not there, then can get from key manager */
    if(rampart_context_get_found_cert_in_shp(rampart_context, env))
    {
        certificate = rampart_context_get_receiver_cert_found_in_shp(rampart_context, env);
    }
    else
    {
        oxs_key_mgr_t *key_mgr = NULL;
        key_mgr = rampart_context_get_key_mgr(rampart_context, env);
        certificate = oxs_key_mgr_get_receiver_certificate(key_mgr, env);
    }

    if (!certificate)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] Receiver certificate cannot be loaded.");
        return AXIS2_FAILURE;
    }

    /* Create asymmetric encryption context and populate algorithm, certificate etc. */
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, enc_asym_algo);
    oxs_asym_ctx_set_certificate(asym_ctx, env, certificate);
    oxs_asym_ctx_set_operation(asym_ctx, env,OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT);
    oxs_asym_ctx_set_st_ref_pattern(asym_ctx, env, eki);

    /* Encrypt the session key */
    status = oxs_xml_enc_encrypt_key(env, asym_ctx, sec_node, session_key, id_list);
    oxs_asym_ctx_free(asym_ctx, env);
    asym_ctx = NULL;
    
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] Session key encryption failed.");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

/**
 * Encrypt the message using derived keys. Uses symmetric encryption
 * @param env pointer to environment struct
 * @param msg_ctx message context
 * @param rampart_context rampart context
 * @param soap_envelope the SOAP envelope
 * @param sec_node The security element
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_dk_encrypt_message(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{
    axis2_status_t status = AXIS2_FAILURE;
    oxs_key_t *session_key = NULL;
    axutil_array_list_t *nodes_to_encrypt = NULL;
    axutil_array_list_t *id_list = NULL;
    axutil_array_list_t *dk_list = NULL;
    axis2_char_t *enc_sym_algo = NULL;
    axis2_char_t *asym_key_id = NULL;
	axis2_bool_t free_asym_key_id = AXIS2_FALSE;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *key_reference_node = NULL;
    axiom_node_t *sig_node = NULL;
    axiom_node_t *data_ref_list_node = NULL;
    axis2_bool_t use_derived_keys = AXIS2_TRUE;
    axis2_char_t *derived_key_version = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    rampart_saml_token_t *saml = NULL;
    oxs_key_t *derived_key = NULL;
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *body_child_node = NULL;

    axis2_bool_t signature_protection = AXIS2_FALSE;
    int i = 0;
    int j = 0;

    body = axiom_soap_envelope_get_body(soap_envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);
    body_child_node = axiom_node_get_first_element(body_node, env);

    /* Get nodes to be encrypted */
    nodes_to_encrypt = axutil_array_list_create(env, 0);
    status = rampart_enc_get_nodes_to_encrypt(
        rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error occured in Adding Encrypted parts.");
        axutil_array_list_free(nodes_to_encrypt, env);
        nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }
    
    /* If the sp:EncryptSignature is ON  &&  We sign before the encryption, 
     * we need to add signature node too. */
    signature_protection = rampart_context_is_encrypt_signature(rampart_context, env);

    /* if nothing to encrypt, then we can return successfully */
    if((axutil_array_list_size(nodes_to_encrypt, env)==0))
    {
        if(!signature_protection)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
                "[rampart]No parts specified or specified parts can't be found for encryprion.");
			axutil_array_list_free(nodes_to_encrypt, env);
			nodes_to_encrypt = NULL;
            return AXIS2_SUCCESS;
        }
    }

    if(signature_protection)
    {
        if(!(rampart_context_is_encrypt_before_sign(rampart_context, env)))
        {
            /*Sign->Encrypt. Easy. just add the signature node to the list*/
            sig_node = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_SIGNATURE);
            if(!sig_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Sigature Not found");
                return AXIS2_FAILURE;
            }
            axutil_array_list_add(nodes_to_encrypt, env, sig_node);

            if(rampart_context_is_sig_confirmation_reqd(rampart_context, env))
            {
                axiom_node_t* cur_node = NULL;
                cur_node = axiom_node_get_first_child(sec_node, env);
                while(cur_node)
                {
                    axis2_char_t *cur_local_name = NULL;
                    cur_local_name = axiom_util_get_localname(cur_node, env);

                    if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE_CONFIRMATION))
                    {
                        axutil_array_list_add(nodes_to_encrypt, env, cur_node);
                    }
                    cur_node = axiom_node_get_next_sibling(cur_node, env);
                }
            }
        }
    }

    
    /*Get the symmetric encryption algorithm*/
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);

    /*If not specified set the default*/
    if(!enc_sym_algo ||  (0 == axutil_strcmp(enc_sym_algo, "")))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
                       "[rampart][rampart_encryption] No symmetric algorithm is specified for encryption. Using the default");
        enc_sym_algo = OXS_DEFAULT_SYM_ALGO;
    }

    /*We need to take the decision whether to use derived keys or not*/
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_TRUE, server_side, AXIS2_FALSE);
    token_type = rp_property_get_type(token, env);
    use_derived_keys = rampart_context_check_is_derived_keys (env, token);
    derived_key_version = rampart_context_get_derived_key_version(env, token);

    if(token_type == RP_PROPERTY_SAML_TOKEN)
    {
        /* We need to obtain the saml here because it is used in many parts of the code*/
        saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_ENCRYPTION_TOKEN);
		if (!saml)
		{
			saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);
		}
        if (!saml)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] SAML not set.");                
            return AXIS2_FAILURE;
        }
    }
    session_key = rampart_context_get_encryption_session_key(rampart_context, env);
    if(!session_key)
    {
        /*Generate the  session key. if security context token, get the 
        shared secret and create the session key.*/
        if(token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
        {
            oxs_buffer_t *key_buf = NULL;
            session_key = oxs_key_create(env);
            key_buf = sct_provider_get_secret(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
            if(!key_buf)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Cannot get shared secret of security context token");
                oxs_key_free(session_key, env);
                return AXIS2_FAILURE;
            }
            oxs_key_populate(session_key, env,
                   oxs_buffer_get_data(key_buf, env), "for-algo",
                   oxs_buffer_get_size(key_buf, env), OXS_KEY_USAGE_NONE);
            rampart_context_set_encryption_session_key(rampart_context, env, session_key);
        }
        else if(token_type == RP_PROPERTY_SAML_TOKEN)
        {			
			session_key = rampart_saml_token_get_session_key(saml, env);
			if (!session_key)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] SAML session key not specified.");                
                return AXIS2_FAILURE;
			}
            rampart_context_set_encryption_session_key(rampart_context, env, session_key);
        }
        else
        {
            axis2_char_t *token_id = NULL;
            token_id = rampart_context_get_encryption_token_id(rampart_context, env, msg_ctx);
            if(token_id)
            {
                session_key = rampart_context_get_key(rampart_context, env, token_id);
                oxs_key_set_usage(session_key, env, OXS_KEY_USAGE_SESSION);
            }
            else
            {
                session_key = oxs_key_create(env);
                status = oxs_key_for_algo(session_key, env, rampart_context_get_algorithmsuite(rampart_context, env));
                rampart_context_set_encryption_session_key(rampart_context, env, session_key);
            }
        }
    }

    id_list = axutil_array_list_create(env, 5);
    dk_list = axutil_array_list_create(env, 5);
    /* For each and every encryption part.
        1. Derive a new key if key derivation is enabled. Or else use the same session key
        2. Encrypt using that key       
     */

    /*Add ReferenceList element to the Security header. Note that we pass the sec_node. Not the EncryptedKey*/
    data_ref_list_node = oxs_token_build_reference_list_element(env, sec_node);

    /*create derived key. */
    if(AXIS2_TRUE == use_derived_keys)
    {
        /*Derive a new key*/
        derived_key = oxs_key_create(env);
        oxs_key_set_length(derived_key, env, rampart_context_get_encryption_derived_key_len(rampart_context, env));
        status = oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE); 
        
        /*Add derived key to the list. We will create tokens*/
        axutil_array_list_add(dk_list, env, derived_key);
        key_reference_node = NULL;
    }

    /*Repeat until all encryption parts are encrypted*/
    for(i=0 ; i < axutil_array_list_size(nodes_to_encrypt, env); i++)
    {
        axiom_node_t *node_to_enc = NULL;
        oxs_ctx_t *enc_ctx = NULL;
#if 0
        oxs_key_t *derived_key = NULL;
#endif
        axis2_char_t *enc_data_id = NULL;
        axiom_node_t *parent_of_node_to_enc = NULL;
        axiom_node_t *enc_data_node = NULL;

        /*Get the node to be encrypted*/
        node_to_enc = (axiom_node_t *)axutil_array_list_get
                      (nodes_to_encrypt, env, i);
    
        /*Create the encryption context for OMXMLSEC*/
        enc_ctx = oxs_ctx_create(env);

        if(AXIS2_TRUE == use_derived_keys)
        {
#if 0
            /*Derive a new key*/
            derived_key = oxs_key_create(env);
            oxs_key_set_length(derived_key, env, rampart_context_get_encryption_derived_key_len(rampart_context, env));
            status = oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE); 
#endif
            /*Set the derived key for the encryption*/
            oxs_ctx_set_key(enc_ctx, env, derived_key);

            /*Set the ref key name to build KeyInfo element. Here the key name is the derived key id*/
            oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(derived_key, env));
#if 0            
            /*Add derived key to the list. We will create tokens*/
            axutil_array_list_add(dk_list, env, derived_key);
            key_reference_node = NULL;
#endif
        }
        else
        {
            /*No key derivation. We use the same session key*/
            oxs_ctx_set_key(enc_ctx, env, session_key);
            oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(session_key, env));

            if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
            {
                if(rampart_context_is_token_include(rampart_context,
                                                token, token_type, server_side, AXIS2_FALSE, env))
                {
                    /*set the AttachedReference to key_reference_node*/
                    key_reference_node = sct_provider_get_attached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
                }
                else
                {
                    /*get the unattachedReference and set to key_reference_node*/
                    key_reference_node = sct_provider_get_unattached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
                }
            }
            else if (token_type == RP_PROPERTY_SAML_TOKEN)
            {
                if(rampart_context_is_token_include(rampart_context,
                                                token, token_type, server_side, AXIS2_FALSE, env))
                {
					axiom_node_t *assertion = NULL;
                    /*set the AttachedReference to key_reference_node*/
                    key_reference_node = rampart_saml_token_get_str(saml, env);						
					if (!key_reference_node)
					{
						assertion = rampart_saml_token_get_assertion(saml, env);
						key_reference_node = oxs_saml_token_build_key_identifier_reference_local(env, NULL, assertion);
					}
                }
                else
                {                    
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] SAML session key not specified.");                
                    return AXIS2_FAILURE;                    
                }
            }
            else
            {
                if(server_side)
                {
                    axis2_char_t *encrypted_key_hash = NULL;
                    axiom_node_t *identifier_token = NULL;
                    encrypted_key_hash = oxs_key_get_key_sha(session_key, env);
                    key_reference_node = oxs_token_build_security_token_reference_element(env, NULL); 
                    identifier_token = oxs_token_build_key_identifier_element(env, key_reference_node, 
                                        OXS_ENCODING_BASE64BINARY, OXS_X509_ENCRYPTED_KEY_SHA1, encrypted_key_hash);
                }
                else
                {
                    key_reference_node = NULL;
                }
            }
        }

        /*Set the algorithm*/
        oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);  

        /*Generate ID for the encrypted data ielement*/       
        parent_of_node_to_enc = axiom_node_get_parent(node_to_enc, env);
        enc_data_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);
 
        if(parent_of_node_to_enc || enc_data_id)
        {
            axis2_char_t *enc_type = OXS_TYPE_ENC_ELEMENT;

            if(body_child_node == node_to_enc)
            {
                /* we have to use #Content for body encryption */
                enc_type = OXS_TYPE_ENC_CONTENT;
            }

            enc_data_node = oxs_token_build_encrypted_data_element(env,
                            parent_of_node_to_enc, enc_type, enc_data_id );
            status = oxs_xml_enc_encrypt_node(env, enc_ctx,
                                                  node_to_enc, &enc_data_node, key_reference_node);
            /*Add Ids to the list. We will create reference list*/
            axutil_array_list_add(id_list, env, enc_data_id);

            if(AXIS2_FAILURE == status)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot encrypt the node " );
				for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
				{
					axis2_char_t *id = NULL;
					id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
					AXIS2_FREE(env->allocator, id);
				}
				axutil_array_list_free(id_list, env);
				id_list = NULL; 

                return AXIS2_FAILURE;
            }

        }
        oxs_ctx_free(enc_ctx, env);
        enc_ctx = NULL;
        
    }/*End of for loop. Iterating nodes_to_encrypt list*/
    
    /*Free node list*/
    axutil_array_list_free(nodes_to_encrypt, env);
    nodes_to_encrypt = NULL;

    if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        if(rampart_context_is_token_include(rampart_context,
                                        token, token_type, server_side, AXIS2_FALSE, env))
        {
            axiom_node_t *security_context_token_node = NULL;
            /*include the security context token*/
            security_context_token_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_SECURITY_CONTEXT_TOKEN);
            if((!security_context_token_node) || (rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context)))
            {
                security_context_token_node = sct_provider_get_token(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
                if(!security_context_token_node)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot get security context token");
			        for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
			        {
				        axis2_char_t *id = NULL;
				        id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
				        AXIS2_FREE(env->allocator, id);
			        }
			        axutil_array_list_free(id_list, env);
			        id_list = NULL;
                    return AXIS2_FAILURE;
                }
                axiom_node_add_child(sec_node, env, security_context_token_node);
            }
        }
    }
    else if (token_type == RP_PROPERTY_SAML_TOKEN)
    {
        if(rampart_context_is_token_include(rampart_context,
                                        token, token_type, server_side, AXIS2_FALSE, env))
        {
            axiom_node_t *assertion = NULL;
            /*include the security context token*/            
            if (!rampart_saml_token_is_added_to_header(saml, env))
                assertion = rampart_saml_token_get_assertion(saml, env);
                if(!assertion)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot get SAML token");
			        for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
			        {
				        axis2_char_t *id = NULL;
				        id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
				        AXIS2_FREE(env->allocator, id);
			        }
			        axutil_array_list_free(id_list, env);
			        id_list = NULL;
                    return AXIS2_FAILURE;
                }
                axiom_node_add_child(sec_node, env, assertion);
        }        
    }
    else
    {
        /* If not done already, Encrypt the session key using the Public Key of the recipient*/
        /* Note: Here we do not send the id_list to create a ReferenceList inside the encrypted key. Instead we create the 
         *       ReferenceList as a child of Security element */
        if(!server_side)
        {
            encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
            if(!encrypted_key_node)
            {
                /*Create EncryptedKey element*/
                status = rampart_enc_encrypt_session_key(env, session_key, msg_ctx, rampart_context, sec_node, NULL );
                if(AXIS2_FAILURE == status)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[rampart][rampart_encryption] Cannot encrypt the session key " );
			        for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
			        {
				        axis2_char_t *id = NULL;
				        id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
				        AXIS2_FREE(env->allocator, id);
			        }
			        axutil_array_list_free(id_list, env);
			        id_list = NULL;
                    return AXIS2_FAILURE;
                }
                /*Now we have en EncryptedKey Node*/
                encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY);

                /*Get the asym key Id*/
                if(!encrypted_key_node)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
			        for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
			        {
				        axis2_char_t *id = NULL;
				        id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
				        AXIS2_FREE(env->allocator, id);
			        }
			        axutil_array_list_free(id_list, env);
			        id_list = NULL;
                    return AXIS2_FAILURE;
                }
                asym_key_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCKEY_ID);
		        free_asym_key_id = AXIS2_TRUE;
                if(asym_key_id)
                {
                    oxs_axiom_add_attribute(env, encrypted_key_node, NULL,
                                        NULL, OXS_ATTR_ID, asym_key_id);
                }
            }
            else
            {
                /*OK Buddy we have already created EncryptedKey node. Get the Id */
                asym_key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
            }
        }
    }

    /*Add used <wsc:DerivedKeyToken> elements to the header*/
    for(j=0 ; j < axutil_array_list_size(dk_list, env); j++){
        oxs_key_t *dk = NULL;
        
        dk = (oxs_key_t *)axutil_array_list_get(dk_list, env, j);
        
        /*Build the <wsc:DerivedKeyToken> element*/
        if(dk)
        {
            axiom_node_t *dk_node = NULL;
            if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
            {
               if(rampart_context_is_token_include(rampart_context,
                                                    token, token_type, server_side, AXIS2_FALSE, env))
                {
                    /*set the AttachedReference to key_reference_node*/
                    key_reference_node = sct_provider_get_attached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
                }
                else
                {
                    /*get the unattachedReference and set to key_reference_node*/
                    key_reference_node = sct_provider_get_unattached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
                }
                dk_node = oxs_derivation_build_derived_key_token_with_stre(env, dk, sec_node, key_reference_node, derived_key_version);
            }
            else
            {
                if(server_side)
                {
                    axis2_char_t *encrypted_key_hash = NULL;
                    axiom_node_t *identifier_token = NULL;
                    encrypted_key_hash = oxs_key_get_key_sha(session_key, env);
                    key_reference_node = oxs_token_build_security_token_reference_element(env, NULL); 
                    identifier_token = oxs_token_build_key_identifier_element(env, key_reference_node, 
                                        OXS_ENCODING_BASE64BINARY, OXS_X509_ENCRYPTED_KEY_SHA1, encrypted_key_hash);
                    dk_node = oxs_derivation_build_derived_key_token_with_stre(env, dk, sec_node, key_reference_node, derived_key_version);
                }
                else
                {
                    dk_node = oxs_derivation_build_derived_key_token(env, dk, sec_node, asym_key_id, OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY, derived_key_version);
                }
            }

            /*derived key should appear before ReferenceList*/
            oxs_axiom_interchange_nodes(env, dk_node, data_ref_list_node);
        }

        /*We will free DK here*/
        oxs_key_free(dk, env);
        dk = NULL;
    
    }/*End of For loop of dk_list iteration*/
    
    /*Free derrived key list*/
    axutil_array_list_free(dk_list, env);
    dk_list = NULL;

    /*Free derrived Id list*/
	for(j=0 ; j < axutil_array_list_size(id_list, env); j++)
	{
		axis2_char_t *id = NULL;
        axis2_char_t* mod_id = NULL;
		id = (axis2_char_t *)axutil_array_list_get(id_list, env, j);
        mod_id = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,id);
        oxs_token_build_data_reference_element(env, data_ref_list_node, mod_id);
        /*if x509 is used and no-derived keys, then we have to modify security token reference*/
        if((token_type == RP_PROPERTY_X509_TOKEN) && (!use_derived_keys) && (asym_key_id))
        {
            axiom_node_t *enc_data_node = NULL;
            axiom_node_t *envelope_node = NULL;
            axiom_node_t *str_node = NULL;
            axiom_node_t *reference_node = NULL;
            axis2_char_t *id_ref = NULL;

            envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
            enc_data_node = oxs_axiom_get_node_by_id(env, envelope_node, OXS_ATTR_ID, id, NULL);
            str_node = oxs_axiom_get_node_by_local_name(env, enc_data_node, OXS_NODE_SECURITY_TOKEN_REFRENCE);
            reference_node = oxs_axiom_get_node_by_local_name(env, str_node, OXS_NODE_REFERENCE);
            axiom_node_free_tree(reference_node, env);
            
            id_ref = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,asym_key_id);
            reference_node = oxs_token_build_reference_element(env, str_node,
                                id_ref, OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY);

            AXIS2_FREE(env->allocator, id_ref);
        }

		AXIS2_FREE(env->allocator, id);
		AXIS2_FREE(env->allocator, mod_id);
	}
    axutil_array_list_free(id_list, env);
    id_list = NULL; 
    
	if(free_asym_key_id && asym_key_id)
	{
		AXIS2_FREE(env->allocator, asym_key_id);
	}

    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_message(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    axutil_array_list_t *nodes_to_encrypt = NULL;
    axutil_array_list_t *id_list = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *enc_sym_algo = NULL;
    oxs_key_t *session_key = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_type_t token_type;
    rp_property_t *token = NULL;
    int i = 0;
    axis2_bool_t signature_protection = AXIS2_FALSE;
    axiom_node_t *sig_node = NULL;
    axiom_soap_body_t *body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *body_child_node = NULL;

    body = axiom_soap_envelope_get_body(soap_envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);
    body_child_node = axiom_node_get_first_element(body_node, env);


    /*Get nodes to be encrypted*/

    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    nodes_to_encrypt = axutil_array_list_create(env, 0);

    signature_protection = rampart_context_is_encrypt_signature(
                               rampart_context, env);

    status = rampart_enc_get_nodes_to_encrypt(
                 rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature]Error occured in Adding Encrypted parts..");
        axutil_array_list_free(nodes_to_encrypt, env);
        nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }

    if((axutil_array_list_size(nodes_to_encrypt, env)==0))
    {
        if(!signature_protection)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
                           "[rampart][rampart_encryption] No parts specified or specified parts can't be found for encryprion.");
			axutil_array_list_free(nodes_to_encrypt, env);
			nodes_to_encrypt = NULL;
            return AXIS2_SUCCESS;
        }
    }

    if(signature_protection)
    {
        if(!(rampart_context_is_encrypt_before_sign(rampart_context, env)))
        {
            sig_node = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_SIGNATURE);
            if(!sig_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Sigature Not found");
				axutil_array_list_free(nodes_to_encrypt, env);
				nodes_to_encrypt = NULL;
                return AXIS2_FAILURE;
            }
            axutil_array_list_add(nodes_to_encrypt, env, sig_node);
        }
    }

    /*Now we have to check whether a token is specified.*/
    token = rampart_context_get_token(rampart_context, env,
                                      AXIS2_TRUE, server_side, AXIS2_FALSE);
    if(!token)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
                       "[rampart][rampart_encryption]Encryption Token is not specified");
		axutil_array_list_free(nodes_to_encrypt, env);
		nodes_to_encrypt = NULL;
        return AXIS2_SUCCESS;
    }
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Specified token type not supported.");
		axutil_array_list_free(nodes_to_encrypt, env);
		nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }
    if(rampart_context_check_is_derived_keys(env,token))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]We still do not support derived keys");
		axutil_array_list_free(nodes_to_encrypt, env);
		nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }

    /*Get the symmetric encryption algorithm*/
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);

    /*If not specified set the default*/
    if(!enc_sym_algo ||  (0 == axutil_strcmp(enc_sym_algo, "")))
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
                       "[rampart][rampart_encryption]No symmetric algorithm is specified for encryption. Using the default");
        enc_sym_algo = OXS_DEFAULT_SYM_ALGO;
    }

    session_key = rampart_context_get_encryption_session_key(rampart_context, env);
    if(!session_key){
        /*Generate the  session key*/
         session_key = oxs_key_create(env);
         status = oxs_key_for_algo(session_key, env, rampart_context_get_algorithmsuite(rampart_context, env));
         rampart_context_set_encryption_session_key(rampart_context, env, session_key);
    }
    if(AXIS2_FAILURE == status)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Cannot generate the key for the algorithm %s, ", enc_sym_algo);
		axutil_array_list_free(nodes_to_encrypt, env);
		nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }

    /*Key will be duplicated inside the function. So no worries freeing it here*/
    /*if(rampart_context_is_encrypt_before_sign(rampart_context, env)
            && signature_protection)
    {
        rampart_context_set_session_key(rampart_context, env, session_key);
    }*/

    /*Create a list to store EncDataIds. This will be used in building the ReferenceList*/

    id_list = axutil_array_list_create(env, 5);

    /*Repeat until all encryption parts are encrypted*/
    for(i=0 ; i < axutil_array_list_size(nodes_to_encrypt, env); i++)
    {
        axiom_node_t *node_to_enc = NULL;
        axiom_node_t *parent_of_node_to_enc = NULL;
        axiom_node_t *enc_data_node = NULL;
        oxs_ctx_t *enc_ctx = NULL;
        axis2_char_t *id = NULL;
        axis2_status_t enc_status = AXIS2_FAILURE;

        /*Get the node to be encrypted*/
        node_to_enc = (axiom_node_t *)axutil_array_list_get
                      (nodes_to_encrypt, env, i);
        if(!node_to_enc)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] Cannot get the node from the list to encrypt");
			axutil_array_list_free(nodes_to_encrypt, env);
			nodes_to_encrypt = NULL;
            return AXIS2_FAILURE;
        }
        /*Create the encryption context for OMXMLSEC*/
        enc_ctx = oxs_ctx_create(env);
        /*Set the key*/
        oxs_ctx_set_key(enc_ctx, env, session_key);
        /*Set the algorithm*/
        oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);
        /*Create an empty EncryptedDataNode*/
        parent_of_node_to_enc = axiom_node_get_parent(node_to_enc, env);
        id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);

        if(parent_of_node_to_enc || id)
        {
            axis2_char_t *enc_type = OXS_TYPE_ENC_ELEMENT;

            if(body_child_node == node_to_enc)
            {
                /* we have to use #Content for body encryption */
                enc_type = OXS_TYPE_ENC_CONTENT;
            }

            enc_data_node = oxs_token_build_encrypted_data_element(env,
                            parent_of_node_to_enc, enc_type, id );
            enc_status = oxs_xml_enc_encrypt_node(env, enc_ctx,
                                                  node_to_enc, &enc_data_node, NULL); 
            axutil_array_list_add(id_list, env, id);
            if(AXIS2_FAILURE == enc_status)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot encrypt the node " );
				axutil_array_list_free(nodes_to_encrypt, env);
				nodes_to_encrypt = NULL;
                return AXIS2_FAILURE;
            }
        }
        oxs_ctx_free(enc_ctx, env);
        enc_ctx = NULL;

    }/*Eof For loop*/

    /*free nodes_to_encrypt list*/
    axutil_array_list_free(nodes_to_encrypt, env);
    nodes_to_encrypt = NULL;

    /*We need to encrypt the session key.*/
    status = rampart_enc_encrypt_session_key(env, session_key, msg_ctx, rampart_context, sec_node, id_list);
    if(AXIS2_FAILURE == status){
        return AXIS2_FAILURE;
    }
    /*Free id_list*/
    if(id_list)
    {
        int size = 0;
        int j = 0;
        size = axutil_array_list_size(id_list, env);
        for (j = 0; j < size; j++)
        {
            axis2_char_t *id = NULL;

            id = axutil_array_list_get(id_list, env, j);
            AXIS2_FREE(env->allocator, id);
            id = NULL;
        }
        axutil_array_list_free(id_list, env);
        id_list = NULL;
    }

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_add_key_info(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    axis2_char_t *key_id = NULL;
    axiom_node_t *key_info_node = NULL;
    axiom_node_t *str_node = NULL;
    axiom_node_t *reference_node = NULL;

    axiom_node_t *encrypted_data_node = NULL;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *body_node = NULL;
    axiom_soap_body_t *body = NULL;

    axiom_element_t *body_ele = NULL;
    axiom_element_t *encrypted_data_ele = NULL;

    encrypted_key_node = oxs_axiom_get_node_by_local_name(
                             env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
    if(!encrypted_key_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
        return AXIS2_FAILURE;
    }

    key_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCKEY_ID);

    if(key_id)
    {
        oxs_axiom_add_attribute(env, encrypted_key_node, NULL/*OXS_WSU*/,
                                NULL/*RAMPART_WSU_XMLNS*/, OXS_ATTR_ID, key_id);
    }

    body = axiom_soap_envelope_get_body(soap_envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);

    body_ele = (axiom_element_t *)
               axiom_node_get_data_element(body_node, env);

    encrypted_data_ele = axiom_util_get_first_child_element_with_localname(
                             body_ele, env, body_node, OXS_NODE_ENCRYPTED_DATA, &encrypted_data_node);

    if(encrypted_data_ele)
    {
        key_info_node = oxs_token_build_key_info_element(
                            env, encrypted_data_node);
        if(key_info_node)
        {
            str_node = oxs_token_build_security_token_reference_element(
                           env, key_info_node);
            if(str_node)
            {
                axis2_char_t *key_id_ref = NULL;
                key_id_ref = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,key_id);
                reference_node = oxs_token_build_reference_element(
                                     env, str_node, key_id_ref, NULL);
                AXIS2_FREE(env->allocator, key_id_ref);
                key_id_ref = NULL;
				AXIS2_FREE(env->allocator, key_id);
				key_id = NULL;

                if(!reference_node)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][rampart_encryption]Encrypting signature, Reference Node build failed");
                    return AXIS2_FAILURE;
                }
                else
                {
                    return AXIS2_SUCCESS;
                }
            }
            else{
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Cannot build the STR node");
				AXIS2_FREE(env->allocator, key_id);
				key_id = NULL;
                return AXIS2_FAILURE;
            }
        }
        else{
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] Encrypting signature, cannot build the key indfo node");
			AXIS2_FREE(env->allocator, key_id);
			key_id = NULL;
            return AXIS2_FAILURE;
        }
    }
    else{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, Cannot get the encryption data element");
		AXIS2_FREE(env->allocator, key_id);
		key_id = NULL;
        return AXIS2_FAILURE;
    }
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    oxs_key_t *session_key = NULL;
    oxs_key_t *derived_key = NULL;
    axiom_node_t *node_to_enc = NULL;
    axiom_node_t *enc_data_node = NULL;
    oxs_ctx_t *enc_ctx = NULL;
    axis2_char_t *id = NULL;
    axis2_status_t enc_status = AXIS2_FAILURE;
    axis2_char_t *enc_sym_algo = NULL;
    axutil_array_list_t *id_list = NULL;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *temp_node = NULL;
    axiom_node_t *node_to_move = NULL;
    axis2_bool_t use_derived_keys = AXIS2_TRUE;
    axis2_char_t *derived_key_version = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *key_reference_node = NULL;
    axiom_node_t *key_reference_for_encrypted_data = NULL;
    rampart_saml_token_t *saml = NULL;

    session_key = rampart_context_get_encryption_session_key(rampart_context, env);

    if(!session_key)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting Signature.Session key not found");
        return AXIS2_FAILURE;
    }
    /*Get <ds:Signature> node*/
    node_to_enc = oxs_axiom_get_node_by_local_name(
                      env, sec_node, OXS_NODE_SIGNATURE);

    if(!node_to_enc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting Signature. Signature node not found");
        return AXIS2_FAILURE;
    }

    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_TRUE, server_side, AXIS2_FALSE);
    token_type = rp_property_get_type(token, env);

    if(token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        if(rampart_context_is_token_include(rampart_context,
                                        token, token_type, server_side, AXIS2_FALSE, env))
        {
            /*set the AttachedReference to key_reference_node*/
            key_reference_node = sct_provider_get_attached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
        }
        else
        {
            /*get the unattachedReference and set to key_reference_node*/
            key_reference_node = sct_provider_get_unattached_reference(env, token, AXIS2_TRUE, rampart_context, msg_ctx);
        }
    }
    else if(token_type == RP_PROPERTY_SAML_TOKEN)
    {
        saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_ENCRYPTION_TOKEN);
		if (!saml)
		{
			saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);
		}
        if (!saml)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] SAML not set.");                
            return AXIS2_FAILURE;
        }
        if(rampart_context_is_token_include(rampart_context,
                                        token, token_type, server_side, AXIS2_FALSE, env))
        {
            /*set the AttachedReference to key_reference_node*/
            key_reference_node = rampart_saml_token_get_str(saml, env);
        }
        else
        {
            /*get the unattachedReference and set to key_reference_node*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "[rampart][rampart_encryption] SAML not set.");                
            return AXIS2_FAILURE;
        }
    }
    else
    {
        if((server_side) && (rampart_context_get_binding_type(rampart_context,env) == RP_PROPERTY_SYMMETRIC_BINDING))
        {
            axis2_char_t *encrypted_key_hash = NULL;
            axiom_node_t *identifier_token = NULL;
            encrypted_key_hash = oxs_key_get_key_sha(session_key, env);
            key_reference_node = oxs_token_build_security_token_reference_element(env, NULL); 
            identifier_token = oxs_token_build_key_identifier_element(env, key_reference_node, 
                                OXS_ENCODING_BASE64BINARY, OXS_X509_ENCRYPTED_KEY_SHA1, encrypted_key_hash);
        }
        else
        {
            encrypted_key_node = oxs_axiom_get_node_by_local_name(
                                     env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
            if(!encrypted_key_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
                return AXIS2_FAILURE;
            }
        }
    }

    enc_ctx = oxs_ctx_create(env);

    /*We need to take the decision whether to use derived keys or not*/
    use_derived_keys = rampart_context_check_is_derived_keys (env, token);
    derived_key_version = rampart_context_get_derived_key_version(env, token);
    if(AXIS2_TRUE == use_derived_keys)
    {
        /*Derive a new key*/
        derived_key = oxs_key_create(env);
        oxs_key_set_length(derived_key, env, rampart_context_get_encryption_derived_key_len(rampart_context, env));
        status = oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE);

        /*Set the derived key for the encryption*/
        oxs_ctx_set_key(enc_ctx, env, derived_key);

        /*Set the ref key name to build KeyInfo element. Here the key name is the derived key id*/
        oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(derived_key, env));
    }
    else
    {
        /*No Key derivation is needed we will proceed with the same session key*/
        oxs_ctx_set_key(enc_ctx, env, session_key);
        key_reference_for_encrypted_data = key_reference_node;
    }
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);
    oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);
    id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);

    /*Manage the reference list*/
    id_list = axutil_array_list_create(env, 0);
    axutil_array_list_add(id_list, env, id);
    if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        /*We append IDs to the EncryptedKey node*/
        axiom_node_t *ref_list_node = NULL;
        ref_list_node = oxs_token_build_data_reference_list(
                         env, encrypted_key_node, id_list);
        if(!ref_list_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_encryption]Asym Encrypting signature,"
                    "Building reference list failed");
            return AXIS2_FAILURE;
        } 
    }
    else if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        if((AXIS2_TRUE == use_derived_keys) || (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN) || (server_side) || 
            (token_type == RP_PROPERTY_SAML_TOKEN))
        {
            /*We need to create a new reference list and then attach it before the EncryptedData(signature)*/
            axiom_node_t *ref_list_node = NULL;

            ref_list_node = oxs_token_build_data_reference_list(env, sec_node, id_list);
            if(!ref_list_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_encryption]Sym Encrypting signature,"
                                    "Building reference list failed");
                return AXIS2_FAILURE;
            }
        }
        else
        {
            /*The session key is in use. Add a ref to the EncryptedKey's ref list*/
            axiom_node_t *ref_list_node = NULL;
            ref_list_node = oxs_axiom_get_first_child_node_by_name(
                        env, encrypted_key_node, OXS_NODE_REFERENCE_LIST, OXS_ENC_NS, NULL);
            if(ref_list_node)
            {
                /*There is a ref list node in EncryptedKey. So append*/
                axiom_node_t *data_ref_node = NULL;
                axis2_char_t *mod_id = NULL;

                /*We need to prepend # to the id in the list to create the reference*/
                mod_id = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,id);
                data_ref_node = oxs_token_build_data_reference_element(env, ref_list_node, mod_id);

            }
            else
            {
                /*There is NO ref list node in EncryptedKey. So create a new one */
                ref_list_node = oxs_token_build_data_reference_list(env, encrypted_key_node, id_list);
            }
        }       
    }
    else
    {
        /*Nothing to do*/
    }
    
    /*Encrypt the signature*/
    enc_data_node = oxs_token_build_encrypted_data_element(
                        env, sec_node, OXS_TYPE_ENC_ELEMENT, id );
    enc_status = oxs_xml_enc_encrypt_node(
        env, enc_ctx, node_to_enc, &enc_data_node, key_reference_for_encrypted_data);

    /*FREE*/
    oxs_ctx_free(enc_ctx, env);
    enc_ctx = NULL;

    if(enc_status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Encrypting node failed");
        return AXIS2_FAILURE;
    }
    /*If we have used a derrived key, we need to attach it to the Securuty Header*/
    if(AXIS2_TRUE == use_derived_keys)
    {
        if((token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN) || token_type == RP_PROPERTY_SAML_TOKEN ||
            (server_side && (rampart_context_get_binding_type(rampart_context,env) == RP_PROPERTY_SYMMETRIC_BINDING)))
        {
            oxs_derivation_build_derived_key_token_with_stre(env, derived_key, sec_node, key_reference_node, derived_key_version);
        }
        else
        {
            axis2_char_t *asym_key_id = NULL;
            asym_key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
            oxs_derivation_build_derived_key_token(env, derived_key, sec_node, asym_key_id, OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY, derived_key_version);  
        }
		/*now we can free the derived key*/
		oxs_key_free(derived_key, env);
		derived_key = NULL;
    }

    node_to_move = oxs_axiom_get_node_by_local_name(
                       env, sec_node,  OXS_NODE_REFERENCE_LIST);

    if(node_to_move)
    {
        temp_node = axiom_node_detach_without_namespaces(node_to_move, env);
        if(temp_node)
        {
            enc_status = axiom_node_insert_sibling_after(
                             enc_data_node, env, temp_node);
            if(enc_status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Node moving failed.");
                return AXIS2_FAILURE;
            }
        }
    }


    if(id_list)
    {
        /*Need to free data of the list*/
        int size = 0;
        int j = 0;
        size = axutil_array_list_size(id_list, env);
        for (j = 0; j < size; j++)
        {
            axis2_char_t *id_temp = NULL;
            id_temp = axutil_array_list_get(id_list, env, j);
            AXIS2_FREE(env->allocator, id_temp);
            id_temp = NULL;
        }

        axutil_array_list_free(id_list, env);
        id_list = NULL;
    }
    return AXIS2_SUCCESS;
}
