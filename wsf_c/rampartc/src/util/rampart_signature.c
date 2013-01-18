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

#include <rampart_signature.h>
#include <rampart_encryption.h>
#include <stdio.h>
#include <axutil_utils.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <rampart_constants.h>
#include <oxs_tokens.h>
#include <axutil_array_list.h>
#include <oxs_axiom.h>
#include <axis2_key_type.h>
#include <oxs_key.h>
#include <oxs_key_mgr.h>
#include <openssl_pkey.h>
#include <oxs_axiom.h>
#include <oxs_transform.h>
#include <oxs_transforms_factory.h>
#include <oxs_sign_ctx.h>
#include <oxs_sign_part.h>
#include <oxs_xml_signature.h>
#include <oxs_derivation.h>
#include <axis2_key_type.h>
#include <rampart_token_builder.h>
#include <rampart_util.h>
#include <rampart_sec_processed_result.h>
#include <rampart_sct_provider_utility.h>
#include <rampart_saml_token.h>
#include <axiom_util.h>

/*Private functions*/

axis2_status_t AXIS2_CALL
rampart_sig_add_x509_token(const axutil_env_t *env, 
                               rampart_context_t *rampart_context, 
                               axiom_node_t *sec_node,
                               axis2_char_t *cert_id);

axutil_array_list_t * AXIS2_CALL
rampart_sig_create_sign_parts(const axutil_env_t *env,
                              rampart_context_t *rampart_context, 
                              axutil_array_list_t *nodes_to_sign,
                              axis2_bool_t server_side,
                              axutil_array_list_t *sign_parts_list);

static axis2_status_t
rampart_sig_endorse_sign(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node);

axis2_status_t AXIS2_CALL
rampart_sig_prepare_key_info_for_sym_binding(const axutil_env_t *env,
                rampart_context_t *rampart_context,
                oxs_sign_ctx_t *sign_ctx,
        		axiom_node_t *sig_node,
                oxs_key_t *key,
                axis2_char_t* encrypted_key_id)
{
    axiom_node_t *key_info_node = NULL;
    axiom_node_t *str_node = NULL;
    axiom_node_t *reference_node = NULL;    
    axis2_char_t *id_ref = NULL;
    axis2_char_t *key_id = NULL;
    axis2_char_t *value_type = NULL;
    
    /*Now we must build the Key Info element*/
    key_info_node = oxs_token_build_key_info_element(env, sig_node);
    str_node = oxs_token_build_security_token_reference_element(
                           env, key_info_node);
    /*Create the reference Id*/
    /*There are two ways the key info can be built
     * 1. If the key used to sign is encrypted using an X509 Certificate, then that EncryptedKey's id will be used
     * 2. If the key used to sign is derrived from the session key, then the Id of the derived key will be used 
     */
    if(encrypted_key_id){
        /*Session key in use. Which is encrypted and hidden in the EncryptedKey with Id=encrypted_key_id*/
        key_id = encrypted_key_id;
        value_type = OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY;
        id_ref = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,key_id);
    }else{
        /*Derived Keys in use.*/
        key_id = oxs_key_get_name(key, env);
        value_type = NULL;
        id_ref = key_id;
    }
    
    reference_node = oxs_token_build_reference_element(env, str_node,
                        id_ref, value_type );   
     
    return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
rampart_sig_prepare_key_info_for_asym_binding(const axutil_env_t *env,
                rampart_context_t *rampart_context,
                oxs_sign_ctx_t *sign_ctx,
        		axiom_node_t *sig_node,
                axis2_char_t *cert_id,
                axis2_char_t *eki,
				axis2_bool_t is_direct_reference)
{
    axiom_node_t *key_info_node = NULL;
	oxs_key_mgr_t *key_mgr = NULL;
    /*axis2_bool_t is_direct_reference = AXIS2_TRUE;*/
    axis2_status_t status = AXIS2_FAILURE;

    /*Now we must build the Key Info element*/
    key_info_node = oxs_token_build_key_info_element(env, sig_node);    
    if(is_direct_reference)
    {
        axiom_node_t *str_node = NULL;
        axiom_node_t *reference_node = NULL;
        axis2_char_t *cert_id_ref = NULL;
        
        str_node = oxs_token_build_security_token_reference_element(
                       env, key_info_node);

        if(!str_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Security Token element creation failed in Direct reference.");
            return AXIS2_FAILURE;
        }
        cert_id_ref = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX,cert_id);
        reference_node = oxs_token_build_reference_element(
                             env, str_node, cert_id_ref, OXS_VALUE_X509V3);
        AXIS2_FREE(env->allocator, cert_id_ref);
        cert_id_ref = NULL;
        if(!reference_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Security Token element creation failed in Direct reference.");
            return AXIS2_FAILURE;
        }
    }
    else
    {
        oxs_x509_cert_t *cert = NULL;
        key_mgr = rampart_context_get_key_mgr(rampart_context, env);

        cert = oxs_key_mgr_get_certificate(key_mgr, env);
        if(!cert)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Cannot get the certificate");
            return AXIS2_FAILURE;
        }
        if(axutil_strcmp(eki, RAMPART_STR_EMBEDDED) == 0)
        {
            status = rampart_token_build_security_token_reference(
                         env, key_info_node, cert, RTBP_EMBEDDED);
        }
        else if(axutil_strcmp(eki, RAMPART_STR_ISSUER_SERIAL) == 0)
        {
            status = rampart_token_build_security_token_reference(
                         env, key_info_node, cert, RTBP_X509DATA_ISSUER_SERIAL);
        }
        else if(axutil_strcmp(eki, RAMPART_STR_KEY_IDENTIFIER) == 0)
        {
            status = rampart_token_build_security_token_reference(
                         env, key_info_node, cert, RTBP_KEY_IDENTIFIER);
        }
        else if(axutil_strcmp(eki, RAMPART_STR_THUMB_PRINT) == 0)
        {
            status = rampart_token_build_security_token_reference(
                        env, key_info_node, cert, RTBP_THUMBPRINT);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Unknown key Identifier type.Token attaching failed");
            status = AXIS2_FAILURE;
        }
        oxs_x509_cert_free(cert, env);
        cert = NULL;
    }

    /*FREE*/
    if(cert_id)
    {
        AXIS2_FREE(env->allocator, cert_id);
        cert_id = NULL;
    }

    return AXIS2_FAILURE;
}


axis2_status_t AXIS2_CALL
rampart_sig_pack_for_sym(const axutil_env_t *env,
                rampart_context_t *rampart_context,
                oxs_sign_ctx_t *sign_ctx,
                axis2_msg_ctx_t *msg_ctx)
{
    oxs_key_t *session_key = NULL;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;

    axis2_bool_t use_derived_keys = AXIS2_FALSE;
    axis2_bool_t server_side = AXIS2_FALSE;
 
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_FALSE, server_side, AXIS2_FALSE);
    token_type = rp_property_get_type(token, env);

    /*We are trying to reuse the same session key which is used for encryption if possible*/
    session_key = rampart_context_get_signature_session_key(rampart_context, env);
    if(!session_key)
    {
        /*Create a new key and set to the rampart_context. This usually happens when the SignBeforeEncrypt*/
        /*Generate the  session key. if security context token, get the 
        shared secret and create the session key.*/
        if(token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
        {
            oxs_buffer_t *key_buf = NULL;
            session_key = oxs_key_create(env);
            key_buf = sct_provider_get_secret(env, token, AXIS2_FALSE, rampart_context, msg_ctx);
            if(!key_buf)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature]Cannot get shared secret of security context token");
                oxs_key_free(session_key, env);
                return AXIS2_FAILURE;
            }
            oxs_key_populate(session_key, env,
                   oxs_buffer_get_data(key_buf, env), "for-algo",
                   oxs_buffer_get_size(key_buf, env), OXS_KEY_USAGE_NONE);
            rampart_context_set_signature_session_key(rampart_context, env, session_key);
        }
		else if(token_type == RP_PROPERTY_SAML_TOKEN)
        {
			rampart_saml_token_t *saml = NULL;
			saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_SIGNATURE_TOKEN);
			if (!saml)
			{
				saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);
			}
			session_key = rampart_saml_token_get_session_key(saml, env);
			if (!session_key)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature]Session key not specified.");                
                return AXIS2_FAILURE;
			}
			rampart_context_set_signature_session_key(rampart_context, env, session_key);
        }
        else
        {
            axis2_char_t *token_id = NULL;
            token_id = rampart_context_get_signature_token_id(rampart_context, env, msg_ctx);
            if(token_id)
            {
                int key_usage = OXS_KEY_USAGE_SESSION;
                if(rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context))
                    key_usage = OXS_KEY_USAGE_SIGNATURE_SESSION;

                session_key = rampart_context_get_key(rampart_context, env, token_id);
                oxs_key_set_usage(session_key, env, key_usage);
            }
            else
            {
                session_key = oxs_key_create(env);
                oxs_key_for_algo(session_key, env, rampart_context_get_algorithmsuite(rampart_context, env));
                rampart_context_set_signature_session_key(rampart_context, env, session_key);
            }
        }
        
    }

    /*If we need to use derrived keys, we must sign using a derived key of the session key*/
    use_derived_keys = rampart_context_check_is_derived_keys (env, token);
    if(use_derived_keys)
    {
        oxs_key_t *derived_key = NULL;
        /*Derive a new key*/
        derived_key = oxs_key_create(env);
        oxs_key_set_length(derived_key, env, rampart_context_get_signature_derived_key_len(rampart_context, env));
        oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE);
        oxs_sign_ctx_set_secret(sign_ctx, env, derived_key);
    }
    else
    {
        /*No need to use derived keys, we use the same session key*/
        oxs_sign_ctx_set_secret(sign_ctx, env, rampart_context_get_signature_session_key(rampart_context, env));
    }

    oxs_sign_ctx_set_sign_mtd_algo(sign_ctx, env, OXS_HREF_HMAC_SHA1);
    oxs_sign_ctx_set_c14n_mtd(sign_ctx, env, OXS_HREF_XML_EXC_C14N);
    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_SIGN);
    
    return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
rampart_sig_pack_for_asym(const axutil_env_t *env,
                rampart_context_t *rampart_context,
		     oxs_sign_ctx_t *sign_ctx)
{
    openssl_pkey_t *prvkey = NULL;
    oxs_key_mgr_t *key_mgr = NULL;
    axis2_char_t *asym_sig_algo = NULL;
    
	key_mgr = rampart_context_get_key_mgr(rampart_context, env);
    prvkey = oxs_key_mgr_get_prv_key(key_mgr, env);

	if (!prvkey)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart][rampart_signature]Private key cannot be loaded.");
		return AXIS2_FAILURE;
    }

    /*Get the asymmetric signature algorithm*/
    asym_sig_algo = rampart_context_get_asym_sig_algo(rampart_context, env);
    
    /*These properties will set for creating signed info element*/

    oxs_sign_ctx_set_private_key(sign_ctx, env, prvkey);
    oxs_sign_ctx_set_sign_mtd_algo(sign_ctx, env, asym_sig_algo);
    oxs_sign_ctx_set_c14n_mtd(sign_ctx, env, OXS_HREF_XML_EXC_C14N);
    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_SIGN);

    return AXIS2_SUCCESS;
}

/*Public functions*/


axis2_status_t AXIS2_CALL
rampart_sig_get_nodes_to_sign(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign)
{

    axis2_status_t status1 = AXIS2_SUCCESS;
    axis2_status_t status2 = AXIS2_SUCCESS;

    status1 = rampart_context_get_nodes_to_sign(
                  rampart_context, env, soap_envelope, nodes_to_sign);

    status2 = rampart_context_get_elements_to_sign(
                  rampart_context, env, soap_envelope, nodes_to_sign);

    if(status1 == AXIS2_SUCCESS || status2 == AXIS2_SUCCESS)
    {
        return AXIS2_SUCCESS;
    }
    else
    {
        return AXIS2_FAILURE;
    }
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_sig_sign_message(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node, 
    axutil_array_list_t *sign_parts_list)
{
    axutil_array_list_t *nodes_to_sign = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    oxs_sign_ctx_t *sign_ctx = NULL;
    /*axutil_array_list_t *tr_list = NULL;*/
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_type_t token_type;
    rp_property_type_t binding_type;
    rp_property_t *token = NULL;
    axis2_char_t *derived_key_version = NULL;
    axiom_node_t *sig_node = NULL;
    axis2_char_t *eki = NULL;
    axis2_bool_t is_direct_reference = AXIS2_TRUE;
    axis2_bool_t include = AXIS2_FALSE;
    axiom_node_t *key_reference_node = NULL;
    axis2_char_t *cert_id = NULL;

    /*Get nodes to be signed*/
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    nodes_to_sign = axutil_array_list_create(env, 0);

    status = rampart_sig_get_nodes_to_sign(
                 rampart_context, env, soap_envelope, nodes_to_sign);
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Error occured in Adding signed parts.");
        axutil_array_list_free(nodes_to_sign, env);
        nodes_to_sign = NULL;
        return AXIS2_FAILURE;
    }

    if((axutil_array_list_size(nodes_to_sign, env)==0))
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_signature] No parts specified or specified parts can't be found for Signature.");
        axutil_array_list_free(nodes_to_sign, env);
        nodes_to_sign = NULL;
        return AXIS2_SUCCESS;
    }

#if 0 /* this block is moved to rampart_context_get_nodes_to_sign */
    /*If Timestamp and usernametoken are in the message we should sign them.*/

    if(rampart_context_get_require_timestamp(rampart_context, env))
    {
        axiom_node_t *ts_node = NULL;
        ts_node = oxs_axiom_get_node_by_local_name(env, sec_node, RAMPART_SECURITY_TIMESTAMP);
        if(!ts_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_signature] Required timestamp cannot be found.");
            axutil_array_list_free(nodes_to_sign, env);
            nodes_to_sign = NULL;
            return AXIS2_FAILURE;
        }
        axutil_array_list_add(nodes_to_sign, env, ts_node);
    }

    if(!server_side)
    {
        if(rampart_context_get_require_ut(rampart_context, env))
        {
            axiom_node_t *ut_node = NULL;
            ut_node = oxs_axiom_get_node_by_local_name(
                          env, sec_node, RAMPART_SECURITY_USERNAMETOKEN);
            if(!ut_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature] Required username token cannot be found.");
                axutil_array_list_free(nodes_to_sign, env);
                nodes_to_sign = NULL;
                return AXIS2_FAILURE;
            }
            axutil_array_list_add(nodes_to_sign, env, ut_node);
        }
    }
    else
    {
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
                    axutil_array_list_add(nodes_to_sign, env, cur_node);
                }
                cur_node = axiom_node_get_next_sibling(cur_node, env);
            }
        }
    }
#endif

    /*Now we have to check whether a token is specified.*/
    token = rampart_context_get_token(rampart_context, env, AXIS2_FALSE, server_side, AXIS2_FALSE);
    if(!token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Signature Token is not specified");
        axutil_array_list_free(nodes_to_sign, env);
        nodes_to_sign = NULL;
        return AXIS2_FAILURE;
    }
    token_type = rp_property_get_type(token, env);

	if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Token type %d not supported", token_type);
        axutil_array_list_free(nodes_to_sign, env);
        nodes_to_sign = NULL;
        return AXIS2_FAILURE;
    }
    /* Determine weather we need to include the token */
    include = rampart_context_is_token_include(rampart_context, token, 
                                                token_type, server_side, 
                                                AXIS2_FALSE, env);
    derived_key_version = rampart_context_get_derived_key_version(env, token);
    if (token_type == RP_PROPERTY_X509_TOKEN) 
    {        
		if (include) 
        {
            cert_id = oxs_util_generate_id(env,(axis2_char_t*)OXS_CERT_ID);
			if (!rampart_sig_add_x509_token(env, rampart_context, sec_node, cert_id)) 
            {
                axutil_array_list_free(nodes_to_sign, env);
                nodes_to_sign = NULL;
				return AXIS2_FAILURE;
			}
			/*This flag will be useful when creating key Info element.*/
			is_direct_reference = AXIS2_TRUE;
			eki = RAMPART_STR_DIRECT_REFERENCE;			
		}
		else 
        {
			eki = rampart_context_get_key_identifier(rampart_context, token, env);
            if(!eki) 
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature] Cannot attach the token.");
                axutil_array_list_free(nodes_to_sign, env);
                nodes_to_sign = NULL;
                return AXIS2_FAILURE;
            }
			is_direct_reference = AXIS2_FALSE;
		}
    }
    else if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        if(include)
        {
            axiom_node_t *security_context_token_node = NULL;
            /*include the security context token and set the AttachedReference to key_reference_node*/
            security_context_token_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_SECURITY_CONTEXT_TOKEN);
            if((!security_context_token_node) || (rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context)))
            {
                security_context_token_node = sct_provider_get_token(env, token, AXIS2_FALSE, rampart_context, msg_ctx);
                if(!security_context_token_node)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature] Cannot get security context token");
                    axutil_array_list_free(nodes_to_sign, env);
                    nodes_to_sign = NULL;
                    return AXIS2_FAILURE;
                }
                axiom_node_add_child(sec_node, env, security_context_token_node);
            }
            key_reference_node = sct_provider_get_attached_reference(env, token, AXIS2_FALSE, rampart_context, msg_ctx);
        }
        else
        {
            /*get the unattachedReference and set to key_reference_node*/
            key_reference_node = sct_provider_get_unattached_reference(env, token, AXIS2_FALSE, rampart_context, msg_ctx);
        }
    }
    else if (token_type == RP_PROPERTY_SAML_TOKEN)
    {
        if (include)
        {
            axiom_node_t *assertion = NULL;
            rampart_saml_token_t *saml = NULL;
            /* Get the saml info from context.First check weather it is a signature token.*/
            saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_SIGNATURE_TOKEN);            
            if (!saml)
            {
                saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);            
            }
            if (!saml)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rampart_signature] SAML token not specified.");
                return AXIS2_FAILURE;
            }
            /* If not already added to the header */
            if (!rampart_saml_token_is_added_to_header(saml, env))            
            {
                assertion = rampart_saml_token_get_assertion(saml, env);
                if (!assertion) 
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rampart_signature] SAML token not specified.");
                    return AXIS2_FAILURE;
                }
				axiom_node_add_child(sec_node, env, assertion);
                /* we are sure that key reference node is not added to the header */
                key_reference_node = rampart_saml_token_get_str(saml, env);            
                if (!key_reference_node)
                {
                    key_reference_node = oxs_saml_token_build_key_identifier_reference_local(env, NULL, assertion);
                }                
            }            
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rampart_signature] SAML tokens with unattached reference not supported.");
            return AXIS2_FAILURE;
        }
    }

    sign_ctx = oxs_sign_ctx_create(env);

    /* Set which parts to be signed*/
    oxs_sign_ctx_set_sign_parts(sign_ctx, env, 
        rampart_sig_create_sign_parts(env, rampart_context, nodes_to_sign, server_side, sign_parts_list));

    /*Get the binding type. Either symmetric or asymmetric for signature*/
    binding_type = rampart_context_get_binding_type(rampart_context,env);

    if(RP_PROPERTY_ASYMMETRIC_BINDING == binding_type)
    {
        /* Pack for asymmetric signature*/
        status = rampart_sig_pack_for_asym(env, rampart_context, sign_ctx);
    }
    else if(RP_PROPERTY_SYMMETRIC_BINDING == binding_type)
    {
        /* Pack for symmetric signature*/
        status = rampart_sig_pack_for_sym(env, rampart_context, sign_ctx, msg_ctx);
    }
    else
    {
        /*We do not support*/
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rampart_signature] Signature support only symmetric and asymmetric bindings.");
        return AXIS2_FAILURE;
    }
    
    /* All the things are ready for signing. So lets try signing*/
    status = oxs_xml_sig_sign(env, sign_ctx, sec_node, &sig_node);
    if(status!=AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_signature] Message signing failed.");
        return AXIS2_FAILURE;
    }

    /*build the key info inside signature node*/
    if(RP_PROPERTY_ASYMMETRIC_BINDING == binding_type)
    {
    	rampart_sig_prepare_key_info_for_asym_binding(env, rampart_context, sign_ctx, sig_node , cert_id, eki, is_direct_reference);
    }
    else if(RP_PROPERTY_SYMMETRIC_BINDING == binding_type)
    {
        oxs_key_t *signed_key = NULL;
        oxs_key_t *session_key = NULL;

        signed_key = oxs_sign_ctx_get_secret(sign_ctx, env);    
        session_key = rampart_context_get_signature_session_key(rampart_context, env);

        if(token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
        {
            if(0 == axutil_strcmp(oxs_key_get_name(session_key, env), oxs_key_get_name(signed_key, env))) 
            {
                /*Now then... we have used the security context token to sign*/
                axiom_node_t* key_info_node = NULL;
                key_info_node = oxs_token_build_key_info_element(env, sig_node);
                axiom_node_add_child(key_info_node, env, key_reference_node);
            }
            else
            {
                axiom_node_t *dk_token = NULL;
                /*We have used a derived key to sign. Note the NULL we pass for the enc_key_id*/
                rampart_sig_prepare_key_info_for_sym_binding(env, rampart_context, sign_ctx, sig_node, signed_key, NULL);
                /*In addition we need to add a DerivedKeyToken*/
                dk_token = oxs_derivation_build_derived_key_token_with_stre(env, signed_key, sec_node, key_reference_node, derived_key_version);
                /*We need to make DerivedKeyToken to appear before the sginature node*/
                oxs_axiom_interchange_nodes(env, dk_token, sig_node);
            }
        }
		else if(token_type == RP_PROPERTY_SAML_TOKEN)
		{
			if(0 == axutil_strcmp(oxs_key_get_name(session_key, env), oxs_key_get_name(signed_key, env))) 
            {
                /*Now then... we have used the security context token to sign*/
                axiom_node_t* key_info_node = NULL;
                key_info_node = oxs_token_build_key_info_element(env, sig_node);
                axiom_node_add_child(key_info_node, env, key_reference_node);
            }
            else
            {
                axiom_node_t *dk_token = NULL;
                /*We have used a derived key to sign. Note the NULL we pass for the enc_key_id*/
                rampart_sig_prepare_key_info_for_sym_binding(env, rampart_context, sign_ctx, sig_node, signed_key, NULL);
                /*In addition we need to add a DerivedKeyToken*/
                dk_token = oxs_derivation_build_derived_key_token_with_stre(env, signed_key, sec_node, key_reference_node, derived_key_version);
                /*We need to make DerivedKeyToken to appear before the sginature node*/
                oxs_axiom_interchange_nodes(env, dk_token, sig_node);
            }
		}
        else
        {
            if(server_side)
            {
                /*have to send EncryptedKeySHA1*/
                axis2_char_t *encrypted_key_hash = NULL;
                axiom_node_t *identifier_token = NULL;
                encrypted_key_hash = oxs_key_get_key_sha(session_key, env);
                key_reference_node = oxs_token_build_security_token_reference_element(env, NULL); 
                identifier_token = oxs_token_build_key_identifier_element(env, key_reference_node, 
                                    OXS_ENCODING_BASE64BINARY, OXS_X509_ENCRYPTED_KEY_SHA1, encrypted_key_hash);

                if(0 == axutil_strcmp(oxs_key_get_name(session_key, env), oxs_key_get_name(signed_key, env))) 
                {
                    /*Now then... we have used the session key to sign*/
                    axiom_node_t* key_info_node = NULL;
                    key_info_node = oxs_token_build_key_info_element(env, sig_node);
                    axiom_node_add_child(key_info_node, env, key_reference_node);
                }
                else
                {
                    axiom_node_t *dk_token = NULL;
                    /*We have used a derived key to sign. Note the NULL we pass for the enc_key_id*/
                    rampart_sig_prepare_key_info_for_sym_binding(env, rampart_context, sign_ctx, sig_node, signed_key, NULL);
                    /*In addition we need to add a DerivedKeyToken*/
                    dk_token = oxs_derivation_build_derived_key_token_with_stre(env, signed_key, sec_node, key_reference_node, derived_key_version);
                    /*We need to make DerivedKeyToken to appear before the sginature node*/
                    oxs_axiom_interchange_nodes(env, dk_token, sig_node);
                }
            }
            else
            {
                axiom_node_t *encrypted_key_node = NULL;
                axis2_char_t *enc_key_id = NULL;
		        axis2_bool_t free_enc_key_id = AXIS2_FALSE;

                /*If there is an EncryptedKey element use the Id. If not, generate an Id and use it*/ 
                encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY); 
                if(!encrypted_key_node)
                {
                    /*There is no EncryptedKey so generate one*/
                    status = rampart_enc_encrypt_session_key(env, session_key, msg_ctx, rampart_context, sec_node, NULL );
                    if(AXIS2_FAILURE == status)
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_signature] Cannot encrypt the session key " );
                        return AXIS2_FAILURE;
                    } 
                    encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
                    /*Add Id attribute*/
                    enc_key_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCKEY_ID);
			        free_enc_key_id = AXIS2_TRUE;
                    oxs_axiom_add_attribute(env, encrypted_key_node, NULL, NULL, OXS_ATTR_ID, enc_key_id);
                    /*And we have to make sure that we place this newly generated EncryptedKey node above the Signature node*/
                    oxs_axiom_interchange_nodes(env, encrypted_key_node, sig_node);
                }
                else
                {
                    /*There is the encrypted key. May be used by the encryption process. So get the Id and use it*/
                    enc_key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
                }

                /* Now if the signed key is the session key. We need to Encrypt it. If it's a derived key, we need to Attach a 
                 * DerivedKeyToken and encrypt the session key if not done already */    
                if(0 == axutil_strcmp(oxs_key_get_name(session_key, env), oxs_key_get_name(signed_key, env))) 
                {
                    /*Now then... we have used the session key to sign*/
                    rampart_sig_prepare_key_info_for_sym_binding(env, rampart_context, sign_ctx, sig_node, signed_key, enc_key_id);
                }
                else
                {
                    axiom_node_t *dk_token = NULL;
                    /*We have used a derived key to sign. Note the NULL we pass for the enc_key_id*/
                    rampart_sig_prepare_key_info_for_sym_binding(env, rampart_context, sign_ctx, sig_node, signed_key, NULL  );
                    /*In addition we need to add a DerivedKeyToken after the EncryptedKey*/
                    dk_token = oxs_derivation_build_derived_key_token(env, signed_key, sec_node, enc_key_id ,OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY, derived_key_version);
                    /*We need to make DerivedKeyToken to appear before the sginature node*/
                    oxs_axiom_interchange_nodes(env, dk_token, sig_node);
                }
		        if (free_enc_key_id)
		        {
			        AXIS2_FREE(env->allocator, enc_key_id);
		        }
            }
        }
    }

    /*If we have used derived keys, then we need to free the key in sign_ctx*/
    if((RP_PROPERTY_SYMMETRIC_BINDING == binding_type) && (rampart_context_check_is_derived_keys (env, token)))
    {
        oxs_key_t *sig_ctx_dk = NULL;
        sig_ctx_dk = oxs_sign_ctx_get_secret(sign_ctx, env);
        if(sig_ctx_dk && (OXS_KEY_USAGE_DERIVED == oxs_key_get_usage(sig_ctx_dk, env)))
        {
            oxs_key_free(sig_ctx_dk, env);
            sig_ctx_dk = NULL;
        }
    }
    /*Free sig ctx*/
    oxs_sign_ctx_free(sign_ctx, env);
    sign_ctx = NULL;

    if(status)
    {
        return rampart_sig_endorse_sign(env, msg_ctx, rampart_context, soap_envelope, sec_node);
    }

    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_sig_confirm_signature(const axutil_env_t *env,
                             axis2_msg_ctx_t *msg_ctx,
                             rampart_context_t *rampart_context,
                             axiom_node_t *sec_node)
{
    axis2_char_t *id = NULL;
    axis2_char_t *sig_val = NULL;
    
    /*Check whether the request was signed*/

    /*If there is no signature. @Value is not present*/
    /*If the request has signed, then the @Value = contents of <ds:SignatureValue>*/

    /*Generate an Id*/
    /*id = oxs_util_generate_id(env,(axis2_char_t*)OXS_SIG_CONF_ID);*/
     
    /*Get SPR*/
    sig_val = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VALUE);

    /*Build wsse11:SignatureConfirmation element */
    oxs_token_build_signature_confirmation_element(env, sec_node, id, sig_val);

    /*id = oxs_util_generate_id(env,(axis2_char_t*)OXS_SIG_CONF_ID);*/
    sig_val = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_ENDORSED_VALUE);
    if(sig_val)
    {
        oxs_token_build_signature_confirmation_element(env, sec_node, id, sig_val);
    }

    return AXIS2_SUCCESS;

}


axis2_status_t AXIS2_CALL
rampart_sig_add_x509_token(const axutil_env_t *env, 
                               rampart_context_t *rampart_context, 
                               axiom_node_t *sec_node,
                               axis2_char_t *cert_id)
{
    oxs_x509_cert_t *cert = NULL;
    axiom_node_t *bst_node = NULL;    
    axis2_char_t *bst_data = NULL;
    oxs_key_mgr_t *key_mgr = NULL;

	key_mgr = rampart_context_get_key_mgr(rampart_context, env);
    /* 
     * If the requirement is to include the token we should build the binary security
     * token element here.
     */
    cert = oxs_key_mgr_get_certificate(key_mgr, env);
    if (!cert)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Cannot get certificate");
        return AXIS2_FAILURE;
    }    
    bst_data = oxs_x509_cert_get_data(cert, env);
    if (!bst_data)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Certificate data cannot be loaded from the cert.");
        return AXIS2_FAILURE;
    }

    bst_node = oxs_token_build_binary_security_token_element(env, sec_node,
               cert_id , OXS_ENCODING_BASE64BINARY, OXS_VALUE_X509V3, bst_data);
    if (!bst_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Binary Security Token creation failed.");
        return AXIS2_FAILURE;
    }
    oxs_x509_cert_free(cert, env);
    cert = NULL;
    return AXIS2_SUCCESS;
}

axutil_array_list_t * AXIS2_CALL
rampart_sig_create_sign_parts(const axutil_env_t *env, 
                              rampart_context_t *rampart_context, 
                              axutil_array_list_t *nodes_to_sign, 
                              axis2_bool_t server_side,
                              axutil_array_list_t *sign_parts)
{
    int i = 0;
    axis2_char_t *digest_method = NULL;    

    axiom_node_t *node_to_sign = NULL;
    axis2_char_t *id = NULL;
    oxs_sign_part_t *sign_part = NULL;
    oxs_transform_t *tr = NULL;
    axutil_array_list_t *tr_list = NULL;

    /*content of sign_parts + sign parts created from nodes_to_sign will be copied to 
    this list. We can put everything to sign_parts, but hard to keep track of who has to delete
    sign_parts in case if there is an error. Since it is copied, sign_parts can be deleted in 
    rampart_shb_build_message retardless of return status. Modified due to SAML modifications*/
    axutil_array_list_t *new_sign_parts = NULL;
    new_sign_parts = axutil_array_list_create(env, 0);

    digest_method = rampart_context_get_digest_mtd(rampart_context, env);   

    /*copy the content of sign_parts to new_sign_parts*/
    for(i = 0; i < axutil_array_list_size(sign_parts, env); i++)
    {
        sign_part = (oxs_sign_part_t*)axutil_array_list_get(sign_parts, env, i);
        if(sign_part)
        {
            axutil_array_list_add(new_sign_parts, env, sign_part);
        }
    }

    /*Now we should create sign part for each node in the arraylist.*/
    for (i=0 ; i < axutil_array_list_size(nodes_to_sign, env); i++)
    {
        node_to_sign = (axiom_node_t *)axutil_array_list_get(nodes_to_sign, env, i);
        if (node_to_sign)
        {
            sign_part = oxs_sign_part_create(env);
            tr_list = axutil_array_list_create(env, 0);
            id = oxs_util_generate_id(env, (axis2_char_t*)OXS_SIG_ID);
            tr = oxs_transforms_factory_produce_transform(env,
                    OXS_HREF_TRANSFORM_XML_EXC_C14N);
            axutil_array_list_add(tr_list, env, tr);
            oxs_sign_part_set_transforms(sign_part, env, tr_list);
            /*oxs_axiom_add_attribute(env, node_to_sign, OXS_WSU, RAMPART_WSU_XMLNS,OXS_ATTR_ID,id);*/
            oxs_axiom_add_attribute(env, node_to_sign,
                                    RAMPART_WSU, RAMPART_WSU_XMLNS,OXS_ATTR_ID, id);
            oxs_sign_part_set_node(sign_part, env, node_to_sign);
            oxs_sign_part_set_digest_mtd(sign_part, env, digest_method);
            axutil_array_list_add(new_sign_parts, env, sign_part);
            AXIS2_FREE(env->allocator, id);
            id = NULL;
        }
    } 
   
    /*if (rampart_context_is_include_supporting_token(rampart_context, env, server_side, AXIS2_FALSE, RP_PROPERTY_SAML_TOKEN))
    {        
        axiom_element_t *stre = NULL;
        axiom_node_t *strn = NULL, *assertion = NULL;
        axutil_qname_t *qname = NULL;*/
        /* These properties are guaranteed to exsists. If not we cannot reach this point. */
        /*rampart_saml_token_t *saml = rampart_context_get_saml_token(rampart_context, env, RP_PROPERTY_SIGNED_SUPPORTING_TOKEN);
        strn = rampart_saml_token_get_str(saml, env);
        assertion = rampart_saml_token_get_assertion(saml, env);
        stre = axiom_node_get_data_element(strn, env);

        qname = axutil_qname_create(env, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);
        sign_part = oxs_sign_part_create(env);
        tr_list = axutil_array_list_create(env, 0);*/
        /* If ID is not present we add it */
        /*id = axiom_element_get_attribute_value(stre, env, qname);
        if (!id)
        {
            id = oxs_util_generate_id(env, (axis2_char_t*)OXS_SIG_ID);
            oxs_axiom_add_attribute(env, strn,
                                RAMPART_WSU, RAMPART_WSU_XMLNS, OXS_ATTR_ID, id);
        }
        oxs_sign_part_set_id(sign_part, env, id);
        tr = oxs_transforms_factory_produce_transform(env,
                OXS_HREF_TRANSFORM_STR_TRANSFORM);
        axutil_array_list_add(tr_list, env, tr);
        oxs_sign_part_set_transforms(sign_part, env, tr_list);                */
        /* Sign the assertion, not the securitytokenreference */
     /*   oxs_sign_part_set_node(sign_part, env, strn);
        oxs_sign_part_set_digest_mtd(sign_part, env, digest_method);
        
        axutil_array_list_add(sign_parts, env, sign_part);
        AXIS2_FREE(env->allocator, id);
        id = NULL;
    }*/
    /*Free array list*/
    axutil_array_list_free(nodes_to_sign, env);
    nodes_to_sign = NULL;
    return new_sign_parts;
}


static axis2_status_t
rampart_sig_endorse_sign(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{
    axis2_bool_t server_side = AXIS2_FALSE;
    axiom_node_t *node_to_sign = NULL;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    axis2_bool_t include = AXIS2_FALSE;
    axis2_bool_t is_direct_reference = AXIS2_TRUE;
    oxs_sign_ctx_t *sign_ctx = NULL;
    axutil_array_list_t *nodes_to_sign = NULL;
    axis2_char_t *cert_id = NULL;
    axis2_char_t *eki = NULL;
    oxs_sign_part_t *sign_part = NULL;
    axutil_array_list_t *tr_list = NULL;
    oxs_transform_t *tr = NULL;
    axis2_char_t *digest_method = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *sig_node = NULL;
    axiom_namespace_t *sign_ns = NULL;

    /*endorsing will be only for client*/
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    if(server_side)
        return AXIS2_SUCCESS;

    /*if signature is not found, can't continue*/
    node_to_sign = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_SIGNATURE);
    if(!node_to_sign)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature]Endorsing signature, Sigature Not found");
        return AXIS2_FAILURE;
    }

    /*Now we have to check whether a token is specified. If not specified then no need to endorse*/
    token = rampart_context_get_endorsing_token(rampart_context, env);
    if(!token)
    {
        AXIS2_LOG_INFO(env->log,
                        "[rampart][rampart_signature] Endorsing Token is not specified. No need to endorse");
        return AXIS2_SUCCESS;
    }

    token_type = rp_property_get_type(token, env);
	if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Token type %d not supported", token_type);
        return AXIS2_FAILURE;
    }

    /*this implementaion supports only x509 to endorse signature*/
    if(token_type != RP_PROPERTY_X509_TOKEN)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Token type %d not supported for endorsing", token_type);
        return AXIS2_FAILURE;
    }

    /* Determine weather we need to include the token */
    include = rampart_context_is_token_include(rampart_context, token, 
                                                token_type, server_side, 
                                                AXIS2_FALSE, env);
    if (token_type == RP_PROPERTY_X509_TOKEN) 
    {        
		if (include) 
        {
            cert_id = oxs_util_generate_id(env,(axis2_char_t*)OXS_CERT_ID);
			if (!rampart_sig_add_x509_token(env, rampart_context, sec_node, cert_id)) 
            {
				return AXIS2_FAILURE;
			}
			/*This flag will be useful when creating key Info element.*/
			is_direct_reference = AXIS2_TRUE;
			eki = RAMPART_STR_DIRECT_REFERENCE;			
		}
		else 
        {
			eki = rampart_context_get_key_identifier(rampart_context, token, env);
            if(!eki) 
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_signature] Cannot attach the token.");
                axutil_array_list_free(nodes_to_sign, env);
                nodes_to_sign = NULL;
                return AXIS2_FAILURE;
            }
			is_direct_reference = AXIS2_FALSE;
		}
    }

    sign_ctx = oxs_sign_ctx_create(env);

    /* Set signatures to be endorsed*/
    nodes_to_sign = axutil_array_list_create(env, 0);
    digest_method = rampart_context_get_digest_mtd(rampart_context, env);   
    sign_part = oxs_sign_part_create(env);
    sign_ns = axiom_namespace_create(env, NULL, NULL); /*we have to get the id from "Id" of signature, not from "wsu:Id"*/
    oxs_sign_part_set_sign_namespace(sign_part, env, sign_ns);
    tr_list = axutil_array_list_create(env, 0);
    tr = oxs_transforms_factory_produce_transform(env,
            OXS_HREF_TRANSFORM_XML_EXC_C14N);
    axutil_array_list_add(tr_list, env, tr);
    oxs_sign_part_set_transforms(sign_part, env, tr_list);
    oxs_sign_part_set_node(sign_part, env, node_to_sign);
    oxs_sign_part_set_digest_mtd(sign_part, env, digest_method);
    axutil_array_list_add(nodes_to_sign, env, sign_part);

    oxs_sign_ctx_set_sign_parts(sign_ctx, env, nodes_to_sign);

    /* We support asymmetric endorsing only for this release. So, pack for asymmetric signature*/
    status = rampart_sig_pack_for_asym(env, rampart_context, sign_ctx);
    
    /* All the things are ready for signing. So lets try signing*/
    status = oxs_xml_sig_sign(env, sign_ctx, sec_node, &sig_node);
    if(status!=AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_signature] Message endorsing failed.");
        return AXIS2_FAILURE;
    }

    /* We support asymmetric endorsing only for this release. 
     * So, build the key info inside signature node for asymmetric signature
     */
    rampart_sig_prepare_key_info_for_asym_binding(env, rampart_context, sign_ctx, sig_node , cert_id, eki, is_direct_reference);

    /*Free sig ctx*/
    oxs_sign_ctx_free(sign_ctx, env);
    sign_ctx = NULL;

    return status;
}



