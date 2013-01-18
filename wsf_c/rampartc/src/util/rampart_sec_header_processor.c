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

#include <axis2_util.h>
#include <stdio.h>
#include <rampart_encryption.h>
#include <rampart_constants.h>
#include <rampart_sec_header_processor.h>
#include <rampart_username_token.h>
#include <rampart_timestamp_token.h>
#include <rampart_util.h>
#include <rampart_sec_processed_result.h>
#include <rampart_handler_util.h>
#include <rampart_token_processor.h>
#include <rampart_policy_validator.h>
#include <oxs_constants.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_key.h>
#include <oxs_axiom.h>
#include <oxs_asym_ctx.h>
#include <oxs_tokens.h>
#include <oxs_derivation.h>
#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <axis2_key_type.h>
#include <oxs_sign_ctx.h>
#include <oxs_xml_signature.h>
#include <oxs_key_mgr.h>
#include <rampart_replay_detector.h>
#include <rampart_sct_provider_utility.h>
#include <saml.h>
#include <rampart_saml.h>
#include <rampart_saml_token.h>
#include <axiom_util.h>
/*Private functions*/

/*Get the security context token and store it in key array*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_shp_add_security_context_token(
    const axutil_env_t* env,
    axis2_char_t* identifier,
    axis2_char_t* key_name,
    rampart_context_t* rampart_context,
    axis2_msg_ctx_t* msg_ctx)
{
    oxs_buffer_t *key_buf = NULL;
    oxs_key_t* key = NULL;

    /*get the shared secret and create the key*/
    key_buf = sct_provider_get_secret_using_id(env, identifier, rampart_context, msg_ctx);
    if(!key_buf)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "Cannot get shared secret of security context token");
        return AXIS2_FAILURE;
    }

    key = oxs_key_create(env);
    oxs_key_populate(key, env, oxs_buffer_get_data(key_buf, env), key_name,
        oxs_buffer_get_size(key_buf, env), OXS_KEY_USAGE_NONE);

    rampart_context_add_key(rampart_context, env, key);
    return AXIS2_SUCCESS;
}



static void
rampart_shp_store_token_id(const axutil_env_t *env, 
                         axiom_node_t *key_info_node, 
                         rampart_context_t *rampart_context, 
                         axiom_node_t *sec_node, 
                         axis2_bool_t is_encryption,
                         axis2_msg_ctx_t* msg_ctx)
{
    axis2_char_t *token_id = NULL;
    axiom_node_t* key_node = NULL;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    rp_security_context_token_t *security_context_token = NULL;
    axis2_char_t *needed_value_type = NULL;
    axis2_char_t *wsc_ns_uri = NULL;

    if(is_encryption)
        token_id = rampart_context_get_encryption_token_id(rampart_context, env, msg_ctx);
    else
        token_id = rampart_context_get_signature_token_id(rampart_context, env, msg_ctx);

    /*if already stored, then can return*/
    if(token_id)
        return;

    /*if not symmetric binding, then return*/
    if (rampart_context_get_binding_type(rampart_context,env) != RP_PROPERTY_SYMMETRIC_BINDING)
        return;

    /*if not server side, then return*/
    if(!axis2_msg_ctx_get_server_side(msg_ctx,env))
        return;

    /*if the token to be used is not security context token, then return*/
    token = rampart_context_get_token(rampart_context, env,
                                      is_encryption, AXIS2_TRUE, AXIS2_TRUE);
    token_type = rp_property_get_type(token, env);
    if((token_type != RP_PROPERTY_SECURITY_CONTEXT_TOKEN) && (token_type != RP_PROPERTY_X509_TOKEN))
        return;

    /* Get the version of security context token */
    security_context_token = (rp_security_context_token_t *)rp_property_get_value(token, env);
    if(rp_security_context_token_get_sc10_security_context_token(security_context_token, env))
    {
        needed_value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02;
        wsc_ns_uri = OXS_WSC_NS_05_02;
    }
    else
    {
        needed_value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12;
        wsc_ns_uri = OXS_WSC_NS_05_12;
    }

    key_node = key_info_node;

    while(!token_id)
    {
        axis2_char_t* id = NULL;
        axis2_char_t *cur_local_name = NULL;
        axiom_node_t *str_node = NULL;
        axiom_node_t *ref_node = NULL;
        axis2_char_t *ref_val = NULL;

        /*Get the STR*/
        str_node = oxs_axiom_get_first_child_node_by_name(env, key_node, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);
        if(!str_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Failed to get security token reference node");
            break;
        }

        /*Get Reference element*/
        ref_node = oxs_axiom_get_first_child_node_by_name(env, str_node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
        if(!ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Failed to get reference node from security token reference");
            break;
        }

        /*Get the reference value in the @URI*/
        ref_val = oxs_token_get_reference(env, ref_node);
        if(ref_val[0] != '#')
        {
            axis2_char_t* value_type = NULL;
            value_type = oxs_token_get_reference_value_type(env, ref_node);
            if(!axutil_strcmp(value_type, needed_value_type))
            {
                token_id = axutil_strdup(env, ref_val);
                break;
            }
        }

        id = axutil_string_substring_starting_at(axutil_strdup(env, ref_val), 1);
        key_node = oxs_axiom_get_node_by_id(env, sec_node, OXS_ATTR_ID, id, OXS_WSU_XMLNS);
        if(!key_node)
            break;

        cur_local_name = axiom_util_get_localname(key_node, env);
        if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SECURITY_CONTEXT_TOKEN))
        {
            axiom_node_t *identifier_node = NULL;

            
            /*Get the identifier node*/
            identifier_node = oxs_axiom_get_first_child_node_by_name(
                env, key_node, OXS_NODE_IDENTIFIER, wsc_ns_uri, NULL);

            if(!identifier_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Cannot find identifier node in security context token");
                break;
            }
            token_id = oxs_axiom_get_node_content(env, identifier_node);
            break;
        }
        else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_ENCRYPTED_KEY))
        {
            token_id = oxs_axiom_get_attribute_value_of_node_by_name(env, key_node, OXS_ATTR_ID, NULL);
            break;
        }
    }

    /*if same key is used for encryption and signature, then store it at both place*/
    if(rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context))
    {
        if(is_encryption)
            rampart_context_set_encryption_token_id(rampart_context, env, token_id, msg_ctx);
        else
            rampart_context_set_signature_token_id(rampart_context, env, token_id, msg_ctx);
    }
    else
    {
        rampart_context_set_encryption_token_id(rampart_context, env, token_id, msg_ctx);
        rampart_context_set_signature_token_id(rampart_context, env, token_id, msg_ctx);
    }
}

#if 0
/*Process a KeyInfo and return the key*/
static oxs_key_t* 
rampart_shp_get_key_for_key_info(const axutil_env_t* env, 
                                 axiom_node_t* key_info_node, 
                                 rampart_context_t* rampart_context, 
                                 axis2_msg_ctx_t *msg_ctx,
								 axis2_bool_t is_signature)
{
    oxs_key_t *key = NULL;
    axiom_node_t *str_node = NULL;
    axiom_node_t *ref_node = NULL;
    axis2_char_t *ref_val = NULL;
    axis2_char_t *id = NULL;
    axis2_bool_t external_reference = AXIS2_TRUE;

    /*Get the STR*/
    str_node = oxs_axiom_get_first_child_node_by_name(env, key_info_node, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);
    if(!str_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Failed to get security token reference node");
        return NULL;
    }

    /*Get Reference element*/
    ref_node = oxs_axiom_get_first_child_node_by_name(env, str_node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_node)
    {
        axis2_char_t *value_type = NULL;
        axis2_char_t *value = NULL;
        oxs_key_t *key = NULL;

        ref_node = oxs_axiom_get_first_child_node_by_name(env, str_node, OXS_NODE_KEY_IDENTIFIER, OXS_WSSE_XMLNS, NULL);
        if(!ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Failed to get reference node from security token reference");
            return NULL;
        }
        value_type = oxs_axiom_get_attribute_value_of_node_by_name(env, ref_node, OXS_ATTR_VALUE_TYPE, NULL);
        if(axutil_strcmp(value_type, OXS_X509_ENCRYPTED_KEY_SHA1) == 0)
        {
			value = oxs_axiom_get_node_content(env, ref_node);
			if(!value)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Failed to get value of EncryptedKeySHA1");
				return NULL;
			}

			key = rampart_context_get_key_using_hash(rampart_context, env, value);
			if(!key)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Cannot get key corresponding to EncryptedKeySHA1");
			}            
        }
		/* SAML token reference */
		else if(axutil_strcmp(value_type, OXS_ST_KEY_ID_VALUE_TYPE) == 0)
		{
			axiom_node_t *assertion = NULL;						
			rampart_saml_token_t *saml = NULL;
            rampart_st_type_t tok_type;                        
			oxs_key_mgr_t *key_mgr = NULL;
			openssl_pkey_t *pvt_key = NULL;

			key_mgr = rampart_context_get_key_mgr(rampart_context, env);
            pvt_key = oxs_key_mgr_get_prv_key(key_mgr, env);
			if (!pvt_key)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Cannot load private key");
				return NULL;					
			}                        
            
			assertion = oxs_saml_token_get_from_key_identifer_reference(env, ref_node, NULL);
			if (!assertion)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Cannot get key SAML Assertion");
				return NULL;					
			}
			if (is_signature)
            {
                tok_type = RAMPART_ST_TYPE_SIGNATURE_TOKEN;
            }
            else
            {
                tok_type = RAMPART_ST_TYPE_ENCRYPTION_TOKEN;
            }
			saml = rampart_saml_add_token(rampart_context, env, assertion, str_node, tok_type); 
			key = rampart_saml_token_get_session_key(saml, env);
			if (!key) 
			{
				key = saml_assertion_get_session_key(env, assertion, 
                               pvt_key);
				rampart_saml_token_set_session_key(saml, env, key);
				oxs_key_set_name(key, env, "for-algo");
			}            
			if(!key)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Cannot get key corresponding to EncryptedKeySHA1");
			}
		}
		else 
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Failed to identify Key Identifier %s", value_type);
            return NULL;
		}
        return key;        
    }
    else
    {
        /*Get the reference value in the @URI*/
        ref_val = oxs_token_get_reference(env, ref_node);
        if(ref_val[0] == '#')
        {
            /*Need to remove # sign from the ID*/
            id = axutil_string_substring_starting_at(axutil_strdup(env, ref_val), 1);
            external_reference = AXIS2_FALSE;
        }
        else
        {
            id = axutil_strdup(env, ref_val);
        }
    }

    if(!id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp]Failed to get key name from reference node");
        return NULL;
    }
    
    key = rampart_context_get_key(rampart_context, env, id);
    if(!key && external_reference)
    {
        axis2_char_t* value_type = NULL;
        value_type = oxs_token_get_reference_value_type(env, ref_node);
        if((0 == axutil_strcmp(value_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02))||
            (0 == axutil_strcmp(value_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12)))
        {
            rampart_shp_add_security_context_token(env, id, id, rampart_context, msg_ctx);
        }
        key = rampart_context_get_key(rampart_context, env, id);
    }

	AXIS2_FREE(env->allocator, id);
    return key;
}
#endif

static axis2_bool_t
rampart_shp_validate_qnames(
    const axutil_env_t *env,
    axiom_node_t *node)

{
    axiom_element_t *node_ele = NULL;
    axutil_qname_t *qname = NULL;
    axutil_qname_t *node_qname = NULL;
    axis2_char_t *local_name = NULL;

    node_ele = axiom_node_get_data_element(node, env);
    if(!node_ele)
        return AXIS2_FALSE;

    local_name = axiom_element_get_localname(node_ele,env);
    if(!local_name){
        return AXIS2_FALSE;
    }
    if(axutil_strcmp(local_name, RAMPART_SECURITY_TIMESTAMP) == 0)
    {
        qname = axutil_qname_create(env, local_name, RAMPART_WSU_XMLNS, NULL/*RAMPART_WSU*/);
    }
    else if(axutil_strcmp(local_name, RAMPART_SECURITY_USERNAMETOKEN) ==0)
    {
        qname = axutil_qname_create(env, local_name, RAMPART_WSSE_XMLNS, NULL/*RAMPART_WSSE*/);
    }
    else if(axutil_strcmp(local_name,OXS_NODE_ENCRYPTED_KEY)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_ENC_NS, NULL/*OXS_XENC*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_ENCRYPTED_DATA)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_ENC_NS, NULL/*OXS_XENC*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_SIGNATURE)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_DSIG_NS, NULL/*OXS_DS*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_BINARY_SECURITY_TOKEN) == 0)
    {
        return AXIS2_FALSE;
    }
    else if(axutil_strcmp(local_name, OXS_NODE_REFERENCE_LIST)==0)
    {
        return AXIS2_FALSE;
    }
    else
    {
        return AXIS2_FALSE;
    }

    if(!qname)
    {
        return AXIS2_FALSE;
    }
    node_qname = axiom_element_get_qname(node_ele, env, node);

    if(!node_qname)
    {
        axutil_qname_free(qname, env);
        qname = NULL;
        return AXIS2_FALSE;
    }

    if(axutil_qname_equals(qname, env, node_qname))
    {
        axutil_qname_free(qname, env);
        qname = NULL;
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}

/*static oxs_x509_cert_t *get_receiver_x509_cert(
    const axutil_env_t *env,
    rampart_context_t *rampart_context)
{
    return rampart_context_get_receiver_certificate(rampart_context, env);
}*/

static axis2_status_t
rampart_shp_process_signature_confirmation(const axutil_env_t *env,
                                   axis2_msg_ctx_t *msg_ctx,
                                   rampart_context_t *rampart_context,
                                   axiom_node_t *cur_node)
{
    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_CONFIRM_FOUND, RAMPART_YES);
    return AXIS2_SUCCESS;
}

static axis2_status_t
rampart_shp_process_timestamptoken(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_node_t *ts_node)
{
    axis2_status_t valid_ts = AXIS2_FAILURE;

    if(!rampart_context_is_include_timestamp(rampart_context, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Timestamp should not be in the message.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
            "Timestamp should not be in the message ", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
        return AXIS2_FAILURE;
    }
    else
    {
        if(!rampart_shp_validate_qnames(env, ts_node))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]QName for given timestamp is not valid.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                "Error in the Timestamp Element. ", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
            return AXIS2_FAILURE;
        }

        valid_ts = rampart_timestamp_token_validate(
            env, msg_ctx, ts_node, rampart_context_get_clock_skew_buffer(rampart_context, env));

        if (valid_ts)
        {
            AXIS2_LOG_INFO(env->log, "[rampart]Succesfully validated the timestamp ");
            return AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Timestamp is not valid");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                "Timestamp is not valid", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
            return AXIS2_FAILURE;
        }
    }
}

static axis2_status_t
rampart_shp_process_usernametoken(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_node_t *ut_node)
{
    axis2_status_t valid_user = AXIS2_FAILURE;

    if(!rampart_context_is_include_username_token(rampart_context, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Username token should not be in the message.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
            "Username Token not expected", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
        return AXIS2_FAILURE;
    }
    else
    {
        if(!rampart_shp_validate_qnames(env, ut_node))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Error in validating qnames for the username token");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
                "Error in the Username token.", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
            return AXIS2_FAILURE;
        }

        AXIS2_LOG_INFO(env->log, "[rampart]Validating UsernameToken");
        valid_user = rampart_username_token_validate(env, msg_ctx, ut_node, rampart_context);
    }

    if (valid_user)
    {
        AXIS2_LOG_INFO(env->log, "[rampart]Validating UsernameToken SUCCESS");
        return AXIS2_SUCCESS;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Validating UsernameToken FAILED");
        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION, 
                "UsernameToken validation failed.", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
        }
        return AXIS2_FAILURE;
    }
}

static axis2_status_t
rampart_shp_process_security_context_token(
    const axutil_env_t *env, 
    axiom_node_t *token_node, 
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *identifier_node = NULL;
    axis2_char_t *identifier = NULL;
    axis2_char_t *key_name = NULL;

    /*Check whether security context token is valid */
    if(sct_provider_validate_security_context_token(env, token_node, rampart_context, msg_ctx)
        != AXIS2_SUCCESS)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
            "Security context token validation failed.", 
            RAMPART_FAULT_INVALID_SECURITY_TOKEN, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart][shp] Security context token validation failed.");
        return AXIS2_FAILURE;
    }

    /*Get the identifier node*/
    identifier_node = oxs_axiom_get_first_child_node_by_name(
        env, token_node, OXS_NODE_IDENTIFIER, OXS_WSC_NS_05_02, NULL);

    if(!identifier_node)
    {
        /* check other namespace as well */
        identifier_node = oxs_axiom_get_first_child_node_by_name(
            env, token_node, OXS_NODE_IDENTIFIER, OXS_WSC_NS_05_12, NULL);
    }

    if(!identifier_node)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
            "Cannot find identifier node in security context token", 
            RAMPART_FAULT_INVALID_SECURITY_TOKEN, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart][shp] Cannot find identifier node in security context token");
        return AXIS2_FAILURE;
    }

    identifier = oxs_axiom_get_node_content(env, identifier_node);
    if(!identifier)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN, 
            "Cannot find identifier content in security context token", 
            RAMPART_FAULT_INVALID_SECURITY_TOKEN, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart][shp] Cannot find identifier content in security context token");
        return AXIS2_FAILURE;
    }

    key_name = oxs_axiom_get_attribute_value_of_node_by_name(
        env, token_node, OXS_ATTR_ID, OXS_WSU_XMLNS);
    return rampart_shp_add_security_context_token(
        env, identifier, key_name, rampart_context, msg_ctx);
}

static axis2_status_t
rampart_shp_process_encrypted_key(const axutil_env_t *env,
                                  axis2_msg_ctx_t *msg_ctx,
                                  rampart_context_t *rampart_context,
                                  axiom_soap_envelope_t *soap_envelope,
                                  axiom_node_t *sec_node,
                                  axiom_node_t *encrypted_key_node)
{
    axiom_node_t *ref_list_node = NULL;
    axiom_node_t *enc_mtd_node = NULL;
    axutil_array_list_t *reference_list = NULL;
    axis2_char_t *enc_asym_algo = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    oxs_asym_ctx_t *asym_ctx = NULL;
    oxs_key_t *decrypted_sym_key = NULL;
	oxs_key_mgr_t *key_mgr = NULL;
    axis2_char_t *enc_asym_algo_in_pol = NULL;
    axis2_char_t *enc_sym_algo_in_pol = NULL;
    openssl_pkey_t *open_prvkey = NULL;
    int i = 0;
    /*void *key_buf = NULL;*/
	axis2_char_t *prv_key_file = NULL;

    /*Get EncryptedData references */
    ref_list_node = oxs_axiom_get_first_child_node_by_name(
                        env, encrypted_key_node, OXS_NODE_REFERENCE_LIST, OXS_ENC_NS, NULL);
    
    /* reference list is not a mandatory item in encrypted key. */
    if(ref_list_node)
    {
        reference_list = oxs_token_get_reference_list_data(env, ref_list_node);
    }

    /*Get the algorithm to decrypt the sesison key*/
    enc_mtd_node = oxs_axiom_get_first_child_node_by_name(
                       env, encrypted_key_node, OXS_NODE_ENCRYPTION_METHOD, OXS_ENC_NS, NULL);
    enc_asym_algo = oxs_token_get_encryption_method(env, enc_mtd_node);

    /*If the reference list > 0 then We have nodes to decrypt. Next step is to get the encrypted key*/
    /*Obtain the session key which is encrypted*/
    /*Create an asym_ctx*/
    /*We should verify the algorithm with policy*/

    enc_asym_algo_in_pol = rampart_context_get_enc_asym_algo(rampart_context, env);
    if(!enc_asym_algo_in_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Error in the policy. No asym algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Assymetric enc algorithm not specified in policy.");
        return AXIS2_FAILURE;
    }

    /*If the algo tally with the policy?*/
    if(axutil_strcmp(enc_asym_algo_in_pol, enc_asym_algo) != 0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "The key is encrypted with the wrong algorithm");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "The key is encrypted with the wrong algorithm", RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
        return AXIS2_FAILURE;
    }
    
	key_mgr = rampart_context_get_key_mgr(rampart_context, env);
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, enc_asym_algo);

   /* key_buf = rampart_context_get_prv_key(rampart_context, env);
    if(key_buf)
    {
        axis2_key_type_t type = 0;
        type = rampart_context_get_prv_key_type(rampart_context, env);
        if(type == AXIS2_KEY_TYPE_PEM)
        {
			oxs_key_mgr_set_format(key_mgr, env, OXS_KEY_MGR_FORMAT_PEM);
			oxs_key_mgr_set_pem_buf(key_mgr, env, key_buf);
        }
    } */   
    oxs_asym_ctx_set_operation(asym_ctx, env, OXS_ASYM_CTX_OPERATION_PRV_DECRYPT);
	prv_key_file = rampart_context_get_private_key_file(rampart_context, env);   
	oxs_key_mgr_set_format(key_mgr, env,  oxs_util_get_format_by_file_extension(env, prv_key_file));

    /* TODO:Populate assymetric context */
	open_prvkey = oxs_key_mgr_get_prv_key(key_mgr, env); 
    oxs_asym_ctx_set_private_key(asym_ctx, env, open_prvkey);

    /*Create an empty key*/
    decrypted_sym_key = oxs_key_create(env);

    /*Call decrypt for the EncryptedKey*/
    status = oxs_xml_enc_decrypt_key(env, asym_ctx,
                                     sec_node, encrypted_key_node,  decrypted_sym_key);


    if(AXIS2_FAILURE == status)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Cannot decrypt the EncryptedKey");
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Key decryption failed", RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
        return AXIS2_FAILURE;
    }
    /*We need to set the session key name= EncryptedKey@Id*/
    if(decrypted_sym_key){
        axis2_char_t *key_id = NULL;

        key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
        if(!key_id){
            key_id = "SESSION_KEY";
        }
        
        oxs_key_set_name(decrypted_sym_key, env, key_id);
    }
    /*Now we need to set this to the rampart context for future use*/
    rampart_context_add_key(rampart_context, env, decrypted_sym_key);

    /*Alright now we have the key used to encrypt the elements in the reference_list*/
    /*Go thru each and every node in the list and decrypt them*/

    /*Before decrypt we should get the symmetric algo from policy.
      So for each encrypted element we can compare the algo. */
    enc_sym_algo_in_pol = rampart_context_get_enc_sym_algo(rampart_context, env);
    if(!enc_sym_algo_in_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                      "Error in the policy. No summetric algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Symetric enc algorithm not specified in policy.");
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
        return AXIS2_FAILURE;
    }
    
    /* In some cases there might not be any references in the list. For example when the derived keys are in use. 
     * If there are references, that means those references are encrypted using the session key. So we need to decrypt 'em*/
    if(reference_list){
      for(i=0 ; i < axutil_array_list_size(reference_list, env); i++ )
      {
        axis2_char_t *id = NULL;
        axis2_char_t *id2 = NULL;
        axiom_node_t *enc_data_node = NULL;
        axiom_node_t *envelope_node = NULL;
        oxs_ctx_t *ctx = NULL;
        axiom_node_t *decrypted_node = NULL;
        axiom_node_t *mtd_node = NULL;
        axis2_char_t *sym_algo = NULL;
        axiom_soap_body_t *soap_body = NULL;

        /*This need to be done in order to build the soap body.Do not remove.*/
        soap_body = axiom_soap_envelope_get_body(soap_envelope, env);

        /*Get the i-th element and decrypt it */
        id = (axis2_char_t*)axutil_array_list_get(reference_list, env, i);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Decrypting node, ID=%s", id);

        /*Need to remove # sign from the ID*/
        id2 = axutil_string_substring_starting_at(id, 1);
        envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);

        /*Search for the node by its ID*/
        enc_data_node = oxs_axiom_get_node_by_id(env, envelope_node, OXS_ATTR_ID, id2, NULL);
        if(!enc_data_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Node with ID=%s cannot be found", id);

            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptedData element", 
                                        RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }
        /*Create an enc_ctx*/
        mtd_node = oxs_axiom_get_first_child_node_by_name(
                       env, enc_data_node, OXS_NODE_ENCRYPTION_METHOD, OXS_ENC_NS, NULL);

        if(!mtd_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot find EncryptionMethod Element");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptionMethod Element", 
                                    RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }

        sym_algo = oxs_token_get_encryption_method(env, mtd_node);
        if(!sym_algo)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the Symmetric Algorithm from Soap message.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptionMethod Element", 
                            RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;

            return AXIS2_FAILURE;
        }
        /*Would the encryption method tally with the policy?*/
        if(axutil_strcmp(sym_algo, enc_sym_algo_in_pol)!=0)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "The content is encrypted with the wrong algorithm");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                          "The content is encrypted with the wrong algorithm",
                                          RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;

        }
        /*Get ready for the decryption. Create an encryption ctx*/
        ctx = oxs_ctx_create(env);
        oxs_ctx_set_key(ctx, env, decrypted_sym_key);
        status = oxs_xml_enc_decrypt_node(env, ctx, enc_data_node, &decrypted_node);

        if(AXIS2_FAILURE == status)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Decryption of node with ID [%s] failed.", id);
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Data decryption failed", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }
        /*Check if the signture is encrypted*/
        if(0 == axutil_strcmp( OXS_NODE_SIGNATURE , axiom_util_get_localname(decrypted_node, env))){
            rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_ENCRYPTED, RAMPART_YES);
        }
        /*Check if the body is encrypted*/
        if(0 == axutil_strcmp(OXS_NODE_BODY , axiom_util_get_localname(axiom_node_get_parent(decrypted_node, env), env))){
             rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_BODY_ENCRYPTED, RAMPART_YES);
        }

        /*Free*/
        oxs_ctx_free(ctx, env);
        ctx = NULL;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Node ID=%s decrypted successfuly", id);
      }/*end of For loop*/
    }

    /*Set the security processed result*/
    rampart_set_security_processed_result(
        env, msg_ctx, RAMPART_SPR_ENC_CHECKED, RAMPART_YES);

    /*Free*/
    if(asym_ctx){
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
    }

    if(reference_list){
        axutil_array_list_free(reference_list, env);
        reference_list = NULL;
    }
    return AXIS2_SUCCESS;
}


static axis2_status_t
rampart_shp_process_reference_list(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *ref_list_node)
{

    axutil_array_list_t *reference_list = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    int i = 0;

    reference_list = oxs_token_get_reference_list_data(env,
                     ref_list_node);

    if((!reference_list) || (0 == axutil_array_list_size(reference_list, env)))
    {
        if (reference_list)
        {
            axutil_array_list_free(reference_list, env);
            reference_list = NULL;
        }

        AXIS2_LOG_INFO(env->log,
                       "[rampart][shp] Nothing Encrypted Outside security header");
        return AXIS2_SUCCESS;
    }
    /*Go thru each and every element in the ReferenceList*/
    for(i=0 ; i < axutil_array_list_size(reference_list, env); i++ )
    {
        axis2_char_t *id = NULL;
        axis2_char_t *id2 = NULL;
        axiom_node_t *enc_data_node = NULL;
        axiom_node_t *envelope_node = NULL;
        axiom_soap_body_t *soap_body = NULL;
        axiom_node_t *key_info_node = NULL;

        soap_body = axiom_soap_envelope_get_body(soap_envelope, env);

        id = (axis2_char_t*)axutil_array_list_get(reference_list, env, i);

        id2 = axutil_string_substring_starting_at(axutil_strdup(env, id), 1);

        envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);

        /*Search for the node by its ID*/
        enc_data_node = oxs_axiom_get_node_by_id(env, envelope_node, OXS_ATTR_ID, id2, NULL);
        if(!enc_data_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Node with ID=%s cannot be found", id2);
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Cannot find EncryptedData element", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            axutil_array_list_free(reference_list, env);
            reference_list = NULL;
            AXIS2_FREE(env->allocator, id2);
            id2 = NULL;
            return AXIS2_FAILURE;
        }

        AXIS2_FREE(env->allocator, id2);
        id2 = NULL;

        key_info_node = oxs_axiom_get_first_child_node_by_name(env, enc_data_node,
                        OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL);

        if(key_info_node)
        {
            oxs_key_t *key_to_decrypt = NULL;
            axis2_char_t *token_type = NULL;
            axis2_char_t *reference_method = NULL;
            oxs_x509_cert_t *cert = NULL;

            /*Get the sesison key*/
            /*key_to_decrypt = rampart_shp_get_key_for_key_info(env, key_info_node, rampart_context, msg_ctx, AXIS2_FALSE);*/
            if(rampart_token_process_key_info(env, key_info_node, sec_node, rampart_context,
                msg_ctx, AXIS2_FALSE, &cert, &key_to_decrypt, &token_type, &reference_method)
                != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]On processing ReferenceList, failed to get the key to decrypt");
                return AXIS2_FAILURE;
            }
            
            /*if security context token is used, then store it. It will be used by the server to encrypt the message*/
            rampart_shp_store_token_id(env, key_info_node, rampart_context, sec_node, AXIS2_TRUE, msg_ctx);

            if(key_to_decrypt)
            {
                /*Now if everything is fine we need to decrypt*/
                oxs_ctx_t *ctx = NULL;
                axiom_node_t *decrypted_node = NULL;

                ctx = oxs_ctx_create(env);
                oxs_ctx_set_key(ctx, env, key_to_decrypt);
                status = oxs_xml_enc_decrypt_node(env, ctx, enc_data_node, &decrypted_node);

                if(AXIS2_FAILURE == status)
                {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Data decryption failed", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
                        return AXIS2_FAILURE;
                }
                /*Check if the signture is encrypted*/
                if(0 == axutil_strcmp( OXS_NODE_SIGNATURE , axiom_util_get_localname(decrypted_node, env))){
                    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_ENCRYPTED, RAMPART_YES);
                }
                /*Check if the body is encrypted*/
                if(0 == axutil_strcmp(OXS_NODE_BODY , axiom_util_get_localname(axiom_node_get_parent(decrypted_node, env), env))){
                    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_BODY_ENCRYPTED, RAMPART_YES);
                }

                /*Free*/
                oxs_ctx_free(ctx, env);
                ctx = NULL;
            }
            else
            {
                /*Can't help. Error retrieving the key to decrypt the reference. */
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,  "[rampart][shp] On processing ReferenceList, failed to get the key to decrypt");
                return AXIS2_FAILURE;
            }
        }
    }

    axutil_array_list_free(reference_list, env);
    reference_list = NULL;
    return status;
}

#if 0
static axis2_status_t
rampart_shp_process_sym_binding_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{
    axis2_status_t status = AXIS2_FAILURE;
    oxs_sign_ctx_t *sign_ctx = NULL;
    axiom_node_t *envelope_node = NULL;
    axiom_node_t *key_info_node = NULL;
    oxs_key_t *key_to_verify = NULL;

    /*Get the envelope node*/
    envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
   
    /*Get the KeyInfo node*/
    key_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                            OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL);
    if(key_info_node)
    {
        key_to_verify = rampart_shp_get_key_for_key_info(env, key_info_node,rampart_context, msg_ctx, AXIS2_TRUE);
    }

    if(!key_to_verify)
    {
        /*It's an error*/
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Signature Verification failed. Cannot get the key to verify", 
                                RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp] Signature Verification failed. Cannot get the key to verify");

        return AXIS2_FAILURE;
    } 
    /*if security context token is used, then store it. It will be used by the server to sign the message*/
    rampart_shp_store_token_id(env, key_info_node, rampart_context, sec_node, AXIS2_FALSE, msg_ctx);

    /*Create sign context*/
    sign_ctx = oxs_sign_ctx_create(env);
    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_VERIFY);
    oxs_sign_ctx_set_secret(sign_ctx, env, key_to_verify);
    status = oxs_xml_sig_verify(env, sign_ctx, sig_node, envelope_node);
    if(status != AXIS2_SUCCESS)
    {
        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope( env, RAMPART_FAULT_INVALID_SECURITY,
                "Signature Verification failed.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        }

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp]Signature Verification failed.");

        return AXIS2_FAILURE;
    }
    /*Free Sign Ctx*/ 
    oxs_sign_ctx_free(sign_ctx, env);
    sign_ctx = NULL;

    return status;
}

static axis2_status_t
rampart_shp_process_asym_binding_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node,
    axis2_bool_t is_endorsing)
{

    oxs_sign_ctx_t *sign_ctx = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *digest_mtd_pol = NULL;
    axis2_char_t *sig_mtd_pol = NULL;
    axiom_node_t *sign_info_node = NULL;
    axiom_node_t *cur_node = NULL;
    rp_property_t *token = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    axis2_char_t *eki = NULL;
    rp_property_type_t token_type;
    axiom_node_t *str_node = NULL;
    axiom_node_t *str_child_node = NULL;
    axis2_char_t *str_child_name = NULL;
    oxs_x509_cert_t *cert = NULL;
    axiom_node_t *key_info_child_node = NULL;
    axiom_node_t *envelope_node = NULL;
    axis2_bool_t is_include_token = AXIS2_FALSE;

    server_side = axis2_msg_ctx_get_server_side(msg_ctx,env);
    sig_mtd_pol = rampart_context_get_asym_sig_algo(rampart_context,env);
    digest_mtd_pol = rampart_context_get_digest_mtd(rampart_context,env);

    if(!sig_mtd_pol || !digest_mtd_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                      "Error in the policy. No signature algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Error in policy, Specifying signature algorithms.");
        return AXIS2_FAILURE;
    }

    sign_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                     OXS_NODE_SIGNEDINFO, OXS_DSIG_NS, NULL);

    if(!sign_info_node)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "Sign info node not found.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Sign info cannot be found.Verifycation failed");
        return AXIS2_FAILURE;
    }

    cur_node = axiom_node_get_first_element(sign_info_node, env);
    while(cur_node)
    {
        axis2_char_t *localname =  NULL;
        localname  = axiom_util_get_localname(cur_node, env);
        if(axutil_strcmp(localname, OXS_NODE_SIGNATURE_METHOD)==0)
        {
            /*Verify the signature method with policy*/
            axis2_char_t *sig_mtd = NULL;
            sig_mtd = oxs_token_get_signature_method(env, cur_node);
            if(sig_mtd)
            {
                if(axutil_strcmp(sig_mtd_pol, sig_mtd)!=0)
                {
                    rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                  "Signed with Invalid algorithm", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][shp] Signed with Invalid algorithm");

                    return AXIS2_FAILURE;
                }
            }

            else
            {
                rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                              "Signature method element not found .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shp] Signature method element not found");
                return AXIS2_FAILURE;
            }
        }
        else if(axutil_strcmp(localname, OXS_NODE_REFERENCE) == 0)
        {
            /*Verify each digest method with policy*/
            axiom_node_t *digest_mtd_node = NULL;
            axis2_char_t *digest_mtd = NULL;
            digest_mtd_node  = oxs_axiom_get_first_child_node_by_name(env, cur_node,
                               OXS_NODE_DIGEST_METHOD, OXS_DSIG_NS, NULL);
            if(digest_mtd_node)
            {
                digest_mtd = oxs_token_get_digest_method(env, digest_mtd_node);
                if(digest_mtd)
                {
                    if(axutil_strcmp(digest_mtd_pol, digest_mtd)!=0)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Digest created with Invalid algorithm", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Digest Created with Invalid algorithm");

                        return AXIS2_FAILURE;
                    }
                }
                else
                {
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                return AXIS2_FAILURE;
            }
        }
        else
        {
            /*we do not need to process at this moment*/
        }
        cur_node = axiom_node_get_next_sibling(cur_node, env);
    }/*Eof While*/
    /*Get the key identifiers and build the certificate*/
    /*First we should verify with policy*/

    if(is_endorsing)
        token = rampart_context_get_endorsing_token(rampart_context, env);
    else
        token = rampart_context_get_token(rampart_context, env,
                                      AXIS2_FALSE, server_side, AXIS2_TRUE);

    if(!token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Signature Token is not specified");
        return AXIS2_FAILURE;
    }
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_UNSUPPORTED_SECURITY_TOKEN,
                                      "The token type does not supported", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] The token type does not supported");

        return  AXIS2_FAILURE;
    }
    
    is_include_token = rampart_context_is_token_include(
                           rampart_context, token, token_type, server_side, AXIS2_TRUE, env);

    key_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                    OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL );

    if(!key_info_node)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "Key Info node is not in the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp]Verify failed. Key Info node is not in the message.");
        return AXIS2_FAILURE;
    }
    str_node = oxs_axiom_get_first_child_node_by_name(env, key_info_node,
               OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);

    if(str_node)
    {
        /* A <wsse:SecurityTokenReference> element MAY reference an X.509 token type
         * by one of the following means:
         *  - Reference to a Subject Key Identifier (<wsse:KeyIdentifier>)
         *  - Reference to a Binary Security Token (<wsse:Reference> element that
         *    references a local <wsse:BinarySecurityToken> element or a remote data
         *    source that contains the token data itself)
         *  - Reference to an Issuer and Serial Number (<ds:X509Data> element that 
         *    contains a <ds:X509IssuerSerial> element that uniquely identifies an 
         *    end entity certificate)
         */
        str_child_node = axiom_node_get_first_element(str_node,env);
        if(str_child_node)
        {
            str_child_name = axiom_util_get_localname(str_child_node, env);
            if(str_child_name)
            {
                if(is_include_token)
                {
                    /* The <wsse:Reference> element is used to reference 
                     * an X.509 security token value by means of a URI reference.
                     */
                    if(axutil_strcmp(str_child_name, OXS_NODE_REFERENCE)!=0)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Token is not in the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[rampart][shp] Token is not included in the message ");

                        return AXIS2_FAILURE;
                    }
                    cert = oxs_x509_cert_create(env);
                    status = rampart_token_process_direct_ref(env, str_child_node, sec_node, cert);
                    if(status == AXIS2_FAILURE)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Processing Direct Reference Failed .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[Rampart][shp]Processing Direct Reference Failed.");
                        return AXIS2_FAILURE;
                    }
                    status = rampart_context_set_found_cert_in_shp(rampart_context, env, AXIS2_TRUE);
                    if(status == AXIS2_FAILURE)
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[Rampart][shp]Setting Certificate into rmapart context failed.");
                        return AXIS2_FAILURE;
                    }
                    status = rampart_context_set_receiver_cert_found_in_shp(rampart_context, env, cert);
                }
                else
                {
                    if(0 == axutil_strcmp(str_child_name, OXS_NODE_EMBEDDED))
                    {
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_EMBEDDED, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_EMBEDDED);
                            return AXIS2_FAILURE;
                        }
                        cert = oxs_x509_cert_create(env);
                        status = rampart_token_process_embedded(env, str_child_node, cert);
                        if(status == AXIS2_FAILURE)
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Processing Embedded Token Failed .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Processing Embedded Token Failed.");
                            return AXIS2_FAILURE;
                        }
                        status = rampart_context_set_found_cert_in_shp(rampart_context, env, AXIS2_TRUE);
                        if(status == AXIS2_FAILURE)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Setting Certificate into rmapart context failed.");
                            return AXIS2_FAILURE;
                        }
                        status = rampart_context_set_receiver_cert_found_in_shp(rampart_context, env, cert);
                    }
                    else if(0 == axutil_strcmp(str_child_name, OXS_NODE_KEY_IDENTIFIER))
                    {
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_KEY_IDENTIFIER, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_KEY_IDENTIFIER);
                            return AXIS2_FAILURE;
                        }
                        cert = get_certificate_by_key_identifier(env, rampart_context, str_child_node);
                        if(!cert)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Couldn't find a certificate which matched given key information.");
                            return AXIS2_FAILURE;
                        }
                        
                        rampart_context_set_found_cert_in_shp(rampart_context, env, AXIS2_TRUE);
                        rampart_context_set_receiver_cert_found_in_shp(rampart_context, env, cert);
                        status = AXIS2_SUCCESS;
                    }
                    else if(0 == axutil_strcmp(str_child_name, OXS_NODE_X509_DATA))
                    {
                        /* The <ds:X509IssuerSerial> element is used to specify 
                         * a reference to an X.509 security token by means of 
                         * the certificate issuer name and serial number.
                         */
                        
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_ISSUER_SERIAL, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_X509_DATA);
                            return AXIS2_FAILURE;
                        }
                        cert = get_certificate_by_issuer_serial(env, rampart_context, str_child_node);
                        if(!cert)
                        {
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Couldn't find a certificate which matched given key information.");
                            return AXIS2_FAILURE;
                        }
                        
                        rampart_context_set_found_cert_in_shp(rampart_context, env, AXIS2_TRUE);
                        rampart_context_set_receiver_cert_found_in_shp(rampart_context, env, cert);
                        status = AXIS2_SUCCESS;
                    }
                    else
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                        "[Rampart][shp]Key Reference %s not supported ", str_child_name);
                        return AXIS2_FAILURE;
                    }
                }
                if(status != AXIS2_SUCCESS || !cert)
                {
                    rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                                  "Cannot load the key to verify the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                    "[Rampart][shp] Cannot load the key to verify the message");
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[Rampart][shp]Cannot get the key Reference Type from the message.");
                return AXIS2_FAILURE;
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[Rampart][shp]No Child node in the Security Token Reference Element.");
            return AXIS2_FAILURE;
        }
    }

    /*So there may be scenarios where there is no Security Token Reference Element.*/
    else
    {

        /*In such case policy support only Isssuer Serial scenario.*/

        if(axutil_strcmp(eki, RAMPART_STR_ISSUER_SERIAL)==0)
        {
            key_info_child_node = axiom_node_get_first_element(key_info_node, env);
            if(key_info_child_node)
            {
                axis2_char_t *key_info_child_name = NULL;
                key_info_child_name = axiom_util_get_localname(key_info_child_node, env);
                if(key_info_child_name)
                {
                    if(0 == axutil_strcmp(key_info_child_name, OXS_NODE_X509_DATA))
                    {
                        status = rampart_token_process_x509_data(env, key_info_child_node, cert);
                        if(status != AXIS2_SUCCESS || !cert)
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                                          "Cannot load the key to verify the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                            "[Rampart][shp] Cannot load the key to verify the message");
                            return AXIS2_FAILURE;
                        }
                    }
                    else
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[Rampart][shp]Cannot get the key Reference Type from the message.");
                        return AXIS2_FAILURE;
                    }
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[Rampart][shp]Cannot get the key Reference Type from the message.");
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[Rampart][shp]Cannot get the key Reference Type from the message.");
                return AXIS2_FAILURE;
            }
        }

        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[Rampart][shp]Can't be used as a direct child of Key Info");
            return AXIS2_FAILURE;
        }
    }

    sign_ctx = oxs_sign_ctx_create(env);

    if(!sign_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Sign context creation failed. Out of Memeory.");
        return AXIS2_FAILURE;
    }

    /*Set the required values in sig_ctx*/

    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_VERIFY);
    oxs_sign_ctx_set_certificate(sign_ctx, env, cert);

    envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
    if(!envelope_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Cannot get the Envelope node from envelope.");
        return AXIS2_FAILURE;
    }

    /*Verify the signature*/

    status = oxs_xml_sig_verify(env, sign_ctx, sig_node, envelope_node);
    if(status != AXIS2_SUCCESS)
    {
        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope(
                env, RAMPART_FAULT_INVALID_SECURITY,
                "Signature Verification failed.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        }

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Signature Verification failed.");

        return AXIS2_FAILURE;
    }

    if(sign_ctx)
    {
        oxs_sign_ctx_free(sign_ctx, env);
        sign_ctx = NULL;
    }

    return status;
}

static axis2_status_t
rampart_shp_process_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{
    rp_property_type_t binding_type;
    axis2_status_t status = AXIS2_FAILURE;

    binding_type = rampart_context_get_binding_type(rampart_context, env);

    if(binding_type == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        status = rampart_shp_process_asym_binding_signature(env, msg_ctx, rampart_context,
            soap_envelope, sec_node, sig_node, AXIS2_FALSE);
    }
    else if(binding_type == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        status = rampart_shp_process_sym_binding_signature(env, msg_ctx, rampart_context,
            soap_envelope, sec_node, sig_node);
    }
    else if(binding_type == RP_PROPERTY_TRANSPORT_BINDING)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Transport Binding Not supported");
        /*Not supported*/
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Binding type not supported");
        /*Not supported*/
    }

    /* We need to set the Signature Value in the Security Processed Results.
     * This is required for the Signature Confirmation support */
    if(AXIS2_SUCCESS == status)
    {
        axis2_char_t *sig_val = NULL;
        axiom_node_t *sig_val_node = NULL;

        sig_val_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
            OXS_NODE_SIGNATURE_VALUE, OXS_DSIG_NS, OXS_DS);
        sig_val = oxs_token_get_signature_value(env, sig_val_node);

        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VERIFIED, RAMPART_YES);
        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VALUE, sig_val);
    }
    else
    {
        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VERIFIED, RAMPART_NO);
    }
    return status;
}
#endif

static axis2_status_t
rampart_shp_process_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{
    /* Steps:
     * (1)get the session key/certificate from key info
     * (2)validate signature based on what is available in the incoming message
     * (3)In the validation step, we can get all the nodes which were included in the signature
     * (4)Check whether this is signature or endorsing, based on the nodes included in signature
     * (5)Get the parameters (algorithm, key) from policy and validate incoming signature
     * (6)Get nodes to be included in the signature based on policy and check whether any of them
     *    are missed in the signature. Also, check any additional nodes included in the signature
     * (7)Store the signature to use in signature confirmation
     */
    axiom_node_t *key_info_node = NULL;
    oxs_key_t *symmetric_key = NULL;
    oxs_x509_cert_t *public_cert = NULL;
    oxs_sign_ctx_t *sign_ctx = NULL;
    axutil_array_list_t *signed_parts = NULL;
    int signed_parts_size = 0;
    int i = 0;
    axis2_bool_t is_endorsing = AXIS2_FALSE;
    axis2_char_t *token_type = NULL;
    axis2_char_t *reference_method = NULL;
    axiom_node_t *envelope_node = NULL;
    axis2_char_t *sig_val = NULL;


    /* Step 1: Get the session key or certificate from the message */
    key_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node, OXS_NODE_KEY_INFO,
        OXS_DSIG_NS, NULL);

    if(!key_info_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "Signature verification failed. Key Info node is not available in the message.");
        return AXIS2_FAILURE;
    }

    if(rampart_token_process_key_info(env, key_info_node, sec_node, rampart_context, msg_ctx,
        AXIS2_TRUE, &public_cert, &symmetric_key, &token_type, &reference_method) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "Signature verification failed. Unable to identify signing key from key info.");
        return AXIS2_FAILURE;
    }

    /* if we reach here, either symmetric key or public certificate should be valid */
    /* if security context token or X509 token is used, then store it. It will be used by the
     * server to sign the message */
    rampart_shp_store_token_id(env, key_info_node, rampart_context, sec_node, AXIS2_FALSE, msg_ctx);

    /* receiver certificate should be stored only if token is included as reference or embedded */
    if((public_cert) &&
        ((0 == axutil_strcmp(reference_method, OXS_NODE_REFERENCE))
            || (0 == axutil_strcmp(reference_method, OXS_NODE_EMBEDDED))))
    {
        rampart_context_set_found_cert_in_shp(rampart_context, env, AXIS2_TRUE);
        rampart_context_set_receiver_cert_found_in_shp(rampart_context, env, public_cert);
    }

    /* Step 2: validate signature */
    sign_ctx = oxs_sign_ctx_create(env);
    if(!sign_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "Insufficient memory. Sign context creation failed.");
        return AXIS2_FAILURE;
    }
    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_VERIFY);
    oxs_sign_ctx_set_certificate(sign_ctx, env, public_cert);
    oxs_sign_ctx_set_secret(sign_ctx, env, symmetric_key);

    envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
    if(!envelope_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the Envelope node from envelope.");
        return AXIS2_FAILURE;
    }

    if(oxs_xml_sig_verify(env, sign_ctx, sig_node, envelope_node) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Signature Verification failed.");
        return AXIS2_FAILURE;
    }

    /* Step 3: get all the nodes which were included in the signature */
    signed_parts = oxs_sign_ctx_get_sign_parts(sign_ctx, env);
    signed_parts_size = axutil_array_list_size(signed_parts, env);
    if(signed_parts_size == 0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "None of the nodes are included in the signature.");
        return AXIS2_FAILURE;
    }

    /* Step 4 - 6: verify whether the signature is according to the policy */
    if(signed_parts_size == 1)
    {
        /* It could be endorsing signature */
        /* TODO WS-SecurityPolicy 1.2 allows endorsing signature to include some other parts as
         * well. Rampart/C is not supporting it.
         */
        oxs_sign_part_t *sign_part = NULL;
        axiom_node_t *sign_node = NULL;
        sign_part = (oxs_sign_part_t*)axutil_array_list_get(signed_parts, env, 0);
        sign_node = oxs_sign_part_get_node(sign_part, env);
        is_endorsing = oxs_axiom_check_node_name(env, sign_node, OXS_NODE_SIGNATURE, OXS_DSIG_NS);
        if(is_endorsing)
        {
            rp_property_t *token = NULL;
            rp_property_type_t rp_token_type;

            /* check whether we need endorsing signature*/
            token = rampart_context_get_endorsing_token(rampart_context, env);
            if(!token)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Endorsing Token is not specified");
                return AXIS2_FAILURE;
            }

            /* check whether the algorithms are according to endorsing token */
            rp_token_type = rp_property_get_type(token, env);
            if(rp_token_type == RP_PROPERTY_X509_TOKEN)
            {
                axis2_char_t *sign_mtd_algo_provided = NULL;
                axis2_char_t *sign_mtd_algo_needed = NULL;
                sign_mtd_algo_provided = oxs_sign_ctx_get_sign_mtd_algo(sign_ctx, env);
                sign_mtd_algo_needed = rampart_context_get_asym_sig_algo(rampart_context,env);
                if(axutil_strcmp(sign_mtd_algo_provided, sign_mtd_algo_needed) != 0)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "Endorsing signature algorithm is not valid. Expected [%s], given [%s]",
                        sign_mtd_algo_needed, sign_mtd_algo_provided);
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                /* TODO for the moment, we support only asymmetric endorsing using x509 */
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "Endorsing signature with non-x509 token is not allowed");
                return AXIS2_FAILURE;
            }
        } /* else part is covered below. It will include the part where signed_parts_size != 1 */
    }

    /* TODO validate the token type, inclusion method, reference method here */

    if(!is_endorsing)
    {
        /* normal signature. Validate whether this signature is valid */
        axutil_array_list_t *nodes_to_sign = NULL;
        int nodes_to_sign_size = 0;
        rp_property_type_t binding_type;
        axis2_char_t *sign_mtd_algo_provided = NULL;
        axis2_char_t *sign_mtd_algo_needed = NULL;
        axis2_char_t *digest_mtd_algo_needed = NULL;

        /* Check the algorithms */
        sign_mtd_algo_provided = oxs_sign_ctx_get_sign_mtd_algo(sign_ctx, env);
        binding_type = rampart_context_get_binding_type(rampart_context, env);
        if(binding_type == RP_PROPERTY_ASYMMETRIC_BINDING)
        {
            sign_mtd_algo_needed = rampart_context_get_asym_sig_algo(rampart_context,env);
        }
        else if(binding_type == RP_PROPERTY_SYMMETRIC_BINDING)
        {
            sign_mtd_algo_needed = rampart_context_get_sym_sig_algo(rampart_context,env);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Signature is not supported for Transport binding");
            return AXIS2_FAILURE;
        }

        if(axutil_strcmp(sign_mtd_algo_provided, sign_mtd_algo_needed) != 0)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Signature algorithm is not valid. Expected [%s], given [%s]",
                sign_mtd_algo_needed, sign_mtd_algo_provided);
            return AXIS2_FAILURE;
        }

        /* Get the nodes to be signed and check whether they are signed */
        nodes_to_sign = axutil_array_list_create(env, 0);
        if(rampart_context_get_nodes_to_sign(rampart_context, env, soap_envelope, nodes_to_sign)
            != AXIS2_SUCCESS)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Cannot get information about nodes to be signed from policy.");
            return AXIS2_FAILURE;
        }

        nodes_to_sign_size = axutil_array_list_size(nodes_to_sign, env);
        if(nodes_to_sign_size != signed_parts_size)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Number of nodes to be signed [%d] and number of nodes which were included in the "
                "signature [%d] are different.", nodes_to_sign_size, signed_parts_size);
            return AXIS2_FAILURE;
        }

        /* Get digest method and check for validity */
        digest_mtd_algo_needed = rampart_context_get_digest_mtd(rampart_context,env);

        for(i = 0; i < signed_parts_size; ++i)
        {
            oxs_sign_part_t *sign_part = NULL;
            axiom_node_t *signed_node = NULL;
            axis2_char_t *digest_mtd_algo_provided = NULL;
            int j = 0;
            axis2_bool_t match_found = AXIS2_FALSE;

            sign_part = (oxs_sign_part_t*)axutil_array_list_get(signed_parts, env, i);

            /* Check for digest method validity */
            digest_mtd_algo_provided = oxs_sign_part_get_digest_mtd(sign_part, env);
            if(axutil_strcmp(digest_mtd_algo_provided, digest_mtd_algo_needed) != 0)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "Digest algorithm is not valid. Expected [%s], given [%s]",
                    digest_mtd_algo_needed, digest_mtd_algo_provided);
                return AXIS2_FAILURE;
            }

            signed_node = oxs_sign_part_get_node(sign_part, env);

            for(j=0; i< nodes_to_sign_size; ++j)
            {
                axiom_node_t *node_to_be_signed = NULL;
                node_to_be_signed =  (axiom_node_t*)axutil_array_list_get(nodes_to_sign, env, j);
                if(node_to_be_signed == signed_node)
                {
                    match_found = AXIS2_TRUE;
                    break;
                }
            }

            if(!match_found)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "Some nodes that should be signed are not signed.");
                return AXIS2_FAILURE;
            }
        }
    }

    /* signature is successful */
    sig_val = oxs_sign_ctx_get_sig_val(sign_ctx, env);
    if(is_endorsing)
    {
        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_ENDORSED_VALUE, sig_val);
    }
    else
    {
        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VALUE, sig_val);
    }


    if(sign_ctx)
    {
        oxs_sign_ctx_free(sign_ctx, env);
        sign_ctx = NULL;
    }

    return AXIS2_SUCCESS;
}

/***/
static axis2_status_t 
rampart_shp_detect_replays(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_soap_envelope_t *soap_envelope,
                            axiom_node_t *sec_node)
{
    axis2_bool_t need_replay_detection = AXIS2_FALSE;
    axis2_status_t status = AXIS2_FAILURE;

        if((NULL == rampart_context_get_rd_val(rampart_context, env)) && (NULL == rampart_context_get_replay_detector_name(rampart_context, env)))
		{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Replay detection is not specified. Nothing to do");
            need_replay_detection = AXIS2_FALSE;
        }
		else
		{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Checking message for replay.");
            need_replay_detection = AXIS2_TRUE;
        }
        if(AXIS2_TRUE == need_replay_detection)
		{
			axis2_char_t* replay_detector_name = rampart_context_get_replay_detector_name(rampart_context, env);
			if (replay_detector_name)
			{
				rampart_replay_detector_t* replay_detector = (rampart_replay_detector_t*)rampart_context_get_replay_detector(rampart_context, env);
				if (!replay_detector)
				{
					AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Cannot find the replay detector module");
					rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
					return AXIS2_FAILURE;
				}

				AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Using replay module.");
				status = RAMPART_REPLAY_DETECTOR_IS_REPLAYED(replay_detector, env, msg_ctx, rampart_context);
				if(status != AXIS2_SUCCESS)
				{
					/*Scream .. replayed*/
					AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Message can be replayed");
					rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
					return AXIS2_FAILURE;
				}
				else
				{
					AXIS2_LOG_INFO(env->log, "[rampart][shp] Checked message for replays. Not a replay.");
				}
			}
			else
			{
				rampart_is_replayed_fn rd_fn = NULL;
				AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Replay module not defined. Using replay function.");
				
				/*Is replayed*/
				rd_fn = rampart_context_get_replay_detect_function(rampart_context, env);
				if(rd_fn)
				{
					status  = (*rd_fn)(env, msg_ctx, rampart_context, rampart_context_get_rd_user_params(rampart_context, env));
					if(status != AXIS2_SUCCESS)
					{
						/*Scream .. replayed*/
						AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Message can be replayed");
						rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
						return AXIS2_FAILURE;
					}
					else
					{
						AXIS2_LOG_INFO(env->log, "[rampart][shp] Checked message for replays. Not a replay.");
					}
				}
				else
				{
					AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] No replay detection function specified. Nothing to do. ");
				}
			}
        }
        return AXIS2_SUCCESS;
}

static axis2_status_t
rampart_shp_process_derived_key(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_node_t *sec_node,
                            axiom_node_t *dk_node)
{
    oxs_key_t *session_key = NULL;
    oxs_key_t *derived_key = NULL;
    axis2_char_t *token_type = NULL;
    axis2_char_t *reference_method = NULL;
    oxs_x509_cert_t* cert = NULL; 

    /* Get the session key. */ 
    /*session_key = rampart_shp_get_key_for_key_info(
        env, dk_node, rampart_context, msg_ctx, AXIS2_TRUE);*/
    if(rampart_token_process_key_info(env, dk_node, sec_node, rampart_context, msg_ctx, AXIS2_TRUE,
        &cert, &session_key, &token_type, &reference_method) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Failed to get the session key. Cannot derive the key");
        return AXIS2_FAILURE;
    }
    if(!session_key)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,  
            "[rampart]Failed to get the session key. Cannot derive the key");
        return AXIS2_FAILURE;
    }

    /*Derive the key*/
    derived_key = oxs_derivation_extract_derived_key_from_token(env, dk_node, sec_node, session_key); 
    
    /*Add to the rampart context*/
    rampart_context_add_key(rampart_context, env, derived_key);

    return AXIS2_SUCCESS; 
}

static axis2_status_t
rampart_shp_process_saml_token(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_node_t *saml_node)
{
    axis2_bool_t server_side = AXIS2_FALSE;
    rampart_saml_token_t *saml = NULL;
    axis2_char_t *sub_conf = NULL;
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);

    if(AXIS2_FAILURE == rampart_saml_token_validate(env, rampart_context, saml_node))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] SAML Signature Verification Failed");
        return AXIS2_FAILURE;
    }
    sub_conf = rampart_saml_token_get_subject_confirmation(env, saml_node);
    if(sub_conf && axutil_strcmp(sub_conf, SAML_SUB_CONFIRMATION_SENDER_VOUCHES) == 0)
    {
        if(!rampart_context_is_include_supporting_token(rampart_context, env, !server_side,
            AXIS2_FALSE, RP_PROPERTY_SAML_TOKEN) && !rampart_context_is_include_supporting_token(
            rampart_context, env, !server_side, AXIS2_FALSE, RP_PROPERTY_ISSUED_TOKEN))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp] Unexpected SAML token.");
            return AXIS2_FAILURE;
        }
    }
    else if(sub_conf && axutil_strcmp(sub_conf, SAML_SUB_CONFIRMATION_HOLDER_OF_KEY) == 0)
    {
        if(!rampart_context_is_include_protection_saml_token(rampart_context, !server_side,
            AXIS2_FALSE, env))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp] Unexpected SAML token.");
            return AXIS2_FAILURE;
        }
    }
    /* Set the SAML token to the rampart context */
    saml = rampart_saml_token_create(env, saml_node, RAMPART_ST_CONFIR_TYPE_UNSPECIFIED);
    rampart_context_add_saml_token(rampart_context, env, saml);
    return AXIS2_SUCCESS;
}

/*Public functions*/

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_shp_process_sec_header(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{
    axiom_node_t *cur_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    /*axis2_bool_t first_signature = AXIS2_TRUE;*/

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Processing security header in Strict layout");

    cur_node = axiom_node_get_first_child(sec_node, env);

    /*Loop all security headers*/
    while(cur_node)
    {
        axis2_char_t *cur_local_name = NULL;
        cur_local_name = axiom_util_get_localname(cur_node, env);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Processing security header element %s",
            cur_local_name);

        /* TODO validate the namespace */

        if(!axutil_strcmp(cur_local_name, OXS_NODE_ENCRYPTED_KEY))
        {
            status = rampart_shp_process_encrypted_key(env, msg_ctx, rampart_context,
                soap_envelope, sec_node, cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_SECURITY_CONTEXT_TOKEN))
        {
            status = rampart_shp_process_security_context_token(env, cur_node, rampart_context,
                msg_ctx);
        }
        else if(!axutil_strcmp(cur_local_name, RAMPART_SECURITY_TIMESTAMP))
        {
            status = rampart_shp_process_timestamptoken(env, msg_ctx, rampart_context, cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, RAMPART_SECURITY_USERNAMETOKEN))
        {
            status = rampart_shp_process_usernametoken(env, msg_ctx, rampart_context, cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE))
        {
            status = rampart_shp_process_signature(env, msg_ctx, rampart_context, soap_envelope,
                sec_node, cur_node);
#if 0
            if(first_signature)
            {
                status = rampart_shp_process_signature(env, msg_ctx, rampart_context,
                    soap_envelope, sec_node, cur_node);
                first_signature = AXIS2_FALSE;
            }
            else /*endorsing*/
            {
                /* TODO this way of validating endorsing signature is wrong. Correct it */
                status = rampart_shp_process_asym_binding_signature(env, msg_ctx, rampart_context,
                    soap_envelope, sec_node, cur_node, AXIS2_TRUE);
                if(AXIS2_SUCCESS == status)
                {
                    axis2_char_t *sig_val = NULL;
                    axiom_node_t *sig_val_node = NULL;
                    sig_val_node = oxs_axiom_get_first_child_node_by_name(env, cur_node,
                        OXS_NODE_SIGNATURE_VALUE, OXS_DSIG_NS, OXS_DS);
                    sig_val = oxs_token_get_signature_value(env, sig_val_node);
                    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_ENDORSED_VALUE,
                        sig_val);
                }
            }
#endif
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_REFERENCE_LIST))
        {
            status = rampart_shp_process_reference_list(env, msg_ctx, rampart_context,
                soap_envelope, sec_node, cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_DERIVED_KEY_TOKEN))
        {
            /* We need to extract this and store in the rampart context*/
            status = rampart_shp_process_derived_key(env, msg_ctx, rampart_context, sec_node,
                cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_ENCRYPTED_DATA))
        {
            /* We do nothing. But this is possible when a security header is Encrypted. 
             * But it would be decrypted thru a ref list */
            status = AXIS2_SUCCESS;
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE_CONFIRMATION))
        {
            status = rampart_shp_process_signature_confirmation(env, msg_ctx, rampart_context,
                cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_BINARY_SECURITY_TOKEN))
        {
            /*We do nothing.*/
            status = AXIS2_SUCCESS;
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_SAML_ASSERTION))
        {
            status = rampart_shp_process_saml_token(env, msg_ctx, rampart_context, cur_node);
        }
        else if(!axutil_strcmp(cur_local_name, OXS_NODE_SECURITY_TOKEN_REFRENCE))
        {
            /*We do nothing.*/
            status = AXIS2_SUCCESS;
        }
        else
        {
            /* if the security header is unknown, we should not continue. */
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Unknown security header %s",
                cur_local_name);
            status = AXIS2_FAILURE;
        }

        if(status != AXIS2_SUCCESS)
        {
            axis2_char_t *reason = NULL;
            reason = axutil_stracat(env, cur_local_name, " processing failed");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, reason,
                cur_local_name, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, reason);
            AXIS2_FREE(env->allocator, reason);
            return AXIS2_FAILURE;
        }

        /* Get next node */
        cur_node = axiom_node_get_next_sibling(cur_node, env);
    }/*Eof while loop*/

    AXIS2_LOG_INFO(env->log, "Security header processing done");

    /*Now detect replays*/
    status = rampart_shp_detect_replays(env, msg_ctx, rampart_context, soap_envelope, sec_node);
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Message replay detected.");
        return AXIS2_FAILURE;
    }

    /* Now validate security policies, those cannot be checked on the fly */
    status = rampart_pv_validate_sec_header(env, rampart_context, sec_node, msg_ctx);
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Security policy validation failed.");
        return AXIS2_FAILURE;
    }
    return AXIS2_SUCCESS;
}
