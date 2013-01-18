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
#include <rampart_sec_header_builder.h>
#include <rampart_username_token.h>
#include <rampart_timestamp_token.h>
#include <rampart_util.h>
#include <rampart_sec_processed_result.h>
#include <rampart_handler_util.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_key.h>
#include <oxs_axiom.h>
#include <oxs_asym_ctx.h>
#include <oxs_tokens.h>
#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <rampart_signature.h>
#include <rampart_saml.h>
#include <rampart_issued.h>
#include <axiom_util.h>
/*Private functions*/

axis2_status_t AXIS2_CALL
rampart_shb_do_asymmetric_binding( const axutil_env_t *env,
                                   axis2_msg_ctx_t *msg_ctx,
                                   rampart_context_t *rampart_context,
                                   axiom_soap_envelope_t *soap_envelope,
                                   axiom_node_t *sec_node,
                                   axiom_namespace_t *sec_ns_obj,
                                   axutil_array_list_t *sign_parts_list)
{
    axis2_bool_t signature_protection = AXIS2_FALSE;
    axis2_bool_t is_encrypt_before_sign = AXIS2_FALSE;
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *sig_node = NULL;
    axiom_node_t *enc_key_node = NULL;


    /*Do Asymmetric Binding specific things*/
    signature_protection = rampart_context_is_encrypt_signature(rampart_context, env);

    /*Check the encryption and signature order*/
    if(rampart_context_is_encrypt_before_sign(rampart_context, env))
    {
        is_encrypt_before_sign = AXIS2_TRUE;

        /*If signature_protection=> <sp:EncryptSignature/> is ON*/
        if(signature_protection)
        {
            /*First Encrypt the parts specified in encrypted parts*/
            status = rampart_enc_encrypt_message(env, msg_ctx, rampart_context, soap_envelope, sec_node);
            if(status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Encryption failed. ERROR");
                return AXIS2_FAILURE;
            }

            /*Add a key reference in Encrypted Data in the Body*/

            status = rampart_enc_add_key_info(env, msg_ctx, rampart_context, soap_envelope, sec_node);
            if(status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Cannot add Key information");
                return AXIS2_FAILURE;
            }
            /*Then Sign the message*/
            status = rampart_sig_sign_message(env, msg_ctx, rampart_context, soap_envelope, sec_node, sign_parts_list);
            if(status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Signing failed. ERROR");
                return AXIS2_FAILURE;
            }

            /*Then encrypt the signature */
            status = rampart_enc_encrypt_signature(env, msg_ctx, rampart_context, soap_envelope, sec_node);
            if(status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Encrypt signature failed. ERROR");
                return AXIS2_FAILURE;
            }

        }
        else /*No Signature protection*/
        {
            status = rampart_enc_encrypt_message(env, msg_ctx, rampart_context, soap_envelope, sec_node);
            if(status != AXIS2_SUCCESS){
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Encryption failed. ERROR");
                return AXIS2_FAILURE;
            }
            /*Then do signature specific things*/
            status = rampart_sig_sign_message(env, msg_ctx, rampart_context, soap_envelope, sec_node, sign_parts_list);
            if(status != AXIS2_SUCCESS){
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] Signature failed. ERROR");
                return AXIS2_FAILURE;
            }
        }

        /*Then Handle Supporting token stuff  */
    }
    else /*Sign before encrypt*/
    {
        is_encrypt_before_sign = AXIS2_FALSE;
        /*First do signature specific stuff*/
        status = rampart_sig_sign_message(env, msg_ctx, rampart_context, soap_envelope, sec_node, sign_parts_list);
        if(status != AXIS2_SUCCESS){
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Signing failed. ERROR");
            return AXIS2_FAILURE;
        }
        /*Then Handle Encryption stuff*/

        status = rampart_enc_encrypt_message(env, msg_ctx, rampart_context, soap_envelope, sec_node);
        if(status!=AXIS2_SUCCESS ){
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Encryption failed. ERROR");
            return AXIS2_FAILURE;
        }
    }

    /*If both encryption and signature is done we should interchange them.
     * because the action done last should appear first in the header. */
    sig_node = oxs_axiom_get_node_by_local_name(env,sec_node,OXS_NODE_SIGNATURE);
    enc_key_node = oxs_axiom_get_node_by_local_name(env,sec_node,OXS_NODE_ENCRYPTED_KEY);
    if(sig_node && enc_key_node)
    {
        if(is_encrypt_before_sign)
        {
            status = oxs_axiom_interchange_nodes(env, sig_node, enc_key_node);
            if(status!=AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Node interchange failed.");
                return status;
            }
        }
        else /*Sign before encryption*/
        {
            status = oxs_axiom_interchange_nodes(env, enc_key_node, sig_node);
            if(status!=AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Node interchange failed.");
                return status;
            }
        }
    }else if(enc_key_node && signature_protection)
    {
        if(!is_encrypt_before_sign)
        {
            axiom_node_t *enc_data_node = NULL;
            enc_data_node = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_ENCRYPTED_DATA);
            if(!enc_data_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shb]Signature is not encrypted,");
                return AXIS2_FAILURE;
            }
            else
            {
                status = oxs_axiom_interchange_nodes(env, enc_key_node, enc_data_node);
                if(status != AXIS2_SUCCESS)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shb]Cannot interchange enc_key and enc_data nodes");
                    return AXIS2_FAILURE;
                }
            }
        }
    }

    return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
rampart_shb_do_symmetric_binding( const axutil_env_t *env,
                                  axis2_msg_ctx_t *msg_ctx,
                                  rampart_context_t *rampart_context,
                                  axiom_soap_envelope_t *soap_envelope,
                                  axiom_node_t *sec_node,
                                  axiom_namespace_t *sec_ns_obj,
                                  axutil_array_list_t *sign_parts_list)
{
    axis2_status_t status = AXIS2_FAILURE;

    /*Check the encryption and signature order*/
    if(rampart_context_is_encrypt_before_sign(rampart_context, env))
    {
        axis2_bool_t signature_protection = AXIS2_FALSE;
        signature_protection = rampart_context_is_encrypt_signature(rampart_context, env);
        /*Encrypt before sign. Complicated stuff...*/
        /**
         * 1. encrypt parts to be encrypted
         * 2. sign parts to be signed
         * 3. encrypt signature if required
         */
        /*1. Encrypt*/
        status = rampart_enc_dk_encrypt_message(env, msg_ctx, rampart_context, soap_envelope, sec_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Sym binding, Encryption failed in Symmetric binding. ERROR");
            return AXIS2_FAILURE;
        }

        /*2. Sign*/
        status = rampart_sig_sign_message(env, msg_ctx, rampart_context, soap_envelope, sec_node, sign_parts_list);
        if(status != AXIS2_SUCCESS)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Signing failed. ERROR");
            return AXIS2_FAILURE;
        }
        /*3. Encrypt signature*/
        if(signature_protection)
        {
            status = rampart_enc_encrypt_signature(env, msg_ctx, rampart_context, soap_envelope, sec_node);
            if(status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Encrypt signature failed. ERROR");
                return AXIS2_FAILURE;
            }
        }
    }
    else
    { 
        /*Sign before encrypt*/
        /*First do signature specific stuff using Symmetric key*/
        status = rampart_sig_sign_message(env, msg_ctx, rampart_context, soap_envelope, sec_node, sign_parts_list);
        if(status != AXIS2_SUCCESS)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Signing failed. ERROR");
            return AXIS2_FAILURE;
        }

        /*Then Handle Encryption stuff*/
        status = rampart_enc_dk_encrypt_message(env, msg_ctx, rampart_context, soap_envelope, sec_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Sym binding, Encryption failed in Symmetric binding. ERROR");
            return AXIS2_FAILURE;
        }
    }

    /*Finaly we need to make sure that our security header elements are in order*/
    status = rampart_shb_ensure_sec_header_order(env, msg_ctx, rampart_context, sec_node);
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shb] Security header ordering failed.");
        return AXIS2_FAILURE;
    }

    status = AXIS2_SUCCESS;

    return status;
}




/*Public functions*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_shb_ensure_sec_header_order(const axutil_env_t *env,
                                    axis2_msg_ctx_t *msg_ctx,
                                    rampart_context_t *rampart_context,
                                    axiom_node_t* sec_node)
{
    axis2_bool_t signature_protection = AXIS2_FALSE;
    axis2_bool_t is_encrypt_before_sign = AXIS2_FALSE;
    axiom_node_t *sig_node = NULL;
    axiom_node_t *enc_key_node = NULL;
    axiom_node_t *ref_list_node = NULL;
    axiom_node_t *h_node = NULL;
    axutil_array_list_t *dk_list = NULL;
    axutil_array_list_t *enc_key_list = NULL;
    axiom_node_t* first_protection_item = NULL;
    int i = 0;

    signature_protection = rampart_context_is_encrypt_signature(rampart_context, env);
    is_encrypt_before_sign = rampart_context_is_encrypt_before_sign(rampart_context, env);

    dk_list = axutil_array_list_create(env, 5);
    enc_key_list = axutil_array_list_create(env, 2);

    h_node = axiom_node_get_first_child(sec_node, env);
    while(h_node)
    {
        if(0 == axutil_strcmp(OXS_NODE_DERIVED_KEY_TOKEN, axiom_util_get_localname(h_node, env)) ||
                (0 == axutil_strcmp(OXS_NODE_BINARY_SECURITY_TOKEN, axiom_util_get_localname(h_node, env))))
        {
            axutil_array_list_add(dk_list, env, h_node);
        }
        else if((0 == axutil_strcmp(OXS_NODE_ENCRYPTED_KEY, axiom_util_get_localname(h_node, env))) ||
                (0 == axutil_strcmp(OXS_NODE_SECURITY_CONTEXT_TOKEN, axiom_util_get_localname(h_node, env))))
        {
            axutil_array_list_add(enc_key_list, env, h_node);
        }
        h_node = axiom_node_get_next_sibling(h_node, env);
    }

    ref_list_node = oxs_axiom_get_first_child_node_by_name(env, sec_node, OXS_NODE_REFERENCE_LIST, OXS_ENC_NS, NULL);
    sig_node = oxs_axiom_get_first_child_node_by_name(env, sec_node, OXS_NODE_SIGNATURE, OXS_DSIG_NS, NULL);

    /*Ensure the protection order in the header*/
    if(sig_node && ref_list_node)
    {
        if(is_encrypt_before_sign)
        {
            int no_of_sig_node = 0;
            /*Encrypt->Sig         <Sig><RefList>*/
            oxs_axiom_interchange_nodes(env,  sig_node, ref_list_node );
            first_protection_item = sig_node;
            no_of_sig_node = oxs_axiom_get_number_of_children_with_qname(env, sec_node, OXS_NODE_SIGNATURE, OXS_DSIG_NS, NULL);
            if(no_of_sig_node > 1)
            {
                axiom_node_t* cur_node = NULL;
                cur_node = axiom_node_get_first_child(sec_node, env);
                while(cur_node)
                {
                    axis2_char_t *cur_local_name = NULL;
                    cur_local_name = axiom_util_get_localname(cur_node, env);

                    if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE))
                    {
                        oxs_axiom_interchange_nodes(env,  cur_node, ref_list_node);
                    }
                    cur_node = axiom_node_get_next_sibling(cur_node, env);
                }
            }
        }
        else
        {
            /*Sig->Encrypt         <RefList> <Sig>*/
            oxs_axiom_interchange_nodes(env, ref_list_node, sig_node );
            first_protection_item = ref_list_node;
        }
    }
    else if(sig_node)
    {
        first_protection_item = sig_node;
    }
    else
    {
        first_protection_item = ref_list_node;
    }

    /*makesure enc_key_node is appearing before first protection item*/
    if(first_protection_item)
    {
        for(i = 0; i < axutil_array_list_size(enc_key_list, env); i++)
        {
            axiom_node_t *tmp_node = NULL;
            tmp_node = (axiom_node_t*)axutil_array_list_get(enc_key_list, env, i);
            enc_key_node = axiom_node_detach_without_namespaces(tmp_node, env);
            axiom_node_insert_sibling_before(first_protection_item, env, enc_key_node);
        }
    }

    /*
     * If there are derived keys, make sure they come after the EncryptedKey/security context token
        1. First we get all the derived keys
        2. Then we attach after the EncryptedKey(hidden sessionkey)/security context token 
        3. If key is not available, then attach derived keys before sig_node and ref_list_node (whichever is first)
     */

    if(enc_key_node)
    {
        for(i = 0; i < axutil_array_list_size(dk_list, env); i++)
        {
            axiom_node_t *dk_node = NULL;
            axiom_node_t *tmp_node = NULL;

            dk_node = (axiom_node_t*)axutil_array_list_get(dk_list, env, i);
            tmp_node = axiom_node_detach(dk_node, env);
            axiom_node_insert_sibling_after(enc_key_node, env, tmp_node);
        }
    }
    else
    {
        if(first_protection_item)
        {
            for(i = 0; i < axutil_array_list_size(dk_list, env); i++)
            {
                axiom_node_t *dk_node = NULL;
                axiom_node_t *tmp_node = NULL;
                dk_node = (axiom_node_t*)axutil_array_list_get(dk_list, env, i);
                tmp_node = axiom_node_detach(dk_node, env);
                axiom_node_insert_sibling_before(first_protection_item, env, tmp_node);
            }
        }
    }
    
    axutil_array_list_free(dk_list, env);
    axutil_array_list_free(enc_key_list, env);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_shb_build_message(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope)
{
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_soap_header_t *soap_header = NULL;
    axiom_node_t *soap_header_node = NULL;
    axiom_element_t *soap_header_ele = NULL;
    axiom_soap_header_block_t *sec_header_block = NULL;
    axiom_namespace_t *sec_ns_obj = NULL;
    axiom_node_t *sec_node =  NULL;
    axiom_element_t *sec_ele = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
	/* 
	 * sign parts list. Moved this up the building process. This was originally 
	 * in the rampart_sig_sign_message 
	 */ 
    axutil_array_list_t *sign_parts_list = NULL;
    AXIS2_ENV_CHECK(env,AXIS2_FAILURE);
    soap_header  = axiom_soap_envelope_get_header(soap_envelope, env);
    soap_header_node = axiom_soap_header_get_base_node(soap_header, env);
    soap_header_ele = (axiom_element_t *)axiom_node_get_data_element(
                          soap_header_node, env);


    sec_ns_obj =  axiom_namespace_create(env, RAMPART_WSSE_XMLNS,
                                         RAMPART_WSSE);
	axiom_namespace_increment_ref(sec_ns_obj, env);

    sec_header_block = axiom_soap_header_add_header_block(soap_header,
                       env, RAMPART_SECURITY, sec_ns_obj);
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    if(!sec_header_block)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Security header block is NULL");
		axiom_namespace_free(sec_ns_obj, env);
        return AXIS2_SUCCESS;
    }

    axiom_soap_header_block_set_must_understand_with_bool(sec_header_block,
            env, AXIS2_TRUE);

    sec_node = axiom_soap_header_block_get_base_node(sec_header_block, env);
    sec_ele = (axiom_element_t *)
              axiom_node_get_data_element(sec_node, env);

    sign_parts_list = axutil_array_list_create(env, 4);
    /*Timestamp Inclusion*/
    if(rampart_context_is_include_timestamp(rampart_context,env))
    {
        int ttl = -1;
        axis2_bool_t need_millisecond = AXIS2_TRUE;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Building Timestamp Token");
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Using default timeToLive value %d",
                       RAMPART_TIMESTAMP_TOKEN_DEFAULT_TIME_TO_LIVE);
        ttl = rampart_context_get_ttl(rampart_context,env);
        need_millisecond = rampart_context_get_need_millisecond_precision(rampart_context, env);

        status = rampart_timestamp_token_build(env, sec_node, ttl, need_millisecond);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Timestamp Token build failed. ERROR");
			axiom_namespace_free(sec_ns_obj, env);
            return AXIS2_FAILURE;
        }
    }

    /*Check whether we need username token*/
    /*User name tokens includes in messages sent from client to server*/
    if(!axis2_msg_ctx_get_server_side(msg_ctx,env))
    {
        if(rampart_context_is_include_username_token(rampart_context,env))
        {

            /*Now we are passing rampart_context here so inside this method
            relevant parameters are extracted. */

            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Building UsernmaeToken");
            status = rampart_username_token_build(
                        env,
                        rampart_context,
                        sec_node,
                        sec_ns_obj);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shb] UsernmaeToken build failed. ERROR");
				axiom_namespace_free(sec_ns_obj, env);
                return AXIS2_FAILURE;
            }
        }
    }

    /**********************
     * Sample node to be added to the security header. This is for testing
     * TODO: Remove later*/

    if(0){
        axiom_node_t *my_token = NULL;
        axutil_array_list_t *token_list = NULL;
        axis2_char_t *buf = "<MyToken/>";

        token_list = axutil_array_list_create(env, 1);
        my_token = oxs_axiom_deserialize_node(env, buf);
        axutil_array_list_add(token_list, env, my_token);
        rampart_context_set_custom_tokens(rampart_context,env, token_list);
    }
 
    /***********************/
    /*Custom tokens are included if its available in the rampart context*/
    if(!axis2_msg_ctx_get_server_side(msg_ctx,env))
    {
        axutil_array_list_t *token_list = NULL;

        token_list = rampart_context_get_custom_tokens(rampart_context, env);
        if(token_list){
            int size = 0, i = 0;
            size = axutil_array_list_size(token_list, env);
            for (i = 0; i < size; i++){
                axiom_node_t *token_node = NULL;
                token_node = (axiom_node_t*)axutil_array_list_get(token_list, env, i);
                if(token_node){
                    axis2_status_t status = AXIS2_FAILURE;
                    status = axiom_node_add_child(sec_node, env, token_node); 
                    if(status != AXIS2_SUCCESS){
                        return AXIS2_FAILURE;
                    }
                }
            }
        }
    }

    if (rampart_context_is_include_supporting_token(rampart_context, env, server_side, AXIS2_FALSE, RP_PROPERTY_SAML_TOKEN))
    {        
        status = rampart_saml_supporting_token_build(env, rampart_context, sec_node, sign_parts_list);    
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] SAML Supporting token build failed. ERROR");
            axutil_array_list_free(sign_parts_list, env);
			axiom_namespace_free(sec_ns_obj, env);
            return AXIS2_FAILURE;
        }
    }

	if (rampart_context_is_include_supporting_token(rampart_context, env, server_side, AXIS2_FALSE, RP_PROPERTY_ISSUED_TOKEN))
	{
		status = rampart_issued_supporting_token_build(rampart_context, env, sec_node, sign_parts_list);					
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shb] Issued supporting token build failed. ERROR");
            axutil_array_list_free(sign_parts_list, env);
			axiom_namespace_free(sec_ns_obj, env);
            return AXIS2_FAILURE;
        }
	}

    /*Signature Confirmation support. Only in the server side*/
    if(axis2_msg_ctx_get_server_side(msg_ctx,env)){
        axis2_bool_t sign_conf_reqd = AXIS2_FALSE;
        /*Sign_conf_reqd <- Get from context <- policy*/
        sign_conf_reqd = rampart_context_is_sig_confirmation_reqd(rampart_context, env);
        if(sign_conf_reqd){
            status = rampart_sig_confirm_signature(env, msg_ctx, rampart_context, sec_node);
        }
    }


    /*check the binding*/
    if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        axis2_status_t status = AXIS2_FAILURE;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Asymmetric Binding. ");
        status = rampart_shb_do_asymmetric_binding(env, msg_ctx, rampart_context, soap_envelope, sec_node, sec_ns_obj, sign_parts_list);
		axiom_namespace_free(sec_ns_obj, env);
        if(AXIS2_FAILURE == status){
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Asymmetric Binding failed");
            if(axis2_msg_ctx_get_server_side(msg_ctx,env)){
                AXIS2_ERROR_SET(env->error, RAMPART_ERROR_INVALID_SECURITY , AXIS2_FAILURE);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,  "[rampart][shb] %s", AXIS2_ERROR_GET_MESSAGE(env->error));
                rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                  " Asymmetric Binding failed. Check configurations ", RAMPART_FAULT_IN_POLICY, msg_ctx);
            }
            axutil_array_list_free(sign_parts_list, env);
            return AXIS2_FAILURE;
        }else{
            axutil_array_list_free(sign_parts_list, env);
            return AXIS2_SUCCESS;
        }

    }
    else if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        axis2_status_t status = AXIS2_FAILURE;

        /*Do Symmetric_binding specific things*/
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Symmetric Binding. ");
        status = rampart_shb_do_symmetric_binding(env, msg_ctx, rampart_context, soap_envelope, sec_node, sec_ns_obj, sign_parts_list);
		axiom_namespace_free(sec_ns_obj, env);
        if(AXIS2_FAILURE == status){
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shb] Symmetric Binding failed");
            if(axis2_msg_ctx_get_server_side(msg_ctx,env)){
                AXIS2_ERROR_SET(env->error, RAMPART_ERROR_INVALID_SECURITY, AXIS2_FAILURE);
                rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                  " Symmetric Binding failed. Check configurations ", RAMPART_FAULT_IN_POLICY, msg_ctx);
            }
            axutil_array_list_free(sign_parts_list, env);
            return AXIS2_FAILURE;
        }else{
            axutil_array_list_free(sign_parts_list, env);
            return AXIS2_SUCCESS;
        }
    }
    else if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_TRANSPORT_BINDING)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shb] Using transport binding");
		axiom_namespace_free(sec_ns_obj, env);
        axutil_array_list_free(sign_parts_list, env);
        return AXIS2_SUCCESS;
    }else{
        axutil_array_list_free(sign_parts_list, env);
		axiom_namespace_free(sec_ns_obj, env);
        return AXIS2_FAILURE;
    }
}
