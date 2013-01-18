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
#include "echo.h"
#include <axiom_xml_writer.h>
#include <axiom_util.h>
#include <stdio.h>
#include <secconv_security_context_token.h>
#include <trust_rstr.h>
#include <trust_rst.h>
#include <openssl_util.h>
#include <oxs_utility.h>
#include <axutil_hash.h>
#include <axis2_conf_ctx.h>
#include <axis2_ctx.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_sct_provider.h>
#include <openssl_hmac.h>

#define RAMPART_SCT_PROVIDER_HASH_PROB "Rampart_SCT_Prov_DB_Prop"

axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text);

axiom_node_t *
build_om_payload_for_echo_svc_interop(const axutil_env_t *env, axis2_char_t *text);

axiom_node_t *
axis2_echo_echo(const axutil_env_t *env, axiom_node_t *node, axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *ret_node = NULL;
    axis2_char_t *name = NULL;
    AXIS2_ENV_CHECK(env, NULL);
    
    name = axiom_util_get_localname(node, env);
    AXIS2_LOG_INFO(env->log, "[rampart][sec_echo_service] Recieved node %s", name);     
/*
 * This shows how to acces the security processed results from the message context
    {
    axis2_char_t *username = NULL;
    
    username = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, "SPR_UT_username");
    printf("Username of the Token is = %s ", username);
    }
*/    
    ret_node = build_om_payload_for_echo_svc_interop(env, name);
    return ret_node;
}

/* Builds the response content */
axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/axis2/rampart/samples", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "RecievedNode", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "LocalName", NULL, &text_om_node);

    axiom_element_set_text(text_om_ele, env, text, text_om_node);
 
    return echo_om_node;
}

static void 
sct_hash_store_free(
    axutil_hash_t *sct_hash_store,
    const axutil_env_t *env)
{
	axutil_hash_index_t *hi = NULL;

	for (hi = axutil_hash_first(sct_hash_store, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			security_context_token_free((security_context_token_t*)v, env);        	
		}
	}

	axutil_hash_free(sct_hash_store, env);
}

static axutil_hash_t *
get_sct_hash_store(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_hash_t *hash_store = NULL;
    
    /* Get the conf ctx */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
            "[rampart]Config context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    ctx = axis2_conf_ctx_get_base(conf_ctx,env);
    if(!ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Axis2 context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    /* Get the hash store property */
    property = axis2_ctx_get_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB);
    if(property)
    {
        /* Get the store */
        hash_store = (axutil_hash_t*)axutil_property_get_value(property, env);
    }
    else
    {
        axutil_property_t *hash_store_prop = NULL;

        hash_store = axutil_hash_make(env);
        hash_store_prop = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION,
               AXIS2_TRUE, (void *)sct_hash_store_free, hash_store);
        axis2_ctx_set_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB, hash_store_prop);
    }

    return hash_store;
}


axiom_node_t *
secconv_echo_sts_request_security_token(
    const axutil_env_t *env, 
    axiom_node_t *node, 
    axis2_msg_ctx_t *msg_ctx)
{
    trust_rst_t* rst = NULL;
    trust_rstr_t* rstr = NULL;
    axis2_status_t status;
    axis2_char_t *token_type = NULL;
    axis2_char_t *request_type = NULL;
    axis2_char_t *global_id = NULL;
    axis2_char_t *local_id = NULL;
    oxs_buffer_t *shared_secret = NULL;
    security_context_token_t *sct = NULL;
    axiom_node_t* rstr_node = NULL;
    int size = 32;
    axutil_hash_t* db = NULL;
    trust_entropy_t* requester_entropy = NULL;

    /*create and populate rst using node given*/
    rst = trust_rst_create(env);
    trust_rst_set_wst_ns_uri(rst, env, TRUST_WST_XMLNS_05_02);
    status = trust_rst_populate_rst(rst, env, node);
    if(status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] cannot populate rst");
        return NULL;
    }

    /*check whether rst is valid and can be processed*/
    token_type = trust_rst_get_token_type(rst, env);
    if((!token_type) || (0 != axutil_strcmp(token_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02)))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] token type is not valid");
        return NULL;
    }
    request_type = trust_rst_get_request_type(rst, env);
    if(!request_type) /*|| (0 != axutil_strcmp(request_type, TRUST_REQ_TYPE_ISSUE)))*/
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] request type is not valid");
        return NULL;
    }

    requester_entropy = trust_rst_get_entropy(rst, env);;

    axutil_allocator_switch_to_global_pool(env->allocator);

    /*create global id, local id, and shared secret*/
    global_id = oxs_util_generate_id(env,"urn:uuid:");
    local_id = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX, oxs_util_generate_id(env, "sctId"));
    shared_secret = oxs_buffer_create(env);
    if(requester_entropy)
    {
        size = trust_rst_get_key_size(rst, env)/16;
    }
    openssl_generate_random_data(env, shared_secret, size);

    /*create security context token and populate it*/
    sct = security_context_token_create(env);
    security_context_token_set_is_sc10(sct, env, AXIS2_TRUE);
    security_context_token_set_global_identifier(sct, env, global_id);
    security_context_token_set_local_identifier(sct, env, local_id);
    
    if(requester_entropy)
    {
        oxs_buffer_t *buffer = NULL;
        int requester_entropy_len = 0;
        axis2_char_t *decoded_requester_entropy = NULL;
        axis2_char_t *requester_nonce = NULL;
        int issuer_entropy_len = 0;
        axis2_char_t *decoded_issuer_entropy = NULL;
        int key_size = 0;
        axis2_char_t *output = NULL;
        
        buffer = oxs_buffer_create(env);
        requester_nonce = trust_entropy_get_binary_secret(requester_entropy, env);
        requester_entropy_len = axutil_base64_decode_len(requester_nonce);
        decoded_requester_entropy = AXIS2_MALLOC(env->allocator, requester_entropy_len);
        axutil_base64_decode_binary((unsigned char*)decoded_requester_entropy, requester_nonce);

        issuer_entropy_len = oxs_buffer_get_size(shared_secret, env);
        decoded_issuer_entropy = oxs_buffer_get_data(shared_secret, env);

        key_size = size * 2;
        output = AXIS2_MALLOC(env->allocator, key_size);

        openssl_p_hash(env, (unsigned char*)decoded_requester_entropy, requester_entropy_len,
                            (unsigned char*)decoded_issuer_entropy, issuer_entropy_len, 
                            (unsigned char*)output, key_size);
        oxs_buffer_populate(buffer, env, (unsigned char*)output, key_size);
        security_context_token_set_secret(sct, env, buffer);
    }
    else
    {
        security_context_token_set_secret(sct, env, shared_secret);
    }

    /*store SCT so that when server needs it, can be extracted*/
    db = get_sct_hash_store(env, msg_ctx);
    if(!db)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] Cannot get sct datastore");
        security_context_token_free(sct, env);
        return NULL;
    }

    axutil_hash_set_env(db, env);
    axutil_hash_set(db, global_id, AXIS2_HASH_KEY_STRING, sct);
    axutil_allocator_switch_to_local_pool(env->allocator);

    /*create rstr and populate*/
    rstr = trust_rstr_create(env);
    trust_rstr_set_token_type(rstr, env, token_type);
    trust_rstr_set_request_type(rstr, env, request_type);
    trust_rstr_set_wst_ns_uri(rstr, env, TRUST_WST_XMLNS_05_02);
    trust_rstr_set_requested_unattached_reference(rstr, env, 
                    security_context_token_get_unattached_reference(sct, env));
    trust_rstr_set_requested_attached_reference(rstr, env, 
                    security_context_token_get_attached_reference(sct, env));
    trust_rstr_set_requested_security_token(rstr, env, 
                    security_context_token_get_token(sct, env));

    if(requester_entropy)
    {
        axis2_char_t *nonce = NULL;
        trust_entropy_t* entropy = NULL;
        axiom_node_t *computed_key = NULL;
        axiom_element_t *computed_key_element = NULL;
        axiom_node_t *requested_proof = NULL;

        trust_rstr_set_key_size(rstr, env, size * 16);

        nonce = AXIS2_MALLOC(env->allocator, sizeof(char) * (axutil_base64_encode_len(size)+1));
        axutil_base64_encode(nonce, (char*)oxs_buffer_get_data(shared_secret, env), size);

        entropy = trust_entropy_create(env);
        trust_entropy_set_binary_secret(entropy, env, nonce);
        trust_entropy_set_ns_uri(entropy, env, TRUST_WST_XMLNS_05_02);
        trust_entropy_set_binary_secret_type(entropy, env, NONCE);
        trust_rstr_set_entropy(rstr, env, entropy);

        computed_key = trust_util_computed_key_element(env, TRUST_WST_XMLNS_05_02, NULL);
        computed_key_element = axiom_node_get_data_element(computed_key, env);
        axiom_element_set_text(computed_key_element, env, TRUST_COMPUTED_KEY_PSHA1, computed_key);
        requested_proof = trust_util_create_requsted_proof_token_element(env, TRUST_WST_XMLNS_05_02, NULL, computed_key);
        trust_rstr_set_requested_proof_token(rstr, env, requested_proof);
    }
    else
    {
        trust_rstr_set_requested_proof_token(rstr, env, 
                        security_context_token_get_requested_proof_token(sct, env));
    }

    /*build the rstr node*/
    rstr_node = trust_rstr_build_rstr(rstr, env, NULL);

    /*clear stuff*/
    trust_rstr_free(rstr, env);

    /*set the action*/
    axis2_msg_ctx_set_wsa_action(msg_ctx, env, SECCONV_200502_REQUEST_ISSUE_ACTION);

    /*return the node*/
    return rstr_node;
}

axiom_node_t *
build_om_payload_for_echo_svc_interop(const axutil_env_t *env, axis2_char_t *text)
{
 axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 = axiom_namespace_create(env, "http://InteropBaseAddress/interop", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "echoResponse", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "LocalName", NULL, &text_om_node);

    axiom_element_set_text(text_om_ele, env, text, text_om_node);
 
    return echo_om_node;

}
