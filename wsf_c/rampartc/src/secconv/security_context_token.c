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

#include <secconv_security_context_token.h>
#include <oxs_buffer.h>
#include <oxs_tokens.h>
#include <trust_constants.h>
#include <trust_util.h>

struct security_context_token_t
{
    oxs_buffer_t *buffer;
    axis2_char_t *global_id;
    axis2_char_t *local_id;
    axiom_node_t *sct_node;
    axiom_node_t *attached_reference;
    axiom_node_t *unattached_reference;
    axis2_bool_t is_sc10;
    int ref;
};

/**
 * Creates security context token 
 * @param env Pointer to environment struct
 * @returns Security context token if success. NULL otherwise.
 */
AXIS2_EXTERN security_context_token_t *AXIS2_CALL
    security_context_token_create(
    const axutil_env_t * env)
{
    security_context_token_t *sct = NULL;
    AXIS2_ENV_CHECK(env, NULL);

    sct =  (security_context_token_t *) AXIS2_MALLOC (
        env->allocator, sizeof (security_context_token_t));

    if(!sct)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot create Security context token. Insufficient memory.");
    }
    else
    {
        sct->buffer = NULL;
        sct->global_id = NULL;
        sct->local_id = NULL;
        sct->sct_node = NULL;
        sct->attached_reference = NULL;
        sct->unattached_reference = NULL;
        sct->is_sc10 = AXIS2_FALSE;
        sct->ref = 1;
    }
    return sct;
}

/**
 * Free security context token 
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_free(
    security_context_token_t *sct, 
    const axutil_env_t *env)
{
    if (--sct->ref <= 0)
    {
        if(sct->buffer)
        {
            oxs_buffer_free(sct->buffer, env);
        }
        if(sct->local_id)
        {
            AXIS2_FREE(env->allocator, sct->local_id);
        }
        if(sct->global_id)
        {
            AXIS2_FREE(env->allocator, sct->global_id);
        }
        if(sct->sct_node)
        {
            axiom_node_free_tree(sct->sct_node, env);
        }
        if(sct->attached_reference)
        {
            axiom_node_free_tree(sct->attached_reference, env);
        }
        if(sct->unattached_reference)
        {
            axiom_node_free_tree(sct->unattached_reference, env);
        }

        AXIS2_FREE(env->allocator, sct);
    }
    return AXIS2_SUCCESS;
}

/**
 * Get shared secret from security context token. Callers should not free returned buffer
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns shared secret if success. NULL otherwise.
 */
AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
security_context_token_get_secret(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->buffer;
}

/**
 * Get global id of security context token. 
 * This id will be used when token is not included in the message
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns global id if success. NULL otherwise.
 */
AXIS2_EXTERN axis2_char_t *AXIS2_CALL
security_context_token_get_global_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->global_id;
}

/**
 * Get local id of security context token. 
 * This id will be used when token is included in the message
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns local id if success. NULL otherwise.
 */
AXIS2_EXTERN axis2_char_t *AXIS2_CALL
security_context_token_get_local_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->local_id;
}

/**
 * Set shared secret of security context token. After this method is called, ownership of 
 * the buffer will be with security context token. Users should not free it.
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param buffer Pointer to shared secret
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_secret(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    oxs_buffer_t *buffer)
{
    if(sct->buffer)
    {
        oxs_buffer_free(sct->buffer, env);
    }
    sct->buffer = buffer;
    return AXIS2_SUCCESS;
}

/**
 * Set WS-SecureConversation version 
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param is_sc10 Boolean denoting whether we need security context token as in WS-SecConv 1.0
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_is_sc10(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axis2_bool_t is_sc10)
{
    sct->is_sc10 = is_sc10;
    return AXIS2_SUCCESS;
}

/**
 * Set global identifier of security context token. After this method is called, ownership of 
 * global_id will be with security context token. Users should not free it.
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param global_id Global identifier of security context token
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_global_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    axis2_char_t *global_id)
{
    if(sct->global_id)
    {
        AXIS2_FREE(env->allocator, sct->global_id);
    }
    sct->global_id = global_id;
    return AXIS2_SUCCESS;
}

/**
 * Set local identifier of security context token. After this method is called, ownership of 
 * local_id will be with security context token. Users should not free it.
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param local_id Local identifier of securiy context token
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_local_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    axis2_char_t *local_id)
{
    if(sct->local_id)
    {
        AXIS2_FREE(env->allocator, sct->local_id);
    }
    sct->local_id = local_id;
    return AXIS2_SUCCESS;
}

/**
 * Get shared secret as axiom_node. Shared secret will be included inside 
 * 'RequestedProofToken' node. This is acording to WS-Trust specification 
 * <wst:RequestedProofToken>
 *      <wst:BinarySecret>Base64EncodedSharedSecret</wst:BinarySecret>
 * </wst:RequestedProofToken>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns valid axiom_node if success. NULL otherwise.
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_requested_proof_token(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    int encodedlen;
    axis2_char_t *encoded_str = NULL;
    axiom_node_t* proof_token = NULL;
    axiom_element_t *proof_token_ele = NULL;
    axiom_node_t* secret_node = NULL;
    axiom_element_t *secret_ele = NULL;
    axiom_namespace_t *ns_obj_wst = NULL;

    if(!sct->buffer)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security context token does not have a shared secret");
        return NULL;
    }
    
    if(sct->is_sc10)
    {
        ns_obj_wst = axiom_namespace_create(env, TRUST_WST_XMLNS_05_02, TRUST_WST);
    }
    else
    {
        ns_obj_wst = axiom_namespace_create(env, TRUST_WST_XMLNS_05_12, TRUST_WST);
    }
    
    proof_token_ele = axiom_element_create(
        env, NULL, TRUST_REQUESTED_PROOF_TOKEN, ns_obj_wst, &proof_token);
    if (!proof_token_ele)
	{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot create requested proof token");
        return NULL;
    }

    secret_ele = axiom_element_create(
        env, proof_token, TRUST_BINARY_SECRET, ns_obj_wst, &secret_node);
    if(!secret_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot create binary secret token");
        return NULL;
    }

	encodedlen = axutil_base64_encode_len(oxs_buffer_get_size(sct->buffer, env));
    encoded_str = AXIS2_MALLOC(env->allocator, encodedlen);
    axutil_base64_encode(encoded_str, 
        (const char *)oxs_buffer_get_data(sct->buffer, env), oxs_buffer_get_size(sct->buffer, env));
    axiom_element_set_text(secret_ele, env, encoded_str, secret_node);
	AXIS2_FREE(env->allocator, encoded_str);

    return proof_token;
}

/**
 * Get local id of security context token as axiom node. 
 * This id will be used when token is included in the message
 * <wsse:SecurityTokenReference>
 *      <wsse:Reference>AttachedReference</wsse:Reference>
 * </wsse:SecurityTokenReference>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns valid axiom node if success. NULL otherwise.
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_attached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t *str_token = NULL;

    if(sct->attached_reference)
    {
        /* If attached reference is given by STS, then we have to return same reference */
        str_token = oxs_axiom_clone_node(env, sct->attached_reference);
    }
    else
    {
        /* If attached reference is not given by STS, then we have to create it */
        if(sct->local_id)
        {
            axiom_node_t *ref_token = NULL;
            axis2_char_t *value_type;

            if(sct->is_sc10)
            {
                value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02;
            }
            else
            {
                value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12;
            }
            str_token = oxs_token_build_security_token_reference_element(env, NULL); 
            ref_token = oxs_token_build_reference_element(
                env, str_token, sct->local_id, value_type); 
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Security context token does not have a local identifier");
        }
    }

    return str_token; 
}

/**
 * Get global id of security context token as axiom node. 
 * This id will be used when token is not included in the message
 * <wsse:SecurityTokenReference>
 *      <wsse:Reference>UnattachedReference</wsse:Reference>
 * </wsse:SecurityTokenReference>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns valid axiom node if success. NULL otherwise.
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_unattached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t *str_token = NULL;
    
    if(sct->unattached_reference)
    {
        /* If unattached reference is given by STS, then we have to return same reference */
        str_token = oxs_axiom_clone_node(env, sct->unattached_reference);
    }
    else
    {
        /* If unattached reference is not given by STS, then we have to create it */
        if(sct->global_id)
        {
            axiom_node_t *ref_token = NULL;
            axis2_char_t *value_type;

            if(sct->is_sc10)
            {
                value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02;
            }
            else
            {
                value_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12;
            }
            str_token = oxs_token_build_security_token_reference_element(env, NULL); 
            ref_token = oxs_token_build_reference_element(
                env, str_token, sct->global_id, value_type); 
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Security context token does not have a global identifier");
        }
    }
    return str_token; 
}

/**
 * Get axiom node representation of security context token. 
 * This will be included in the message if the token needs to be sent in the message
 * <wsc:SecurityContextToken wsu:id=local_id> 
 *      <wsc:Identifier>global_id</wsc:Identifier>
 * </wsc:SecurityContextToken>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns valid axiom node if success. NULL otherwise.
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_token(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t* sct_token = NULL;
    axiom_element_t *token_ele = NULL;
    axiom_node_t* identifier_node = NULL;
    axiom_element_t *identifier_ele = NULL;
    axiom_namespace_t *ns_obj_sc = NULL;
    axiom_namespace_t *ns_obj_wsu = NULL;
    axiom_attribute_t *id_attr = NULL;

    if(sct->sct_node)
        return oxs_axiom_clone_node(env, sct->sct_node);

    if(!sct->global_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security context token does not have an identifier.");
        return NULL;
    }

    if(sct->is_sc10)
    {
        ns_obj_sc = axiom_namespace_create(env, OXS_WSC_NS_05_02, OXS_WSC);
    }
    else
    {
        ns_obj_sc = axiom_namespace_create(env, OXS_WSC_NS_05_12, OXS_WSC);
    }
    token_ele = axiom_element_create(
        env, NULL, OXS_NODE_SECURITY_CONTEXT_TOKEN, ns_obj_sc, &sct_token);
    if (!token_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error creating SecurityContextToken element.");
        return NULL;
    }

    if(sct->local_id)
    {
		axis2_char_t *id = NULL;
        
        /* local id is in the format of '#sct2343443'. When including it in the axiom representation 
         * of the token, we should remove first '#' */
		id = axutil_string_substring_starting_at(axutil_strdup(env, sct->local_id), 1);

        ns_obj_wsu = axiom_namespace_create(env, OXS_WSU_XMLNS, OXS_WSU);
        id_attr = axiom_attribute_create(env, OXS_ATTR_ID, id, ns_obj_wsu);
        axiom_element_add_attribute(token_ele, env, id_attr, sct_token);
		AXIS2_FREE(env->allocator, id);
    }

    identifier_ele = axiom_element_create(
        env, sct_token, OXS_NODE_IDENTIFIER, ns_obj_sc, &identifier_node);
    if(!identifier_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error creating Identifier element of security context token.");
        return NULL;
    }
    axiom_element_set_text(identifier_ele, env, sct->global_id, identifier_node);

    return sct_token;
}

/**
 * Set shared secret of security context token from proof token. This proof token will be given
 * by STS. 
 * <wst:BinarySecret>Base64EncodedSharedSecret</wst:BinarySecret>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param node Pointer to proof token axiom node
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_requested_proof_token(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    axis2_char_t *shared_secret = NULL;
    int decoded_len = 0;
    axis2_char_t *decoded_shared_secret = NULL;
    oxs_buffer_t *buffer = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    shared_secret = oxs_axiom_get_node_content(env, node);
    if(!shared_secret)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Cannot get content of binary secret node");
        return AXIS2_FAILURE;
    }
    
    decoded_len = axutil_base64_decode_len(shared_secret);
	decoded_shared_secret = AXIS2_MALLOC(env->allocator, decoded_len);
	axutil_base64_decode_binary((unsigned char*)decoded_shared_secret, shared_secret);

    buffer = oxs_buffer_create(env);
    oxs_buffer_populate(buffer, env, (unsigned char*)decoded_shared_secret, decoded_len);
    AXIS2_FREE(env->allocator, decoded_shared_secret);

    return security_context_token_set_secret(sct, env, buffer);
}

/**
 * Set local identifier of security context token from attached reference node. 
 * <wsse:SecurityTokenReference>
 *      <wsse:Reference>AttachedReference</wsse:Reference>
 * </wsse:SecurityTokenReference>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param node Pointer to attached reference axiom node
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_attached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    axiom_node_t *ref_token = NULL;
    axis2_char_t *local_id = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    ref_token = oxs_axiom_get_first_child_node_by_name(
        env, node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get reference node from attached reference");
        return AXIS2_FAILURE;
    }

    local_id = oxs_token_get_reference(env, ref_token);
    if(!local_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot get attached reference");
        return AXIS2_FAILURE;
    }
    
    sct->attached_reference = oxs_axiom_clone_node(env, node);
    return security_context_token_set_local_identifier(sct, env, axutil_strdup(env, local_id));
}

/**
 * Set global identifier of security context token from unattached reference node. 
 * <wsse:SecurityTokenReference>
 *      <wsse:Reference>AttachedReference</wsse:Reference>
 * </wsse:SecurityTokenReference>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param node Pointer to unattached reference axiom node
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_unattached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    axiom_node_t *ref_token = NULL;
    axis2_char_t *reference_id = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    ref_token = oxs_axiom_get_first_child_node_by_name(
        env, node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get reference node from unattached reference");
        return AXIS2_FAILURE;
    }

    reference_id = oxs_token_get_reference(env, ref_token);
    if(!reference_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Cannot get unattached reference");
        return AXIS2_FAILURE;
    }
    
    sct->unattached_reference = oxs_axiom_clone_node(env, node);

    return security_context_token_set_global_identifier(sct, env, axutil_strdup(env, reference_id));
}

/**
 * Set axiom representation of security context token. We don't need to understand the details of it
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param node Pointer to security context token axiom node
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_token(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    sct->sct_node = oxs_axiom_clone_node(env, node);
    return AXIS2_SUCCESS;
}

/**
 * Increment the reference of security context token
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_increment_ref(
    security_context_token_t *sct,
    const axutil_env_t * env)
{
    sct->ref++;
    return AXIS2_SUCCESS;
}

/**
 * Serializes the security context token. Caller should take the ownership of returned value.
 * Serialized value will be of format
 * <wsc:SecurityContextToken wsu:id=local_id> 
 *      <wsc:Identifier>global_id</wsc:Identifier>
 *      <wst:RequestedProofToken>
 *          <wst:BinarySecret>Base64EncodedSharedSecret</wst:BinarySecret>
 *      </wst:RequestedProofToken>
 *      <wst:RequestedAttachedReference>
 *          <wsse:SecurityTokenReference>
 *              <wsse:Reference>AttachedReference</wsse:Reference>
 *          </wsse:SecurityTokenReference>
 *      </wst:RequestedAttachedReference>
 *      <wst:RequestedUnattachedReference>
 *          <wsse:SecurityTokenReference>
 *              <wsse:Reference>AttachedReference</wsse:Reference>
 *          </wsse:SecurityTokenReference>
 *      </wst:RequestedUnattachedReference>
 * </wsc:SecurityContextToken>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @returns serialized security context token if success. NULL otherwise
 */
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
security_context_token_serialize(
    security_context_token_t *sct, 
    const axutil_env_t *env)
{
    axiom_node_t *sct_node = NULL;
    axiom_node_t *proof_node = NULL;
    axiom_node_t *attached_ref_node = NULL;
    axiom_node_t *unattached_ref_node = NULL;
    axiom_node_t *parent_attached_ref_node = NULL;
    axiom_node_t *parent_unattached_ref_node = NULL;
    axis2_char_t *serialised_node = NULL;
    axis2_char_t *wst_uri = NULL;


    sct_node = security_context_token_get_token(sct, env);
    if(!sct_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot serialise security context token.");
        return NULL;
    }

    proof_node = security_context_token_get_requested_proof_token(sct, env);
    attached_ref_node = security_context_token_get_attached_reference(sct, env);
    unattached_ref_node = security_context_token_get_unattached_reference(sct, env);
    
    if(!proof_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot serialise proof token of security context token.");
        axiom_node_free_tree(sct_node, env);
        return NULL;
    }
    axiom_node_add_child(sct_node, env, proof_node);

    /* get trust namespace based on version */
    if(sct->is_sc10)
    {
        wst_uri = TRUST_WST_XMLNS_05_02;
    }
    else
    {
        wst_uri = TRUST_WST_XMLNS_05_12;
    }

    /* attached reference is optional */
    if(attached_ref_node)
    {
        parent_attached_ref_node = trust_util_create_req_attached_reference_element(
            env, wst_uri, sct_node);
        if(!parent_attached_ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot serialise attached reference of security context token.");
            axiom_node_free_tree(sct_node, env);
            return NULL;
        }
        axiom_node_add_child(parent_attached_ref_node, env, attached_ref_node);    
    }

    /* unattached reference is optional */
    if(unattached_ref_node)
    {
        parent_unattached_ref_node = trust_util_create_req_unattached_reference_element(
            env, wst_uri, sct_node);
        if(!parent_unattached_ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot serialise unattached reference of security context token.");
            axiom_node_free_tree(sct_node, env);
            return NULL;
        }
        axiom_node_add_child(parent_unattached_ref_node, env, unattached_ref_node);
    }

    serialised_node = axiom_node_sub_tree_to_string(sct_node, env);
    axiom_node_free_tree(sct_node, env);

    return serialised_node;
}

/**
 * Deserializes the security context token. 
 * <wsc:SecurityContextToken wsu:id=local_id> 
 *      <wsc:Identifier>global_id</wsc:Identifier>
 *      <wst:RequestedProofToken>
 *          <wst:BinarySecret>Base64EncodedSharedSecret</wst:BinarySecret>
 *      </wst:RequestedProofToken>
 *      <wst:RequestedAttachedReference>
 *          <wsse:SecurityTokenReference>
 *              <wsse:Reference>AttachedReference</wsse:Reference>
 *          </wsse:SecurityTokenReference>
 *      </wst:RequestedAttachedReference>
 *      <wst:RequestedUnattachedReference>
 *          <wsse:SecurityTokenReference>
 *              <wsse:Reference>AttachedReference</wsse:Reference>
 *          </wsse:SecurityTokenReference>
 *      </wst:RequestedUnattachedReference>
 * </wsc:SecurityContextToken>
 * @param sct Pointer to secuirty context token struct
 * @param env Pointer to environment struct
 * @param serialised_node serialised string representation of security context token
 * @returns serialized security context token if success. NULL otherwise
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_deserialize(
    security_context_token_t *sct, 
    const axutil_env_t *env, 
    axis2_char_t *serialised_node)
{
    axiom_node_t *sct_node = NULL;
    axiom_node_t *proof_node = NULL;
    axiom_node_t *attached_ref_node = NULL;
    axiom_node_t *unattached_ref_node = NULL;
    axiom_node_t *parent_attached_ref_node = NULL;
    axiom_node_t *parent_unattached_ref_node = NULL;
    axiom_node_t *parent_proof_node = NULL;
    axis2_char_t *ns = NULL;
    axutil_qname_t *node_qname = NULL;
    axiom_element_t *element = NULL;

    sct_node = oxs_axiom_deserialize_node(env, serialised_node);
    if(!sct_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security context token deserialize failed.");
        return AXIS2_FAILURE;
    }

    /* get the namespace of root node and decide the sct version */
    element = (axiom_element_t *) axiom_node_get_data_element(sct_node, env);
    node_qname = axiom_element_get_qname(element, env, sct_node);
    if(!node_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Cannot get qname from SecurityContextToken element.");
        return AXIS2_FAILURE;
    }

    ns = axutil_qname_get_uri(node_qname, env);
    if(!ns)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Cannot get namespace from SecurityContextToken element.");
        return AXIS2_FAILURE;
    }

    if(!axutil_strcmp(ns, OXS_WSC_NS_05_02))
    {
        sct->is_sc10 = AXIS2_TRUE;
    }

    parent_proof_node = oxs_axiom_get_node_by_local_name(
        env, sct_node, TRUST_REQUESTED_PROOF_TOKEN);
    if(!parent_proof_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Proof not could not be found. Security context token deserialize failed.");
        return AXIS2_FAILURE;
    }

    axiom_node_detach(parent_proof_node, env);
    proof_node = oxs_axiom_get_node_by_local_name(env, parent_proof_node, TRUST_BINARY_SECRET);
    if(!proof_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Proof not could not be found. Security context token deserialize failed.");
        return AXIS2_FAILURE;
    }

    if(security_context_token_set_requested_proof_token(sct, env, proof_node) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Deserializing proof token node failed. " 
            "Security context token deserialize failed.");
        return AXIS2_FAILURE;
    }
    
    parent_attached_ref_node = oxs_axiom_get_node_by_local_name(
        env, sct_node, TRUST_REQUESTED_ATTACHED_REFERENCE);
    if(parent_attached_ref_node)
    {
        axiom_node_detach(parent_attached_ref_node, env);
        attached_ref_node = oxs_axiom_get_node_by_local_name(
            env, parent_attached_ref_node, OXS_NODE_SECURITY_TOKEN_REFRENCE);
        if(!attached_ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Attached reference node could not be found. " 
                "Security context token deserialize failed.");
            return AXIS2_FAILURE;
        }
        if (security_context_token_set_attached_reference(sct, env, attached_ref_node)
            != AXIS2_SUCCESS)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Deserializing attached reference node failed. " 
                "Security context token deserialize failed.");
            return AXIS2_FAILURE;
        }
    }
    
    parent_unattached_ref_node = oxs_axiom_get_node_by_local_name(
        env, sct_node, TRUST_REQUESTED_UNATTACHED_REFERENCE);
    if(parent_unattached_ref_node)
    {
        axiom_node_detach(parent_unattached_ref_node, env);
        unattached_ref_node = oxs_axiom_get_node_by_local_name(
            env, parent_unattached_ref_node, OXS_NODE_SECURITY_TOKEN_REFRENCE);
        if(!unattached_ref_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Unattached reference node could not be found. " 
                "Security context token deserialize failed.");
            return AXIS2_FAILURE;
        }
        if (security_context_token_set_unattached_reference(sct, env, unattached_ref_node)
            != AXIS2_SUCCESS)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Deserializing unattached reference node failed. " 
                "Security context token deserialize failed.");
            return AXIS2_FAILURE;
        }
    }

    if(security_context_token_set_token(sct, env, sct_node) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Deserializing security context token failed." );
        return AXIS2_FAILURE;
    }
    
    return AXIS2_SUCCESS;
}


