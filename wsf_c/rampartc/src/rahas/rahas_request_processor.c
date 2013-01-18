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
#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <trust_rst.h>
#include <trust_rstr.h>
#include <oxs_buffer.h>
#include <rampart_constants.h>
#include <rampart_context.h>
#include <openssl_hmac.h>
#include <oxs_utility.h>
#include <openssl_util.h>
#include <rampart_handler_util.h>

static security_context_token_t *
rahas_create_security_context_token(
    const axutil_env_t *env, 
    axis2_bool_t server_entropy_needed, 
    trust_entropy_t *requester_entropy, 
    int key_size,
    oxs_buffer_t **server_secret);

static axis2_status_t
rahas_store_security_context_token(
    const axutil_env_t *env, 
    security_context_token_t *sct, 
    axis2_msg_ctx_t *msg_ctx);

static axis2_status_t
rahas_validate_issue_request_parameters(
    const axutil_env_t *env, 
    trust_rst_t *rst, 
    trust_rstr_t *rstr,
    axis2_msg_ctx_t *msg_ctx,
    int trust_version, 
    axis2_bool_t client_entropy_needed, 
    trust_entropy_t** requester_entropy);

static axis2_status_t
rahas_populate_rstr_for_issue_request(
    const axutil_env_t *env, 
    trust_rstr_t *rstr,
    int trust_version, 
    axis2_bool_t client_entropy_needed, 
    oxs_buffer_t *server_secret, 
    security_context_token_t *sct, 
    int key_size);

static axis2_status_t
rahas_get_sts_policy_parameters(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx, 
    axis2_bool_t *client_entropy_needed,
    axis2_bool_t *server_entropy_needed);


/**
 * Processes issue request
 * @param env pointer to environment struct
 * @param rst request security token struct
 * @param rstr request security token response struct
 * @param msg_ctx message context structure
 * @param trust_version Trust specification. Can be TRUST_VERSION_05_02 or TRUST_VERSION_05_12
 * @return AXIS2_SUCCESS if processed successfully. AXIS2_FAILURE otherwise.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rahas_process_issue_request(
    const axutil_env_t *env, 
    trust_rst_t *rst, 
    trust_rstr_t *rstr,
    axis2_msg_ctx_t *msg_ctx,
    int trust_version)
{
    trust_entropy_t* requester_entropy = NULL;
    oxs_buffer_t *server_secret = NULL;
    security_context_token_t *sct = NULL;
    axis2_bool_t client_entropy_needed = AXIS2_FALSE;
    axis2_bool_t server_entropy_needed = AXIS2_FALSE;
    int key_size = TRUST_DEFAULT_KEY_SIZE;

    /* check whether client entropy and server entropy are needed */
    if (rahas_get_sts_policy_parameters(
        env, msg_ctx, &client_entropy_needed, &server_entropy_needed) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot issue SecurityContextToken because security token service policy "
            "could not be found.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        return AXIS2_FAILURE;
    }

    /* validate whether given parameters are ok to proceed */
    if(rahas_validate_issue_request_parameters(env, rst, rstr, msg_ctx, trust_version, 
        client_entropy_needed, &requester_entropy) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot issue SecurityContextToken because parameter validation failed.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_INVALID, 
            "The request was invalid or malformed", RAMPART_FAULT_TRUST_REQUEST_INVALID, msg_ctx);
        return AXIS2_FAILURE;
    }

    /* Get the size of the key*/
    key_size = trust_rst_get_key_size(rst, env);
    
    /* size is not a compulsary field. If missing, we can use default size */
    if(key_size <= 0)
    {
        key_size = TRUST_DEFAULT_KEY_SIZE;
    }

    /* Create sct and populate it */
    sct = rahas_create_security_context_token(
        env, server_entropy_needed, requester_entropy, key_size, &server_secret);
    if(!sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot issue SecurityContextToken because SCT creation failed.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        return AXIS2_FAILURE;
    }

    /* set sct version */
    if(trust_version == TRUST_VERSION_05_02)
    {
        security_context_token_set_is_sc10(sct, env, AXIS2_TRUE);
    }
    else if(trust_version == TRUST_VERSION_05_12)
    {
        security_context_token_set_is_sc10(sct, env, AXIS2_FALSE);
    }


    /* store SCT so that when server needs it, can be extracted. It is the responsibility of the 
     * storing implementer to switch to global pool if needed */
    if(rahas_store_security_context_token(env, sct, msg_ctx) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]Cannot store SecurityContextToken.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        security_context_token_free(sct, env);
        return AXIS2_FAILURE;
    }

    /* Populate rstr structure */
    if (rahas_populate_rstr_for_issue_request(env, rstr, trust_version, 
        client_entropy_needed, server_secret, sct, key_size) != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot issue SecurityContextToken because response createion failed.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_TRUST_REQUEST_FAILED, 
            "The specified request failed", RAMPART_FAULT_TRUST_REQUEST_FAILED, msg_ctx);
        security_context_token_free(sct, env);
        return AXIS2_FAILURE;
    }
    
    return AXIS2_SUCCESS;
}

/* this method validates whether rst, rstr, msg_ctx, trust_version are correct. If they are ok, 
 * it will populate requester_entropy. requester_entropy will be output parameter */
static axis2_status_t
rahas_validate_issue_request_parameters(
    const axutil_env_t *env, 
    trust_rst_t *rst, 
    trust_rstr_t *rstr,
    axis2_msg_ctx_t *msg_ctx,
    int trust_version, 
    axis2_bool_t client_entropy_needed, 
    trust_entropy_t** requester_entropy)
{
    axis2_char_t *token_type = NULL;
    axis2_char_t *expected_token_type = NULL;

    if(!rst)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Given RequestSecurityToken structure is not valid.");
        return AXIS2_FAILURE;
    }

    if(!rstr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Given RequestSecurityTokenResponse structure is not valid.");
        return AXIS2_FAILURE;
    }

    if(!msg_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Given Message context structure is not valid.");
        return AXIS2_FAILURE;
    }

    /* check whether trust version is valid, and if so, get trust version specific constants */
    if(trust_version == TRUST_VERSION_05_02)
    {
        expected_token_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02;
    }
    else if(trust_version == TRUST_VERSION_05_12)
    {
        expected_token_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12; 
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Given trust specification version is not valid or not supported.");
        return AXIS2_FAILURE;
    }

    /* check whether token type is valid and can be processed */
    token_type = trust_rst_get_token_type(rst, env);
    if(!token_type)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rahas]Token type is not given.");
        return AXIS2_FAILURE;
    }

    if(axutil_strcmp(token_type, expected_token_type))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Given token type [%s] is not valid. Expected token type is [%s]", 
            token_type, expected_token_type);
        return AXIS2_FAILURE;
    }

    /* check whether client entropy is needed according to policy and whether it is provided */
    *requester_entropy = trust_rst_get_entropy(rst, env);
    if(client_entropy_needed)
    {
        if(!*requester_entropy)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rahas]Client entropy is expected, but not given by client.");
            return AXIS2_FAILURE;
        }
    }
    else
    {
        if(*requester_entropy)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rahas]Client entropy is not expected, but it is given by client.");
            return AXIS2_FAILURE;
        }
    }

    return AXIS2_SUCCESS;
}

static security_context_token_t *
rahas_create_security_context_token(
    const axutil_env_t *env, 
    axis2_bool_t server_entropy_needed, 
    trust_entropy_t *requester_entropy, 
    int key_size,
    oxs_buffer_t **server_secret)
{
    axis2_char_t *global_id = NULL;
    axis2_char_t *local_id = NULL;
    security_context_token_t *sct = NULL;

    /* given key size will be in bits. Convert into bytes */
    int key_size_in_byte = key_size / 8;

    /* we are going to create objects which will be shared among multiple requests. So we have to 
     * create in global pool */
    axutil_allocator_switch_to_global_pool(env->allocator);

    /* create security context token */
    sct = security_context_token_create(env);
    if(!sct)
    {
        axutil_allocator_switch_to_local_pool(env->allocator);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot create security context token. Insufficient memory.");
        return NULL;
    }

    /* create global id, local id */
    global_id = oxs_util_generate_id(env, SECCONV_GLOBAL_ID_PREFIX);
    local_id = axutil_stracat(
        env, OXS_LOCAL_REFERENCE_PREFIX, oxs_util_generate_id(env, SECCONV_LOCAL_ID_PREFIX));
    
    /* check whether server secret is needed. If specifically said "server entropy needed" then 
     * no problem. If not said specifically, and if client entropy is not there, then again we have 
     * to provide a shared secret */
    if((server_entropy_needed) || (!requester_entropy))
    {
        int server_secret_size = key_size_in_byte;
        /* if client entropy is given, our entropy should be half of the size given */
        if(requester_entropy)
        {
            server_secret_size = server_secret_size / 2;
        }
        *server_secret = oxs_buffer_create(env);
        openssl_generate_random_data(env, *server_secret, server_secret_size);
    }

    /* populate security context token */
    security_context_token_set_global_identifier(sct, env, global_id);
    security_context_token_set_local_identifier(sct, env, local_id);

    if(requester_entropy)
    {
        axis2_char_t *requester_nonce = NULL;
        int requester_entropy_len = 0;
        axis2_char_t *decoded_requester_entropy = NULL;
        oxs_buffer_t *buffer = NULL;

        /* client entropy will be in base64 format. should decode it */
        requester_nonce = trust_entropy_get_binary_secret(requester_entropy, env);
        requester_entropy_len = axutil_base64_decode_len(requester_nonce);
        decoded_requester_entropy = AXIS2_MALLOC(env->allocator, requester_entropy_len);
        axutil_base64_decode_binary((unsigned char*)decoded_requester_entropy, requester_nonce);
        buffer = oxs_buffer_create(env);

        if(server_entropy_needed)
        {
            /* we have client entropy and server entropy. so shared secret will be combined key */
            axis2_char_t *output = NULL;

            output = AXIS2_MALLOC(env->allocator, key_size);
            openssl_p_hash(env, 
                (unsigned char*)decoded_requester_entropy, requester_entropy_len,
                oxs_buffer_get_data(*server_secret, env), oxs_buffer_get_size(*server_secret, env), 
                (unsigned char*)output, key_size_in_byte);
            oxs_buffer_populate(buffer, env, (unsigned char*)output, key_size_in_byte);
        }
        else
        {
            /* we have to use client entropy as the sct shared secret */
            oxs_buffer_populate(
                buffer, env, (unsigned char*)decoded_requester_entropy, requester_entropy_len);
        }

        security_context_token_set_secret(sct, env, buffer);
    }
    else
    {
        /* we have to use server entropy as the sct shared secret */
        security_context_token_set_secret(sct, env, *server_secret);
    }

    /* we are done with creating the SCT. Now we can switch back to local pool */
    axutil_allocator_switch_to_local_pool(env->allocator);

    return sct;
}

static axis2_status_t
rahas_populate_rstr_for_issue_request(
    const axutil_env_t *env, 
    trust_rstr_t *rstr,
    int trust_version, 
    axis2_bool_t client_entropy_needed, 
    oxs_buffer_t *server_secret, 
    security_context_token_t *sct, 
    int key_size)
{
    axis2_char_t *token_type = NULL;
    axis2_char_t *trust_ns_uri = NULL;
    axis2_char_t *computed_key_algo = NULL;

    /* Get trust version specific constants */
    if(trust_version == TRUST_VERSION_05_02)
    {
        trust_ns_uri = TRUST_WST_XMLNS_05_02;
        token_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02;
        computed_key_algo = TRUST_COMPUTED_KEY_PSHA1;
        security_context_token_set_is_sc10(sct, env, AXIS2_TRUE);
    }
    else if(trust_version == TRUST_VERSION_05_12)
    {
        trust_ns_uri = TRUST_WST_XMLNS_05_12;
        token_type = OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12; 
        computed_key_algo = TRUST_COMPUTED_KEY_PSHA1_05_12;
        security_context_token_set_is_sc10(sct, env, AXIS2_FALSE);
    }

    /* We have to populate issue request specific items.
     * (1) Token Type
     * (2) Attached reference
     * (3) Unattached reference
     * (4) SCT representation
     * (5) Shared secret.
     * We are assuming request_type, namespace, etc. are already populated. */
    trust_rstr_set_token_type(rstr, env, token_type);
    trust_rstr_set_requested_unattached_reference(rstr, env, 
                    security_context_token_get_unattached_reference(sct, env));
    trust_rstr_set_requested_attached_reference(rstr, env, 
                    security_context_token_get_attached_reference(sct, env));
    trust_rstr_set_requested_security_token(rstr, env, 
                    security_context_token_get_token(sct, env));

    /* we have to send the key detail to client. 
     * (1) If client entropy and server entropy is used, we have to send server entropy and computed
           key
     * (2) If only server entropy is used, then we have to send entropy as proof token
     * (3) If only client entropy is used, then we don't have to send anything. 
     */
    if((client_entropy_needed) && (server_secret))
    {
        /* we have to send computed key and entropy */
        axis2_char_t *nonce = NULL;
        trust_entropy_t* entropy = NULL;
        axiom_node_t *computed_key = NULL;
        axiom_element_t *computed_key_element = NULL;
        axiom_node_t *requested_proof = NULL;
        
        /* if client and server entropy are there, then server entropy will be half the key_size. 
         * Also, key size is in bits. So, actual server_entropy size is key_size / 16 */
        int size = key_size / 16; 

        trust_rstr_set_key_size(rstr, env, key_size);
        nonce = AXIS2_MALLOC(env->allocator, sizeof(char) * (axutil_base64_encode_len(size)+1));
        axutil_base64_encode(nonce, (char*)oxs_buffer_get_data(server_secret, env), size);

        entropy = trust_entropy_create(env);
        trust_entropy_set_binary_secret(entropy, env, nonce);
        trust_entropy_set_ns_uri(entropy, env, trust_ns_uri);
        trust_entropy_set_binary_secret_type(entropy, env, NONCE);
        trust_rstr_set_entropy(rstr, env, entropy);

        computed_key = trust_util_computed_key_element(env, trust_ns_uri, NULL);
        computed_key_element = axiom_node_get_data_element(computed_key, env);
        axiom_element_set_text(computed_key_element, env, computed_key_algo, computed_key);
        requested_proof = trust_util_create_requsted_proof_token_element(
            env, trust_ns_uri, NULL, computed_key);
        trust_rstr_set_requested_proof_token(rstr, env, requested_proof);
    }
    else if(!client_entropy_needed)
    {
        /* server key only. so have to send proof token */
        trust_rstr_set_requested_proof_token(
            rstr, env, security_context_token_get_requested_proof_token(sct, env));
    }

    return AXIS2_SUCCESS;
}

/* this method uses store_method defined in rampart context to store sct */
static axis2_status_t
rahas_store_security_context_token(
    const axutil_env_t *env, 
    security_context_token_t *sct, 
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_property_t *property = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    property = axis2_msg_ctx_get_property(msg_ctx, env, RAMPART_CONTEXT);
    if(property)
    {
        rampart_context_t *rampart_context = NULL;
        rampart_context = (rampart_context_t *)axutil_property_get_value(property, env);
        if(rampart_context)
        {
            store_security_context_token_fn store_fn = NULL;
            void *user_param = NULL;

            store_fn = rampart_context_get_store_security_context_token_fn(rampart_context, env);
            user_param = rampart_context_get_security_context_token_user_params(
                rampart_context, env);
            status = store_fn(env, msg_ctx, security_context_token_get_global_identifier(sct, env),
                security_context_token_get_local_identifier(sct, env), sct, user_param);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rahas]Cannot find rampart context. Cannot store security context token.");
            status = AXIS2_FAILURE;
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot find rampart context property. Cannot store security context token.");
        status = AXIS2_FAILURE;
    }

    return status;
}

/* This method checks whether rampart policy has STS related parameters. If so, will extract it */
static axis2_status_t
rahas_get_sts_policy_parameters(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx, 
    axis2_bool_t *client_entropy_needed,
    axis2_bool_t *server_entropy_needed)
{
    axutil_property_t *property = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    property = axis2_msg_ctx_get_property(msg_ctx, env, RAMPART_CONTEXT);
    if(property)
    {
        rampart_context_t *rampart_context = NULL;
        rampart_context = (rampart_context_t *)axutil_property_get_value(property, env);
        if(rampart_context)
        {
           rp_secpolicy_t *sec_policy = NULL;
           sec_policy = rampart_context_get_secpolicy(rampart_context, env);
           if(sec_policy)
           {
               rp_trust10_t *trust_policy = NULL;
               trust_policy = rp_secpolicy_get_trust10(sec_policy, env);
               if(trust_policy)
               {
                   *client_entropy_needed = rp_trust10_get_require_client_entropy(trust_policy, env);
                   *server_entropy_needed = rp_trust10_get_require_server_entropy(trust_policy, env);
               }
               else
               {
                   *client_entropy_needed = AXIS2_FALSE;
                   *server_entropy_needed = AXIS2_FALSE;
               }
           }
           else
           {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rahas]Cannot find security policy related to security context token service "
                    "from rampart context.");
                status = AXIS2_FAILURE;
           }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rahas]Cannot find rampart context. "
                "Cannot find policy related to security context token service.");
            status = AXIS2_FAILURE;
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rahas]Cannot find rampart context property. "
            "Cannot find policy related to security context token service.");
        status = AXIS2_FAILURE;
    }

    return status;
}
