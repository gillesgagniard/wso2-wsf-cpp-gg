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

#include <trust_util.h>
#include <oxs_key.h>

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_rst_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axis2_char_t * context)
{
    axiom_node_t *rst_node = NULL;
    axiom_element_t *rst_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_attribute_t *context_attr = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    rst_ele = axiom_element_create(env, NULL, TRUST_REQUEST_SECURITY_TOKEN, wst_ns, &rst_node);

    if (!rst_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST Element creation failed.");
        return NULL;
    }

    if (context)
    {
        context_attr = axiom_attribute_create(env, TRUST_RST_CONTEXT, context, wst_ns);
        status = axiom_element_add_attribute(rst_ele, env, context_attr, rst_node);

        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] RST Element add attribute function failed.");
            return NULL;
        }
    }

    return rst_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_rstr_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axis2_char_t * context)
{
    axiom_node_t *rstr_node = NULL;
    axiom_element_t *rstr_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_attribute_t *context_attr = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    rstr_ele =
        axiom_element_create(env, NULL, TRUST_REQUEST_SECURITY_TOKEN_RESPONSE, wst_ns, &rstr_node);

    if (!rstr_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR Element creation failed.");
        return NULL;
    }

    if (context)
    {
        context_attr = axiom_attribute_create(env, TRUST_RST_CONTEXT, context, wst_ns);
        status = axiom_element_add_attribute(rstr_ele, env, context_attr, rstr_node);

        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] RSTR Element add attribute function failed.");
            return NULL;
        }
    }

    return rstr_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_rstr_collection_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri)
{
    axiom_node_t *rstrc_node = NULL;
    axiom_element_t *rstrc_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    rstrc_ele =
        axiom_element_create(env, NULL, TRUST_REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION, wst_ns,
                             &rstrc_node);

    if (!rstrc_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTRC Element creation failed.");
        return NULL;
    }

    return rstrc_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_request_type_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * request_type)
{
    axis2_char_t *req_type_str = NULL;
    axiom_node_t *request_type_node = NULL;
    axiom_element_t *request_type_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    request_type_ele =
        axiom_element_create(env, parent_node, TRUST_REQUEST_TYPE, wst_ns, &request_type_node);

    if (!request_type_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestType Element creation failed.");
        return NULL;
    }

    if (0 == axutil_strcmp(request_type, TRUST_REQ_TYPE_ISSUE) ||
        0 == axutil_strcmp(request_type, TRUST_REQ_TYPE_CANCEL) ||
        0 == axutil_strcmp(request_type, TRUST_REQ_TYPE_RENEW) ||
        0 == axutil_strcmp(request_type, TRUST_REQ_TYPE_VALIDATE))
    {
        req_type_str = axutil_stracat(env, wst_ns_uri, request_type);
        status = axiom_element_set_text(request_type_ele, env, req_type_str, request_type_node);
		AXIS2_FREE(env->allocator, req_type_str);
    }
    else
    {
        status = axiom_element_set_text(request_type_ele, env, request_type, request_type_node);
    }

    if (status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] RequestType Element's setting text function failed.");
        return NULL;
    }

    return request_type_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_token_type_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * token_type)
{
    axiom_node_t *token_type_node = NULL;
    axiom_element_t *token_type_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    token_type_ele =
        axiom_element_create(env, parent_node, TRUST_TOKEN_TYPE, wst_ns, &token_type_node);

    if (!token_type_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] TokenType Element creation failed.");
        return NULL;
    }

    status = axiom_element_set_text(token_type_ele, env, token_type, token_type_node);
    if (status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] TokenType Element's setting text function failed.");
        return NULL;
    }

    return token_type_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_applies_to_element(
    const axutil_env_t * env,
    axiom_node_t * parent_node,
    const axis2_char_t * address,
    const axis2_char_t * addressing_ns)
{
    axiom_node_t *applies_to_node = NULL;
    axiom_node_t *epr_node = NULL;
    axiom_node_t *addr_node = NULL;
    axiom_element_t *applies_to_ele = NULL;
    axiom_element_t *epr_ele = NULL;
    axiom_element_t *addr_ele = NULL;
    axiom_namespace_t *wsp_ns = NULL;
    axiom_namespace_t *wsa_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wsp_ns = axiom_namespace_create(env, TRUST_WSP_XMLNS, TRUST_WSP);
    wsa_ns = axiom_namespace_create(env, addressing_ns, TRUST_WSA);

    applies_to_ele =
        axiom_element_create(env, parent_node, TRUST_APPLIES_TO, wsp_ns, &applies_to_node);
    if (!applies_to_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] AppliesTo Element creation failed!");
        return NULL;
    }

    epr_ele = axiom_element_create(env, applies_to_node, TRUST_EPR, wsa_ns, &epr_node);
    if (!epr_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] EndpointReference Element creation failed!");
        return NULL;
    }

    addr_ele = axiom_element_create(env, epr_node, TRUST_EPR_ADDRESS, wsa_ns, &addr_node);
    if (!addr_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Address Element creation failed!");
        return NULL;
    }

    status = axiom_element_set_text(addr_ele, env, address, addr_node);
    if (status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] Address Element's setting text function failed.");
        return NULL;
    }

    return applies_to_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_claims_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * dialect_uri)
{
    axiom_node_t *claims_node = NULL;
    axiom_element_t *claims_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_attribute_t *dialect_attr = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    claims_ele = axiom_element_create(env, parent_node, TRUST_CLAIMS, wst_ns, &claims_node);
    if (!claims_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Claims Element creation failed!");
        return NULL;
    }
    
    if (dialect_uri)
    {
		wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
        dialect_attr = axiom_attribute_create(env, TRUST_CLAIMS_DIALECT, dialect_uri, NULL);
        if (dialect_attr)
        {
            status = axiom_element_add_attribute(claims_ele, env, dialect_attr, claims_node);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] Claims element adding attribute failed.");
                return NULL;
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Dialect attribute creation failed.");
            return NULL;
        }

    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Dialect uri null.");
        return NULL;
    }

    return claims_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_requested_security_token_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * sec_token_node)
{
    axiom_node_t *requested_token_node = NULL;
    axiom_element_t *requested_token_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    
    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    requested_token_ele =
        axiom_element_create(env, parent_node, TRUST_REQUESTED_SECURITY_TOKEN, wst_ns,
                             &requested_token_node);
    
    if (!requested_token_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] RequestedSecurityToken Element creation failed!");
        return NULL;
    }
    
    if(sec_token_node)
    {      
        axiom_node_add_child(requested_token_node, env, sec_token_node);
    }

    return requested_token_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_requsted_proof_token_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t *req_proof_token)
{
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *requested_prooft_node = NULL;
    axiom_element_t *requested_prooft_ele = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    requested_prooft_ele =
        axiom_element_create(env, parent_node, TRUST_REQUESTED_PROOF_TOKEN, wst_ns,
                             &requested_prooft_node);
    if (!requested_prooft_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] RequestedProofToken Element creation failed!");
        return NULL;
    }
    if(req_proof_token)
    {
        if(AXIS2_FAILURE == axiom_node_add_child(requested_prooft_node, env, req_proof_token))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestedProofToken child setting failed!");
            return NULL;
        }
    }

    return requested_prooft_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_entropy_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node)
{
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *entropy_node = NULL;
    axiom_element_t *entropy_ele = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    entropy_ele = axiom_element_create(env, parent_node, TRUST_ENTROPY, wst_ns, &entropy_node);
    if (!entropy_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Entropy Element creation failed!");
        return NULL;
    }

    return entropy_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_computed_key_element(
    const axutil_env_t * env,
	axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node)
{
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *computed_key_node = NULL;
    axiom_element_t *computed_key_ele = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    computed_key_ele =
        axiom_element_create(env, parent_node, TRUST_COMPUTED_KEY, wst_ns, &computed_key_node);
    if (!computed_key_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] ComputedKey Element creation failed!");
        return NULL;
    }

    return computed_key_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_binary_secret_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * enc_secret,
    axis2_char_t * bin_sec_type)
{
    axiom_node_t *bin_sec_node = NULL;
    axiom_element_t *bin_sec_ele = NULL;
    axiom_attribute_t *bin_sec_type_attr = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_char_t *type_str = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    bin_sec_ele =
        axiom_element_create(env, parent_node, TRUST_BINARY_SECRET, wst_ns, &bin_sec_node);
    if (!bin_sec_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] BinarySecret Element creation failed!");
        return NULL;
    }

    if (enc_secret)
    {
        /* Setting up the encoeded secret */
        status = axiom_element_set_text(bin_sec_ele, env, enc_secret, bin_sec_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] BinarySecret Element's setting text failed.");
            return NULL;
        }
    }

    if (bin_sec_type)
    {
        /* Setting up BS-Type attribute */
        type_str = axutil_stracat(env, wst_ns_uri, bin_sec_type);
        bin_sec_type_attr = axiom_attribute_create(env, ATTR_TYPE, type_str, NULL);
        if (!bin_sec_type_attr)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] BinarySecret Element's Type attribute creation failed.");
            return NULL;
        }

        status = axiom_element_add_attribute(bin_sec_ele, env, bin_sec_type_attr, bin_sec_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] BinarySecret Element's attribute adding failed.");
            return NULL;
        }
    }

    return bin_sec_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_computed_key_algo_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * algo_id)
{
    axiom_node_t *comp_key_algo_node = NULL;
    axiom_element_t *comp_key_algo_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    /*axis2_char_t *algo = NULL;*/
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    if (algo_id)
    {
        comp_key_algo_ele =
            axiom_element_create(env, parent_node, TRUST_COMPUTED_KEY_ALGO, wst_ns,
                                 &comp_key_algo_node);
        if (!comp_key_algo_ele)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] ComputedKeyAlgorithm element creation failed.");
            return NULL;
        }

        /*algo = axutil_strcat(env, wst_ns_uri, "/" ,algo_id);*/
        status = axiom_element_set_text(comp_key_algo_ele, env, algo_id, comp_key_algo_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] ComputedKeyAlgorithm Element's setting text failed.");
            return NULL;
        }

    }

    return comp_key_algo_node;
}

/* KEY SIZE Element*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_key_size_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * key_size)
{
    axiom_node_t *key_size_node = NULL;
    axiom_element_t *key_size_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    key_size_ele = axiom_element_create(env, parent_node, TRUST_KEY_SIZE, wst_ns, &key_size_node);
    if (!key_size_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeySize element creation failed.");
        return NULL;
    }

    if (key_size)
    {
        status = axiom_element_set_text(key_size_ele, env, key_size, key_size_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] KeySize Element's setting text failed.");
            return NULL;
        }
    }

    return key_size_node;
}

/* KEY TYPE Element*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_key_type_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * key_type)
{
    axiom_node_t *key_type_node = NULL;
    axiom_element_t *key_type_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_char_t *type = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    key_type_ele = axiom_element_create(env, parent_node, TRUST_KEY_TYPE, wst_ns, &key_type_node);
    if (!key_type_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeyType element creation failed.");
        return NULL;
    }

    if (key_type)
    {
        if (0 == axutil_strcmp(key_type, TRUST_KEY_TYPE_SYMM_KEY) ||
            0 == axutil_strcmp(key_type, TRUST_KEY_TYPE_PUBLIC_KEY) ||
            0 == axutil_strcmp(key_type, TRUST_KEY_TYPE_BEARER))
        {
            type = axutil_stracat(env, wst_ns_uri, key_type);
            status = axiom_element_set_text(key_type_ele, env, type, key_type_node);
            
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] KeyType Element's setting text failed.");
                return NULL;
            }
        }
    }

    return key_type_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_life_time_element(
        const axutil_env_t * env,
        axiom_node_t * parent_node,
        axis2_char_t *wst_ns_uri,
        int ttl)
{
    axiom_node_t *life_time_node = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *life_time_ele = NULL;
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expires_ele = NULL;
    axis2_char_t *created_val_str = NULL;
    axis2_char_t *expires_val_str = NULL;
    axiom_namespace_t *wsu_ns = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axutil_date_time_t *dt = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);
    wsu_ns = axiom_namespace_create(env, TRUST_WSU_XMLNS, TRUST_WSU);

    life_time_ele =
        axiom_element_create(env, parent_node, TRUST_LIFE_TIME, wst_ns, &life_time_node);

    if (life_time_ele)
    {
        created_ele =
            axiom_element_create(env, life_time_node, TRUST_LIFE_TIME_CREATED, wsu_ns,
                                 &created_node);
        if (created_ele)
        {
            dt = axutil_date_time_create_with_offset(env, 0);
            created_val_str = axutil_date_time_serialize_date_time(dt, env);
            status = axiom_element_set_text(created_ele, env, created_val_str, created_node);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] Created Element's setting text failed.");
                return NULL;
            }

            AXIS2_FREE(env->allocator, created_val_str);
            axutil_date_time_free(dt, env);
            created_val_str = NULL;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Created element creation failed.");
            return NULL;
        }

        /*if ttl <0 we dont build the expires element */
        if (ttl < 0)
        {
            return life_time_node;
        }

        expires_ele =
            axiom_element_create(env, life_time_node, TRUST_LIFE_TIME_EXPIRES, wsu_ns,
                                 &expires_node);
        if (expires_ele)
        {
            dt = axutil_date_time_create_with_offset(env, ttl);
            expires_val_str = axutil_date_time_serialize_date_time(dt, env);
            axiom_element_set_text(expires_ele, env, expires_val_str, expires_node);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] Expires Element's setting text failed.");
                return NULL;
            }

            AXIS2_FREE(env->allocator, expires_val_str);
            axutil_date_time_free(dt, env);
            expires_val_str = NULL;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Expires element creation failed.");
            return NULL;
        }

        return life_time_node;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] LifeTime element creation failed.");
        return NULL;
    }

    return NULL;
}

/* RequstedAttachedReference */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_req_attached_reference_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node)
{
    axiom_node_t *attached_ref_node = NULL;
    axiom_element_t *attached_ref_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    attached_ref_ele =
        axiom_element_create(env, parent_node, TRUST_REQUESTED_ATTACHED_REFERENCE, wst_ns,
                             &attached_ref_node);
    if (!attached_ref_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] RequestedAttachedReference element creation failed.");
        return NULL;
    }

    return attached_ref_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_req_unattached_reference_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node)
{
    axiom_node_t *unattached_ref_node = NULL;
    axiom_element_t *unattached_ref_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    unattached_ref_ele =
        axiom_element_create(env, parent_node, TRUST_REQUESTED_UNATTACHED_REFERENCE, wst_ns,
                             &unattached_ref_node);
    if (!unattached_ref_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] RequestedUnAttachedReference element creation failed.");
        return NULL;
    }

    return unattached_ref_node;
}

/*AuthenticationType*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_authentication_type_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * authentication_type)
{
    axiom_node_t *authentication_type_node = NULL;
    axiom_element_t *authentication_type_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    authentication_type_ele =
        axiom_element_create(env, parent_node, TRUST_AUTHENTICATION_TYPE, wst_ns,
                             &authentication_type_node);
    if (!authentication_type_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] AuthenticationType element creation failed.");
        return NULL;
    }
    
    if (authentication_type)
    {
        status = axiom_element_set_text(authentication_type_ele, env, authentication_type, authentication_type_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] Authenticationtype Element's setting text failed.");
            return NULL;
        }
    }

    return authentication_type_node;
    
}

/*SignatureAlgorithm*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_signature_algo_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * signature_algo)
{
    axiom_node_t *signature_algo_node = NULL;
    axiom_element_t *signature_algo_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    signature_algo_ele =
        axiom_element_create(env, parent_node, TRUST_SIGNATURE_ALGO, wst_ns,
                             &signature_algo_node);
    if (!signature_algo_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] SignatureAlgo element creation failed.");
        return NULL;
    }
    
    if (signature_algo)
    {
        status = axiom_element_set_text(signature_algo_ele, env, signature_algo, signature_algo_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] SignatureAlgo Element's setting text failed.");
            return NULL;
        }
    }

    return signature_algo_node;
}

/*EncryptionAlgorithm*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_encryption_algo_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * encryption_algo)
{
    axiom_node_t *encryption_algo_node = NULL;
    axiom_element_t *encryption_algo_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    encryption_algo_ele =
        axiom_element_create(env, parent_node, TRUST_ENCRYPTION_ALGO, wst_ns,
                             &encryption_algo_node);
    if (!encryption_algo_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] EncryptionAlgo element creation failed.");
        return NULL;
    }
    
    if (encryption_algo)
    {
        status = axiom_element_set_text(encryption_algo_ele, env, encryption_algo, encryption_algo_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] EncryptionAlgo Element's setting text failed.");
            return NULL;
        }
    }

    return encryption_algo_node;
}

/*CanonicalizationAlgorithm*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_canonicalization_algo_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * canonicalization_algo)
{
    axiom_node_t *canonicalization_algo_node = NULL;
    axiom_element_t *canonicalization_algo_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    canonicalization_algo_ele =
        axiom_element_create(env, parent_node, TRUST_CANONICAL_ALGO, wst_ns,
                             &canonicalization_algo_node);
    if (!canonicalization_algo_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] CanonicalizationAlgo element creation failed.");
        return NULL;
    }
    
    if (canonicalization_algo)
    {
        status = axiom_element_set_text(canonicalization_algo_ele, env, canonicalization_algo, canonicalization_algo_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] CanonicalizationAlgo Element's setting text failed.");
            return NULL;
        }
    }

    return canonicalization_algo_node;
}

/*ComputedKeyAlgorithm*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_computedkey_algo_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * computedkey_algo)
{
    axiom_node_t *computedkey_algo_node = NULL;
    axiom_element_t *computedkey_algo_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    computedkey_algo_ele =
        axiom_element_create(env, parent_node, TRUST_COMPUTED_KEY_ALGO, wst_ns,
                             &computedkey_algo_node);
    if (!computedkey_algo_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] ComputedKeyAlgo element creation failed.");
        return NULL;
    }
    
    if (computedkey_algo)
    {
        status = axiom_element_set_text(computedkey_algo_ele, env, computedkey_algo, computedkey_algo_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] ComputedKey Element's setting text failed.");
            return NULL;
        }
    }
    

    return computedkey_algo_node;   
}

/*(Desired)Encryption*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_desired_encryption_element(
    const axutil_env_t * env,
    axis2_char_t * wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * encryption_key) /*@param encryption_key - This can be either a key or a STR*/
{
    axiom_node_t *desired_encryption_node = NULL;
    axiom_element_t *desired_encryption_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    
    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    desired_encryption_ele =
        axiom_element_create(env, parent_node, TRUST_DESIRED_ENCRYPTION, wst_ns,
                             &desired_encryption_node);
    
    if (!desired_encryption_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] Encryption Element creation failed!");
        return NULL;
    }
    
    if(encryption_key)
    {      
        /*This node can be a key or a STR*/
        axiom_node_add_child(desired_encryption_node, env, encryption_key);
    }

    return desired_encryption_node;    
}

/*ProofEncryption*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_proof_encryption_element(
    const axutil_env_t * env,
    axis2_char_t * wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * proof_encryption_key) /*@param encryption_key - This can be either a key or a STR*/
{
    axiom_node_t *proof_encryption_node = NULL;
    axiom_element_t *proof_encryption_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    
    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    proof_encryption_ele =
        axiom_element_create(env, parent_node, TRUST_PROOF_ENCRYPTION, wst_ns,
                             &proof_encryption_node);
    
    if (!proof_encryption_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] ProofEncryption Element creation failed!");
        return NULL;
    }
    
    if(proof_encryption_key)
    {      
        /*This node can be a key or a STR*/
        axiom_node_add_child(proof_encryption_node, env, proof_encryption_key);
    }

    return proof_encryption_node; 
}

/*UseKey*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_usekey_element(
    const axutil_env_t * env,
    axis2_char_t * wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * usekey_key) /*@param encryption_key - This can be either a key or a STR*/
{
    axiom_node_t *usekey_node = NULL;
    axiom_element_t *usekey_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    
    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    usekey_ele =
        axiom_element_create(env, parent_node, TRUST_USE_KEY, wst_ns,
                             &usekey_node);
    
    if (!usekey_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] UseKey Element creation failed!");
        return NULL;
    }
    
    if(usekey_key)
    {      
        /*This node can be a key or a STR*/
        axiom_node_add_child(usekey_node, env, usekey_key);
    }

    return usekey_node; 
    
    
}

/*SignWith*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_signwith_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * signwith)
{
    axiom_node_t *signwith_node = NULL;
    axiom_element_t *signwith_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    signwith_ele =
        axiom_element_create(env, parent_node, TRUST_SIGN_WITH, wst_ns,
                             &signwith_node);
    if (!signwith_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] SignWith element creation failed.");
        return NULL;
    }
    
    if (signwith)
    {
        status = axiom_element_set_text(signwith_ele, env, signwith, signwith_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] SignWith Element's setting text failed.");
            return NULL;
        }
    }

    return signwith_node;   
}

/*EncryptWith*/
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_encryptwith_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axis2_char_t * encryptwith)
{
    axiom_node_t *encryptwith_node = NULL;
    axiom_element_t *encryptwith_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    encryptwith_ele =
        axiom_element_create(env, parent_node, TRUST_ENCRYPT_WITH, wst_ns,
                             &encryptwith_node);
    if (!encryptwith_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[trust] EncryptWith element creation failed.");
        return NULL;
    }
    
    if (encryptwith)
    {
        status = axiom_element_set_text(encryptwith_ele, env, encryptwith, encryptwith_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] EncryptWith Element's setting text failed.");
            return NULL;
        }
    }

    return encryptwith_node;   
    
    
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_encrypted_data_element(
    const axutil_env_t * env,
    axiom_node_t * parent_node,
    axis2_char_t * enc_data)
{
    axiom_node_t *encrypted_node = NULL;
    axiom_element_t *encrypted_ele = NULL;
    axiom_namespace_t *xenc_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    xenc_ns = axiom_namespace_create(env, TRUST_XENC_XMLNS, TRUST_XENC);
    encrypted_ele =
        axiom_element_create(env, parent_node, TRUST_ENCRYPTED_DATA, xenc_ns, &encrypted_node);
    if (!encrypted_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] EncryptedData element creation failed.");
        return NULL;
    }
    if (enc_data)
    {
        status = axiom_element_set_text(encrypted_ele, env, enc_data, encrypted_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] Encrypted Data Element's setting text failed.");
            return NULL;
        }
    }

    return encrypted_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_renew_traget_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * renew_pending_node)
{
    axiom_node_t *renew_target_node = NULL;
    axiom_element_t *renew_target_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    renew_target_ele =
        axiom_element_create(env, parent_node, TRUST_RENEW_TARGET, wst_ns, &renew_target_node);
    if (!renew_target_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RenewTarget element creation failed.");
        return NULL;
    }
    if (renew_pending_node)
    {
        /* Set up token as it is  for the request */
        status = axiom_node_add_child(renew_target_node, env, renew_pending_node);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[trust] token renew pending node adding as a child failed.");
        }
    }

    /** Otherwise user has to create a STR as a child ot RenewTarget element and
     *  add the token reference to it.
     **/
    return renew_target_node;

}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_allow_postdating_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node)
{
    axiom_node_t *allow_postdating_node = NULL;
    axiom_element_t *allow_postdating_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    allow_postdating_ele =
        axiom_element_create(env, parent_node, TRUST_REQUESTED_UNATTACHED_REFERENCE, wst_ns,
                             &allow_postdating_node);
    if (!allow_postdating_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] AllowPostdating element creation failed.");
        return NULL;
    }

    return allow_postdating_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_renewing_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    trust_allow_t allow_flag,
    trust_ok_t ok_flag)
{
    axiom_node_t *renewing_node = NULL;
    axiom_element_t *renewing_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_attribute_t *allow_attr = NULL;
    axiom_attribute_t *ok_attr = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_char_t *allow = NULL;
    axis2_char_t *ok = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    renewing_ele = axiom_element_create(env, parent_node, TRUST_RENEWING, wst_ns, &renewing_node);

    sprintf(allow, "%d", allow_flag);
    sprintf(ok, "%d", ok_flag);

    allow_attr = axiom_attribute_create(env, TRUST_RENEW_ALLOW_ATTR, allow, wst_ns);
    ok_attr = axiom_attribute_create(env, TRUST_RENEW_OK_ATTR, ok, wst_ns);

    status = axiom_element_add_attribute(renewing_ele, env, allow_attr, renewing_node);
    if (status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Allow attribute setting failed.");
    }
    status = axiom_element_add_attribute(renewing_ele, env, ok_attr, renewing_node);
    if (status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Ok attribute setting failed.");
    }

    return renewing_node;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_cancel_target_element(
    const axutil_env_t * env,
    axis2_char_t *wst_ns_uri,
    axiom_node_t * parent_node,
    axiom_node_t * token_cancel_pending_node)
{
    axiom_node_t *cancel_target_node = NULL;
    axiom_element_t *cancel_target_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    cancel_target_ele =
        axiom_element_create(env, parent_node, TRUST_CANCEL_TARGET, wst_ns, &cancel_target_node);
    if (!cancel_target_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] CancelTarget element creation failed.");
        return NULL;
    }

    if (token_cancel_pending_node)
    {
        /* Set up token as it is  for the request */
        axiom_node_add_child(cancel_target_node, env, token_cancel_pending_node);
    }

    /** Otherwise user has to create a STR as a child ot CancelTarget element and
    *   add the token reference to it.
    **/
    return cancel_target_node;

}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_util_create_validation_response_element(
    const axutil_env_t * env,
    axiom_node_t * parent_node,
    axis2_char_t *wst_ns_uri,
    axis2_char_t * code,
    axis2_char_t * reason)
{
    axiom_node_t *status_node = NULL;
    axiom_node_t *code_node = NULL;
    axiom_node_t *reason_node = NULL;
    axiom_element_t *status_ele = NULL;
    axiom_element_t *code_ele = NULL;
    axiom_element_t *reason_ele = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

    status_ele =
        axiom_element_create(env, parent_node, TRUST_VALIDATION_STATUS, wst_ns, &status_node);
    if (status_ele)
    {
        if (code)
        {
            code_ele =
                axiom_element_create(env, status_node, TRUST_VALIDATION_CODE, wst_ns, &code_node);
            if (!code_ele)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Code element creation failed.");
                return NULL;
            }
            status = axiom_element_set_text(code_ele, env, code, code_node);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] Code element text setting failed.");
                return NULL;
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Code string null.");
            return NULL;
        }

        if (reason)
        {
            reason_ele =
                axiom_element_create(env, status_node, TRUST_VALIDATION_REASON, wst_ns,
                                     &reason_node);
            if (!reason_ele)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Reason element creation failed.");
                return NULL;
            }
            status = axiom_element_set_text(reason_ele, env, reason, reason_node);
            if (status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[trust] Reason element text setting failed.");
                return status_node;
            }
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Status element creation failed.");
        return NULL;
    }

    return status_node;
}


/*Generating Random Session Key*/
AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_util_create_random_session_key_proof_token_element(
		const axutil_env_t * env,
		axis2_char_t *wst_ns_uri)
{
	axiom_namespace_t *wst_ns = NULL;
	axiom_node_t *requested_prooft_node = NULL;
	axiom_element_t *requested_prooft_ele = NULL;

	axiom_node_t *binary_secret_node = NULL;
	int encodedlen = 0;

	oxs_key_t *session_key = NULL;
	axis2_char_t * base64_encoded_key = NULL;

	wst_ns = axiom_namespace_create(env, wst_ns_uri, TRUST_WST);

	requested_prooft_ele = axiom_element_create(env, NULL, TRUST_REQUESTED_PROOF_TOKEN, wst_ns, &requested_prooft_node);

	if (!requested_prooft_ele)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
				"[trust] RequestedProofToken-Session Key Proof- Element creation failed!");
		return NULL;
	}	


	/*Generating Session key*/
	session_key = oxs_key_create(env);
	oxs_key_for_algo(session_key, env, NULL);

	if(oxs_key_get_data(session_key, env))
	{
		/*Encoding the binary key to base 64 encoded value*/

		/*FIX : Encoded length is hardcoded :64 */

		encodedlen = axutil_base64_encode_len(strlen((const char *)oxs_key_get_data(session_key, env)));
		base64_encoded_key = AXIS2_MALLOC(env->allocator, encodedlen);

		axutil_base64_encode(base64_encoded_key, (const char *)oxs_key_get_data(session_key, env), strlen((const char *)oxs_key_get_data(session_key, env)));

		/*Inside <binarysecret> element*/
		binary_secret_node = trust_util_create_binary_secret_element(env, wst_ns_uri, requested_prooft_node, base64_encoded_key, TRUST_KEY_TYPE_SYMM_KEY);

		return requested_prooft_node;
	}

	return NULL;
}

axis2_char_t *AXIS2_CALL
trust_util_get_wst_ns(
    const axutil_env_t * env,
    int wst_version)
{
    switch (wst_version)
    {
    case TRUST_VERSION_05_02:
        return axutil_strdup(env, TRUST_WST_XMLNS_05_02);
    case TRUST_VERSION_05_12:
        return axutil_strdup(env, TRUST_WST_XMLNS_05_12);
    default:
        return NULL;
    }
}
