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

#include <trust_token.h>

struct trust_token {

    /*Token identifier*/
    axis2_char_t *id;

    /*Current state of the token*/
    trust_token_state_t state;

    /*The actual token in its current state <RequstedSecurityToken*/
    axiom_node_t *token;

    /*The token in its previous state*/
    axiom_node_t *previous_token;

    axiom_node_t *proof_token;

    /**
    *Store the RSTR's modifications of the requested parameters.
    *These RSTR parameters sholud be compare with the RST parameter and should take
    *the proprietary actions
    **/
    axis2_char_t *applies_to_uri;
    axis2_char_t *token_type_uri;

    /* Entropy */
    axiom_node_t* entropy;

    /* Entropy - BinarySecret */
    axis2_char_t *binary_secret;

    /**
     * The RequestedAttachedReference element
     * NOTE : The oasis-200401-wss-soap-message-security-1.0 spec allows 
     * an extensibility mechanism for wsse:SecurityTokenReference and 
     * wsse:Reference. Hence we cannot limit to the 
     * wsse:SecurityTokenReference\wsse:Reference case and only hold the URI and 
     * the ValueType values.
     */
    axiom_node_t *attached_reference;

    /**
     * The RequestedUnattachedReference element
     * NOTE : The oasis-200401-wss-soap-message-security-1.0 spec allows 
     * an extensibility mechanism for wsse:SecurityTokenRefence and 
     * wsse:Reference. Hence we cannot limit to the 
     * wsse:SecurityTokenReference\wsse:Reference case and only hold the URI and 
     * the ValueType values.
     */
    axiom_node_t *unattached_reference;

    /*A bag to hold any other properties*/
    /*trust_properties_t *properties;*/

    /*A flag to assist the TokenStorage*/
    axis2_bool_t changed;

    /*The secret associated with the Token*/
    unsigned char *secret;

    /*Created time*/
    axutil_date_time_t *created;

    /*Expiration Time*/
    axutil_date_time_t *expire;

    /*issuer end point address*/
    axis2_char_t* issuer_address;
};

AXIS2_EXTERN trust_token_t* AXIS2_CALL 
trust_token_create(
    const axutil_env_t *env,
    axis2_char_t *id,
    axiom_node_t *token_node,
    axiom_node_t *life_node)
{
    trust_token_t *token = NULL;
    axis2_status_t status;

    token = AXIS2_MALLOC(env->allocator, sizeof(trust_token_t));

    if(id)
    {
            token->id = id;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null id!");
            return NULL;
    }

    if(token_node)
    {
            token->token = token_node;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null token element!");
            return NULL;
    }

    if(life_node)
    {
            status = trust_token_process_life_elem(env, life_node, token);
            if(status == AXIS2_FAILURE)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Lifetime element processing failed.");
            }

    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null life element!");
            return NULL;
    }

    return token;

}

AXIS2_EXTERN trust_token_t* AXIS2_CALL 
trust_token_create_with_dates(const axutil_env_t *env,
        axis2_char_t *id,
        axiom_node_t *token_node,
        axutil_date_time_t *created,
        axutil_date_time_t *expire)
{
    trust_token_t *token = NULL;


    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    token = AXIS2_MALLOC(env->allocator, sizeof(trust_token_t));

    if(id)
    {
            token->id = id;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null id!");
            return NULL;
    }

    if(token_node)
    {
            token->token = token_node;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null token element!");
            return NULL;
    }

    if(created)
    {
            token->created = created;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null create date!");
            return NULL;
    }

    if(expire)
    {
            token->expire = expire;
    } else
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Cannot create trust token with null expired date!");
            return NULL;
    }
    return token;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_process_life_elem(const axutil_env_t *env,
    axiom_node_t *life_node,
    trust_token_t *token)
{
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expire_ele = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expire_node = NULL;
    axiom_element_t *life_ele = NULL;
    axutil_date_time_t *created_dt = NULL;
    axutil_date_time_t *expire_dt = NULL;
    axutil_qname_t *created_qn = NULL;
    axutil_qname_t *expire_qn = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_char_t *created_str = NULL;
    axis2_char_t *expire_str = NULL;

    if(!life_node){
            return AXIS2_FAILURE;
    }

    life_ele = axiom_node_get_data_element(life_node, env);

    created_dt = axutil_date_time_create(env);
    created_qn = axutil_qname_create(env, TRUST_LIFE_TIME_CREATED, TRUST_WSU_XMLNS, TRUST_WSU);
    created_ele = axiom_element_get_first_child_with_qname(life_ele, env, created_qn, life_node, &created_node);	
    created_str = axiom_element_get_text(created_ele, env, created_node);
    status = axutil_date_time_deserialize_date_time(created_dt, env, created_str);

    if(status == AXIS2_FAILURE){
            return status;
    }

    token->created = created_dt;


    expire_dt = axutil_date_time_create(env);
    expire_qn = axutil_qname_create(env, TRUST_LIFE_TIME_EXPIRES, TRUST_WSU_XMLNS, TRUST_WSU);
    expire_ele = axiom_element_get_first_child_with_qname(life_ele, env, expire_qn, life_node, &expire_node);
    expire_str = axiom_element_get_text(expire_ele, env, expire_node);
    status = axutil_date_time_deserialize_date_time(expire_dt, env, expire_str);

    if(status == AXIS2_FAILURE){
            return status;
    }

    token->expire = expire_dt;

    return status;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL 
trust_token_is_changed(
    const axutil_env_t *env,
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    return (token->changed);
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_changed(
    const axutil_env_t *env,
    trust_token_t *token,
    axis2_bool_t changed)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return AXIS2_FAILURE;

    token->changed = changed;

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN trust_token_state_t AXIS2_CALL 
trust_token_get_state(const axutil_env_t *env,
            trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return AXIS2_FAILURE;

    return token->state;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_token_set_state(const axutil_env_t *env, 
            trust_token_t *token, 
            trust_token_state_t state)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return AXIS2_FAILURE;
    token->state = state;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
trust_token_get_token(
        const axutil_env_t *env,
                    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return NULL;

    return token->token;	
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_token(
    const axutil_env_t *env, 
    trust_token_t *token, 
    axiom_node_t *token_node)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return AXIS2_FAILURE;
    token->token = token_node;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
trust_token_get_previous_token(
    const axutil_env_t *env,
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    if(!token)
            return NULL;

    return token->previous_token;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_previous_token(
    const axutil_env_t *env, 
    trust_token_t *token, 
    axiom_node_t *prev_token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return AXIS2_FAILURE;
    token->previous_token = prev_token;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
trust_token_get_id(
    const axutil_env_t *env,
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->id;
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
trust_token_get_attached_reference(
    const axutil_env_t *env, 
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->attached_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_attached_reference(
    const axutil_env_t *env, 
    trust_token_t *token,
    axiom_node_t *attached_reference)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return AXIS2_FAILURE;

    token->attached_reference = attached_reference;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
trust_token_get_unattached_reference(
    const axutil_env_t *env, 
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->unattached_reference;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_unattached_reference(
    const axutil_env_t *env, 
    trust_token_t *token, 
    axiom_node_t *unattached_reference)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return AXIS2_FAILURE;

    token->unattached_reference = unattached_reference;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
trust_token_get_created(
    const axutil_env_t *env, 
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->created;
}

AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
trust_token_get_expires(
    const axutil_env_t *env, 
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->expire;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL 
trust_token_set_expires(
    const axutil_env_t *env, 
    trust_token_t *token, 
    axutil_date_time_t *expire)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return AXIS2_FAILURE;

    token->expire = expire;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
trust_token_get_issuer_address(
    const axutil_env_t *env, 
    trust_token_t *token)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(!token)
            return NULL;

    return token->issuer_address;
}

