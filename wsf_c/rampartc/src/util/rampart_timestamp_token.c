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

#include <rampart_constants.h>
#include <rampart_util.h>
#include <rampart_timestamp_token.h>
#include <rampart_sec_processed_result.h>
#include <oxs_axiom.h>

/**
 * Builds timestamp token.
 * @param env pointer to environment struct
 * @param sec_node security node
 * @param ttl Time to live. The time difference btwn Created and Expired. If it is zero or less
 * than zero, then Expired element will not be created. 
 * @param with_millisecond shows whether millisecond precision is needed
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
axis2_status_t AXIS2_CALL
rampart_timestamp_token_build(
    const axutil_env_t *env,
    axiom_node_t *sec_node,
    int ttl, 
    axis2_bool_t with_millisecond)
{
    axiom_node_t *ts_node = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expires_node = NULL;
    axiom_element_t *ts_ele = NULL;
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expires_ele = NULL;
    axis2_char_t *created_val = NULL;
    axis2_char_t *expires_val = NULL;
    axiom_namespace_t *wsu_ns_obj = NULL;

    wsu_ns_obj = axiom_namespace_create(env, RAMPART_WSU_XMLNS, RAMPART_WSU);
    if(!wsu_ns_obj)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Unable to create %s namespace.", RAMPART_WSU);
        return AXIS2_FAILURE;
    }

    ts_ele = axiom_element_create(env, sec_node, RAMPART_SECURITY_TIMESTAMP, wsu_ns_obj, &ts_node);
    if(!ts_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Timestamp element creation failed.");
        axiom_namespace_free(wsu_ns_obj, env);
        return AXIS2_FAILURE;
    }

    /* First we build Created element */
    created_ele = axiom_element_create(
        env, ts_node, RAMPART_SECURITY_TIMESTAMP_CREATED, wsu_ns_obj, &created_node);
    if(!created_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Unable to build 'Created' child element of timestamp.");
        return AXIS2_FAILURE;
    }

    created_val = rampart_generate_time(env, 0, with_millisecond);   /* Current time */
    axiom_element_set_text(created_ele, env, created_val, created_node);
    AXIS2_FREE(env->allocator, created_val);
    created_val = NULL;

    /* Then we build Expires element */
    /* TIP: If ttl<0 then we don't build the expires element. */
    if(ttl <= 0)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, " [rampart]ttl is %d which is less then zero. "
            "Thus we do not need to build the expires element.", ttl);
        return AXIS2_SUCCESS;
    }

    expires_ele = axiom_element_create(
        env, ts_node, RAMPART_SECURITY_TIMESTAMP_EXPIRES, wsu_ns_obj, &expires_node);
    if (!expires_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Unable to build 'Expires' child element of timestamp.");
        return AXIS2_FAILURE;
    }
    
    expires_val = rampart_generate_time(env, ttl, with_millisecond);
    axiom_element_set_text(expires_ele, env, expires_val, expires_node);
    AXIS2_FREE(env->allocator, expires_val);
    expires_val = NULL;

    return AXIS2_SUCCESS;
}

/**
 * Validates time stamp token. Validation is based in expiration time of the Expired element.
 * @param env pointer to environment struct
 * @param msg_ctx pointer to message context structure
 * @param ts_node Timestamp node
 * @param clock_skew_buffer buffer of allowable skew of time between sender and receiver
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
*/
axis2_status_t AXIS2_CALL
rampart_timestamp_token_validate(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axiom_node_t *ts_node, 
    int clock_skew_buffer)
{
    axis2_status_t validity = AXIS2_FAILURE;
    axiom_element_t *created_ele = NULL;
    axiom_element_t *expires_ele = NULL;
    axiom_element_t *ts_ele = NULL;
    axiom_node_t *created_node = NULL;
    axiom_node_t *expires_node = NULL;
    axis2_char_t *created_val = NULL;
    axis2_char_t *expires_val = NULL;
    axis2_char_t *current_val = NULL;

    /* Check: TIMESTAMP MUST contain exactly one CREATED */
    if(1 !=  oxs_axiom_get_number_of_children_with_qname(
        env, ts_node, RAMPART_SECURITY_TIMESTAMP_CREATED, RAMPART_WSU_XMLNS, RAMPART_WSU))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Timestamp not valid: Timestamp must contain exactly one Created element");
        return AXIS2_FAILURE;
    }

    /* Check: TIMESTAMP MUST NOT contain more than one EXPIRES */
    if(1 < oxs_axiom_get_number_of_children_with_qname(
        env, ts_node, RAMPART_SECURITY_TIMESTAMP_EXPIRES, RAMPART_WSU_XMLNS, RAMPART_WSU))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,  "[rampart]Timestamp not valid: "
            "Timestamp must not contain more than one Expires element");
        return AXIS2_FAILURE;
    }

    ts_ele = axiom_node_get_data_element(ts_node, env);
    if (!ts_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Timestamp not valid: Cannot find timestamp element.");
        return AXIS2_FAILURE;
    }

    /* First child MUST be the Created element */
    created_node = axiom_node_get_first_element(ts_node, env);
    created_ele = (axiom_element_t*)axiom_node_get_data_element(created_node, env);
    if (axutil_strcmp(RAMPART_SECURITY_TIMESTAMP_CREATED, 
        axiom_element_get_localname(created_ele, env)))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Timestamp not valid: "
            "Cannot find Created element in timestamp element. The first element MUST be CREATED");
        return AXIS2_FAILURE;
    }

    created_val = axiom_element_get_text(created_ele, env, created_node);
    rampart_set_security_processed_result(env, msg_ctx,RAMPART_SPR_TS_CREATED, created_val);

    /* Check whether created is less than current time or not */
    current_val = rampart_generate_time(env, clock_skew_buffer, AXIS2_TRUE);
    validity = rampart_compare_date_time(env, current_val, created_val); 
    if (validity == AXIS2_SUCCESS)
    {
        /* this means current_val < created_val. Which is not a valid case */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Timestamp not valid: Created time is not valid");
        AXIS2_FREE(env->allocator, current_val);
        return AXIS2_FAILURE;
    }

    /* Any TIMESTAMP containing an EXPIRES MUST contain a CREATED that preceeds its sibling 
     * EXPIRES. */
    expires_node =  axiom_node_get_next_sibling(created_node, env);
    if (!expires_node)
    {
        /* If the expire element is not present, it means that the message will not be expired. */
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,"[rampart]Cannot find expires in timestamp element."
            " This is not critical. Assume that the message is not expiring");
        AXIS2_FREE(env->allocator, current_val);
        return AXIS2_SUCCESS;
    }

    expires_ele  = (axiom_element_t*)axiom_node_get_data_element(expires_node, env);
    if (axutil_strcmp(RAMPART_SECURITY_TIMESTAMP_EXPIRES ,
                      axiom_element_get_localname(expires_ele, env)))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Timestamp not valid: "
            "The second element of timestamp token (if any) MUST be EXPIRES");
        AXIS2_FREE(env->allocator, current_val);
        return AXIS2_FAILURE;
    }

    /* Now the expires element is present. So check whether this has a valid timestamp.
     * If not it's a failure */
    expires_val = axiom_element_get_text(expires_ele, env, expires_node);
    rampart_set_security_processed_result(env, msg_ctx,RAMPART_SPR_TS_EXPIRES, expires_val);

    /* Check whether time has expired or not */
    validity = rampart_compare_date_time(env, created_val, expires_val);
    if (validity == AXIS2_FAILURE)
    {
        /* this means created_value > expires_value. Which is not valid */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Timestamp not valid: Timestamp token has expired");
        AXIS2_FREE(env->allocator, current_val);
        return AXIS2_FAILURE;
    }

    validity = rampart_compare_date_time(env, current_val, expires_val);
    AXIS2_FREE(env->allocator, current_val);
    if (validity == AXIS2_FAILURE)
    {
        /* this means current_value > expires_value. Which is not valid */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Timestamp not valid: Timestamp token has expired");
        return AXIS2_FAILURE;
    }

    AXIS2_LOG_INFO(env->log, "[rampart]Timstamp is valid");

    rampart_set_security_processed_result(env, msg_ctx,RAMPART_SPR_TS_CHECKED, RAMPART_YES);
    return AXIS2_SUCCESS;
}
