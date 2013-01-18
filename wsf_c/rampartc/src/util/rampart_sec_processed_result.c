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

#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_sec_processed_result.h>

/**
 * Set a security processed result to the message context
 * @param env Environment structure
 * @param msg_ctx message context sttucture
 * @param key key of the security processed result
 * @param value value of the security processed result
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_set_security_processed_result(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_char_t *key,
    void *value)
{
    axutil_hash_t *sec_processed_results = NULL;

    sec_processed_results = rampart_get_all_security_processed_results(env, msg_ctx);
    if(!sec_processed_results)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot retrieve security processed results container.");
        return AXIS2_FAILURE;
    }

    axutil_hash_set(sec_processed_results, key, AXIS2_HASH_KEY_STRING, value);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[rampart]Set %s in Security Processed Results of message context ", key);
    return AXIS2_SUCCESS;
}

/**
 * Get a security processed result from a message context.
 * A service  may use this method to retirieve a particular result by the key
 * @env the environment 
 * @msg_ctx the message context in which data are extracted
 * @key as specified in rampart_constants section SPR
 * @return value of the security processed result corresponding to @key
 */
AXIS2_EXTERN void *AXIS2_CALL
rampart_get_security_processed_result(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_char_t *key)
{
    axutil_hash_t *sec_processed_results = NULL;

    sec_processed_results = rampart_get_all_security_processed_results(env, msg_ctx);
    if(!sec_processed_results)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot retrieve security processed results container.");
        return NULL;
    }
    return axutil_hash_get(sec_processed_results, key, AXIS2_HASH_KEY_STRING);
}

/**
 * Set a security processed result property to the message context
 * @env the environment 
 * @msg_ctx the message context in which data are stored/extracted
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_set_security_processed_results_property(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_hash_t *sec_processed_results = NULL;
    axutil_property_t *sec_processed_results_prop = NULL;

    sec_processed_results = axutil_hash_make(env);
    if(!sec_processed_results)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security processed result hash container creation failed.");
        return AXIS2_FAILURE;
    }

    sec_processed_results_prop = axutil_property_create_with_args(
        env, AXIS2_SCOPE_REQUEST , AXIS2_TRUE, (void *)axutil_hash_free, sec_processed_results);
    if(!sec_processed_results_prop)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security processed result property creation failed.");
        return AXIS2_FAILURE;
    }

    axis2_msg_ctx_set_property(
        msg_ctx, env, RAMPART_SECURITY_PROCESSED_RESULTS, sec_processed_results_prop);

    return AXIS2_SUCCESS;
}

/**
 * Get the complete set of security processed results
 * @env the environment 
 * @msg_ctx the message context in which data are extracted
 * @return complete set of security processed results.
 */
AXIS2_EXTERN axutil_hash_t* AXIS2_CALL
rampart_get_all_security_processed_results(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_property_t *sec_processed_results_prop = NULL;
    axutil_hash_t *sec_processed_results = NULL;

    sec_processed_results_prop =  axis2_msg_ctx_get_property(
        msg_ctx, env, RAMPART_SECURITY_PROCESSED_RESULTS);
    if(!sec_processed_results_prop)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get %s from msg ctx ", RAMPART_SECURITY_PROCESSED_RESULTS);
        return NULL;
    }

    sec_processed_results = (axutil_hash_t*)axutil_property_get_value(
        sec_processed_results_prop, env);
    if(!sec_processed_results)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get Security Processed Results Hash table from the property");
        return NULL;
    }

    return sec_processed_results;
}

/**
 * Prints all ke/val pairs in the security processed results. For debugging purposes
 * @env the environment 
 * @msg_ctx the message context in which data are extracted
 * @return void
 */
AXIS2_EXTERN void AXIS2_CALL
rampart_print_security_processed_results_set(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axutil_hash_t *sec_processed_results = NULL;
    axutil_hash_index_t *hi = NULL;
    const void *key = NULL;
    void *val = NULL;

    sec_processed_results = rampart_get_all_security_processed_results(env, msg_ctx);
    if(!sec_processed_results)
    {
        return;
    }

    for (hi = axutil_hash_first(sec_processed_results, env); hi; hi = axutil_hash_next(env, hi)) 
    {
        axutil_hash_this(hi, &key, NULL, &val);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart](key, val) %s = %s\n", (axis2_char_t*)key, (axis2_char_t*)val);
    }
}
