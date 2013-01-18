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

#ifndef TRUST_LIFETIME_H
#define TRUST_LIFETIME_H

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <axis2_msg_ctx.h>
#include <axis2_addr.h>

#include <trust_constants.h>
#include <trust_util.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
    typedef struct trust_life_time trust_life_time_t;
    
    AXIS2_EXTERN trust_life_time_t * AXIS2_CALL
    trust_life_time_create(
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_free(
        trust_life_time_t *life_time,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_deserialize(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axiom_node_t *life_time_node);
    
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_life_time_serialize(
        trust_life_time_t *life_time,
        const axutil_env_t *env,
        axiom_node_t *parent);
    
    AXIS2_EXTERN int AXIS2_CALL
    trust_life_time_get_ttl(
        trust_life_time_t *life_time,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_set_ttl(
            trust_life_time_t *life_time,
            const axutil_env_t *env,
            int ttl);        

    AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL
    trust_life_time_get_created(
            trust_life_time_t *life_time,
            const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_set_created(
            trust_life_time_t *life_time,
            const axutil_env_t *env,
            axutil_date_time_t *created);

    AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL
    trust_life_time_get_expires(
            trust_life_time_t *life_time,
            const axutil_env_t *env);


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_set_expires(
            trust_life_time_t *life_time,
            const axutil_env_t *env,
            axutil_date_time_t *expires);


    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_life_time_get_ns_uri(
            trust_life_time_t *life_time,
            const axutil_env_t *env);


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_life_time_set_ns_uri(
            trust_life_time_t *life_time,
            const axutil_env_t *env,
            axis2_char_t *ns_uri);

    
#ifdef __cplusplus
}
#endif
#endif 
