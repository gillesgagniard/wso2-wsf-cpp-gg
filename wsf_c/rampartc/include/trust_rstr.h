
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

#ifndef TRUST_RSTR_H
#define TRUST_RSTR_H

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <trust_constants.h>
#include <trust_entropy.h>
#include <trust_life_time.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
    typedef struct trust_rstr trust_rstr_t;
    
    AXIS2_EXTERN trust_rstr_t * AXIS2_CALL
    trust_rstr_create(
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_free(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_populate_rstr(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *rstr_node);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rstr_build_rstr(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *parent);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rstr_get_token_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_token_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *token_type);
    
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rstr_get_request_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_request_type(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *request_type);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rstr_get_requested_security_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_requested_security_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *security_token);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rstr_get_applies_to(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_applies_to(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *applies_to);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rstr_get_requested_attached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_requested_attached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *ref_node);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rstr_get_requested_unattached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_requested_unattached_reference(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *ref_node);
    
    AXIS2_EXTERN  axiom_node_t * AXIS2_CALL
    trust_rstr_get_requested_proof_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_requested_proof_token(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axiom_node_t *proof_token);
    
    AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
    trust_rstr_get_entropy(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN  axis2_status_t AXIS2_CALL
    trust_rstr_set_entropy(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        trust_entropy_t *entropy);
    
    AXIS2_EXTERN trust_life_time_t* AXIS2_CALL
    trust_rstr_get_life_time(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_life_time(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        trust_life_time_t *life_time);
    
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    trust_rstr_get_in_header(
        trust_rstr_t *rstr,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rstr_set_in_header(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_bool_t in_header); 
	
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
        trust_rstr_set_wst_ns_uri(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        axis2_char_t *wst_ns_uri);

    AXIS2_EXTERN int AXIS2_CALL
    trust_rstr_get_key_size(
        trust_rstr_t *rstr,
        const axutil_env_t *env);

    AXIS2_EXTERN  axis2_status_t AXIS2_CALL
    trust_rstr_set_key_size(
        trust_rstr_t *rstr,
        const axutil_env_t *env,
        int key_size);

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rstr_get_wst_ns_uri(
	    trust_rstr_t *rstr,
	    const axutil_env_t *env);    
     

#ifdef __cplusplus
}
#endif

#endif
