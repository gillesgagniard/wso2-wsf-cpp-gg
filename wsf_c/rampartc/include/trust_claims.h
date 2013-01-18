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

#ifndef TRUST_CLAIMS_H
#define TRUST_CLAIMS_H

#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <axiom.h>

#include <trust_constants.h>
#include <trust_util.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
    typedef struct trust_claims trust_claims_t;
    
    AXIS2_EXTERN trust_claims_t * AXIS2_CALL
    trust_claims_create(
        const axutil_env_t *env);
    
    AXIS2_EXTERN  axis2_status_t AXIS2_CALL
    trust_claims_free(
        trust_claims_t *claims,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_claims_deserialize(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axiom_node_t *claims_node);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_claims_serialize(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axiom_node_t *parent);
        
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_claims_set_attr_dialect(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axis2_char_t *dialect_attr);

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_claims_get_attr_dialect(
        trust_claims_t *claims,
        const axutil_env_t *env);

    AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
    trust_claims_get_claim_list(
        trust_claims_t *claims,
        const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_claims_set_claim_list(
        trust_claims_t *claims,
		axutil_array_list_t *claims_list,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_claims_set_wst_ns_uri(
        trust_claims_t *claims,
        const axutil_env_t *env,
        axis2_char_t *wst_ns_uri);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_claims_get_wst_ns_uri(
        trust_claims_t *claims,
        const axutil_env_t *env);
        
            
    
#ifdef __cplusplus
}
#endif

#endif /*TRUST_CLAIMS_H*/
