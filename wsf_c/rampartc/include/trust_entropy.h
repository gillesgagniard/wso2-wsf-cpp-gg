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

#ifndef TRUST_ENTROPY_H
#define	TRUST_ENTROPY_H

#include <axutil_utils.h>
#include <axutil_string.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <trust_constants.h>
#include <trust_util.h>


#ifdef	__cplusplus
extern "C"
{
#endif
    
    #define BIN_SEC_ASSYM   "/AsymmetricKey"
    #define BIN_SEC_SYM     "/SymmetricKey"
    #define BIN_SEC_NONCE   "/Nonce"    

    typedef enum
    {
        BIN_SEC_TYPE_ERROR = -1,
        ASYMMETRIC ,
        SYMMETRIC,
        NONCE
    }trust_bin_sec_type_t;

    typedef struct trust_entropy trust_entropy_t;

    #define TRUST_BIN_SEC_TYPE_ATTR "Type"
            
    AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
    trust_entropy_create(
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_free(
        trust_entropy_t *entropy,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_deserialize(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *entropy_node);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_entropy_serialize(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *parent);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_entropy_get_binary_secret(
        trust_entropy_t *entropy,
        const axutil_env_t *env);

	AXIS2_EXTERN trust_bin_sec_type_t AXIS2_CALL
	trust_entropy_get_bin_sec_type_from_str(
        axis2_char_t *str,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
        trust_entropy_get_str_for_bin_sec_type(
        trust_bin_sec_type_t type,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_set_binary_secret(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axis2_char_t *bin_sec);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_entropy_get_other(
        trust_entropy_t *entropy,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_set_other(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axiom_node_t *other_node);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_entropy_get_ns_uri(
        trust_entropy_t *entropy,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_set_ns_uri(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        axis2_char_t *ns_uri);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_entropy_set_binary_secret_type(
        trust_entropy_t *entropy,
        const axutil_env_t *env,
        trust_bin_sec_type_t binsec_type);

#ifdef	__cplusplus
}
#endif

#endif                          /* _TRUST_ENTROPY_H */
