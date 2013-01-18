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

#ifndef RAMPART_SCT_PROVIDER_UTILITY_H
#define RAMPART_SCT_PROVIDER_UTILITY_H

/**
  * @file rampart_sct_provider_utility.h
  * @brief Utility methods using Security context token provider module
  */

/**
* @defgroup sct_provider Security Context Token provider
* @ingroup rampart_utils
* @{
*/

#include <axis2_defines.h>
#include <axutil_env.h>
#include <axis2_msg_ctx.h>
#include <axis2_conf_ctx.h>
#include <rampart_context.h>
#include <secconv_security_context_token.h>
#include <axutil_hash.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Finds security context token and gets shared secret. 
     * returned buffer should NOT be cleared by the caller
     * @param env Pointer to environment struct
     * @param token rampart policy property of the token
     * @param is_encryption boolean showing whether the token is needed for encryption or signature
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns shared secret of the security context token. returned buffer should NOT be freed
     */    
    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
    sct_provider_get_secret(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /**
     * Finds security context token and gets shared secret. 
     * returned buffer should NOT be cleared by the caller
     * @param env Pointer to environment struct
     * @param sct_id id of security context token
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns shared secret of the security context token. returned buffer should NOT be freed
     */    
    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
        sct_provider_get_secret_using_id(
        const axutil_env_t* env, 
        axis2_char_t* sct_id, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /**
     * Finds security context token and gets the xml representation of token
     * @param env Pointer to environment struct
     * @param token rampart policy property of the token
     * @param is_encryption boolean showing whether the token is needed for encryption or signature
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns shared secret of the security context token. returned buffer should NOT be freed
     */    
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    sct_provider_get_token(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /**
     * Finds security context token and gets the xml representation of key reference. This reference
     * is used when security context token is included in the message
     * @param env Pointer to environment struct
     * @param token rampart policy property of the token
     * @param is_encryption boolean showing whether the token is needed for encryption or signature
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns shared secret of the security context token. returned buffer should NOT be freed
     */    
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    sct_provider_get_attached_reference(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /**
     * Finds security context token and gets the xml representation of key reference. This reference
     * is used when security context token is NOT included in the message
     * @param env Pointer to environment struct
     * @param token rampart policy property of the token
     * @param is_encryption boolean showing whether the token is needed for encryption or signature
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns shared secret of the security context token. returned buffer should NOT be freed
     */    
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    sct_provider_get_unattached_reference(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /** 
     * Validates whether security context token is valid or not. Normally, we can directly send 
     * true as response. But if syntax of security context token is altered/added by using 
     * extensible mechanism (e.g having sessions, etc.) then user can implement this method. 
     * Axiom representation of the sct will be given as the parameter, because if sct is extended, 
     * we don't know the syntax. Method writer can implement whatever needed.
     * @param env Pointer to environment struct
     * @param sct_node axiom node representation of security context token.
     * @param rampart_context pointer to rampart context structure
     * @param msg_ctx pointer to message context structure
     * @returns AXIS2_TRUE is sct is valid. AXIS2_FALSE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    sct_provider_validate_security_context_token(
        const axutil_env_t *env, 
        axiom_node_t *sct_node, 
        rampart_context_t *rampart_context, 
        axis2_msg_ctx_t *msg_ctx);

    /** 
     * Default implementation of obtain sct function. If neither sct_provider nor user defined 
     * obtain function is given, this function will be used. (obtain_security_context_token_fn)
     * @param env pointer to environment struct
     * @param is_encryption boolean denotes sct is needed for encryption or signature
     * @param msg_ctx pointer to message context structure
     * @param sct_id identifier of security context token. Can be NULL
     * @param sct_id_type type of sct id. can be global, local or unknown
     * @param user_params parameter provided by user (not used in this method)
     * return security context token if found. NULL otherwise.
     */
    AXIS2_EXTERN void* AXIS2_CALL
    sct_provider_obtain_sct_default(
        const axutil_env_t *env, 
        axis2_bool_t is_encryption, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_id, 
        int sct_id_type,
        void* user_params);

    /**
     * Default implementation of store sct function. If neither sct_provider nor user defined 
     * store function is given, this function will be used. (store_security_context_token_fn)
     * @param env pointer to environment struct
     * @param msg_ctx pointer to message context structure
     * @param sct_global_id global identifier of security context token. Can be NULL
     * @param sct_local_id local identifier of security context token. Can be NULL
     * @param sct security context token to be stored
     * @param user_params parameter provided by user (not used in this method)
     * return AXIS2_SUCCESS if stored. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    sct_provider_store_sct_default(
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_global_id, 
        axis2_char_t *sct_local_id, 
        void *sct, 
        void *user_params);

    /**
     * Default implementation of delete sct function. If neither sct_provider nor user defined 
     * store function is given, this function will be used. (delete_security_context_token_fn)
     * @param env pointer to environment struct
     * @param msg_ctx pointer to message context structure
     * @param sct_id identifier of security context token. Should not be NULL.
     * @param sct_id_type type of sct id. can be global or local.
     * @param user_params parameter provided by user (not used in this method)
     * @return AXIS2_SUCCESS if deleted. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    sct_provider_delete_sct_default(
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_id, 
        int sct_id_type,
        void* user_params);

    /**
     * Default implementation of validate sct function. If neither sct_provider nor user defined 
     * store function is given, this function will be used. (validate_security_context_token_fn)
     * @param env pointer to environment struct
     * @param sct_node axiom representation of security context token
     * @param user_params parameter provided by user (not used in this method)
     * @return AXIS2_SUCCESS if valid. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    sct_provider_validate_sct_default(
        const axutil_env_t *env, 
        axiom_node_t *sct_node, 
        axis2_msg_ctx_t *msg_ctx,
        void *user_params);


    /** @} */
#ifdef __cplusplus
}
#endif

#endif  /* RAMPART_SCT_PROVIDER_UTILITY_H */


