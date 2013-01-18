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

#ifndef RAMPART_CONTEXT_H
#define RAMPART_CONTEXT_H

/**
  * @file rampart_context.h
  * @brief The Rampart Context, in which configurations are stored
  */

/**
 * @defgroup rampart_context Rampart Context
 * @ingroup rampart_utils
 * @{
 */

#include <rp_includes.h>
#include <rp_secpolicy.h>
#include <rampart_authn_provider.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_callback.h>
#include <rampart_authn_provider.h>
#include <axis2_key_type.h>
#include <axis2_msg_ctx.h>
#include <oxs_key.h>
#include <axutil_array_list.h>
#include <rampart_saml_token.h>
#include <rampart_issued_token.h>
#include <oxs_key_mgr.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_context_t rampart_context_t;

    typedef axis2_char_t *(AXIS2_CALL*
        password_callback_fn)(
        const axutil_env_t *env,
        const axis2_char_t *username,
        void *user_params);

    typedef axis2_status_t (AXIS2_CALL*
        rampart_is_replayed_fn)(
        const axutil_env_t *env,
        axis2_msg_ctx_t* msg_ctx,
        rampart_context_t *rampart_context,
        void *user_params);

    typedef rampart_authn_provider_status_t (AXIS2_CALL*
        auth_password_func)(
        const axutil_env_t* env,
        const axis2_char_t *username,
        const axis2_char_t *password,
        void *ctx);

    typedef rampart_authn_provider_status_t (AXIS2_CALL*
        auth_digest_func)(
        const axutil_env_t* env,
        const axis2_char_t *username,
        const axis2_char_t *nonce,
        const axis2_char_t *created,
        const char *digest,
        void *ctx);

    /* This function will be used to store sct. Global id, local id will be given so function 
     * writer can store them in anyway. Get or Delete method will use any of the Global id or local 
     * id, so Store function writer should be ready for that.
     */
    typedef axis2_status_t (AXIS2_CALL*
        store_security_context_token_fn)(
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_global_id, 
        axis2_char_t *sct_local_id, 
        void *sct, 
        void *user_params);

    /* This function will be called to get previously stored sct. If secure conversation token is 
     * referred by this method, then sct_id will be not null. However, if security context token 
     * (pre-agreed and established offline) is refered then sct_id might be NULL. is_encryption is 
     * passed, so that if pre-agreed sct is different for encryption and signature, then it could be 
     * accessed. sct_id_type will be RAMPART_SCT_ID_TYPE_LOCAL or RAMPART_SCT_ID_TYPE_GLOBAL if 
     * sct_id is NOT NULL. If sct_id is NULL, then sct_id_type will be RAMPART_SCT_ID_TYPE_UNKNOWN
     */
    typedef void* (AXIS2_CALL*
        obtain_security_context_token_fn)(
        const axutil_env_t *env, 
        axis2_bool_t is_encryption, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_id, 
        int sct_id_type,
        void* user_params);

    /* This function will be called to delete previously stored sct. sct_id_type can be 
     * RAMPART_SCT_ID_TYPE_LOCAL or RAMPART_SCT_ID_TYPE_GLOBAL
     */
    typedef axis2_status_t (AXIS2_CALL*
        delete_security_context_token_fn)(
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx, 
        axis2_char_t *sct_id, 
        int sct_id_type,
        void* user_params);

    /* Validates whether security context token is valid or not. Normally, we can directly send 
     * true as response. But if syntax of security context token is altered/added by using 
     * extensible mechanism (e.g having sessions, etc.) then user can implement this method. 
     * Axiom representation of the sct will be given as the parameter, because if sct is 
     * extended, we don't know the syntax. Method writer can implement whatever needed.
     */
    typedef axis2_status_t (AXIS2_CALL*
    validate_security_context_token_fn)(
        const axutil_env_t *env, 
        axiom_node_t *sct_node, 
        axis2_msg_ctx_t *msg_ctx, 
        void *user_params);

	
    /**
    * Create a rampart_context.rampart_context is the wrapper
    * of secpolicy and the main configuration for rampart.
    * @param env pointer to environment struct,Must not be NULL.
    * @return ramaprt_context_t* on successful creation.Else NULL; 
    */

    AXIS2_EXTERN rampart_context_t *AXIS2_CALL
    rampart_context_create(
        const axutil_env_t *env);


    /**
    * Frees a rampart_context.
    * @param rampart_context the rampart_context
    * @env pointer to environment struct,Must not be NULL.
    */

    AXIS2_EXTERN void AXIS2_CALL
    rampart_context_free(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);


    /****************************************************************/

    /**
    * Sets the policy node which is an om_node containing policy.This om_node
    * can be build outside rampart. 
    * @param rampart_context the rampart_context
    * @param env pointer to environment struct,Must not be NULL.
    * @param policy_node is an axiom_node.
    * @returns status of the op.                                                                                                        
    * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
    */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_policy_node(rampart_context_t *rampart_context,
                                    const axutil_env_t *env,
                                    axiom_node_t *policy_node);

    /**
    * Sets private key of sender as a buffer.This can be
    * set from outside rampart.  
    * @param rampart_context the rampart_context
    * @param env pointer to environment struct,Must not be NULL.
    * @param prv_key is a void buffer.
    * @returns status of the op.                                                                                                        
    * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
    */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_prv_key(rampart_context_t *rampart_context,
                                const axutil_env_t *env,
                                void *prv_key);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_prv_key_type(rampart_context_t *rampart_context,
                                     const axutil_env_t *env,
                                     axis2_key_type_t type);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param certificate
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_certificate(rampart_context_t *rampart_context,
                                    const axutil_env_t *env,
                                    void *certificate);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_certificate_type(rampart_context_t *rampart_context,
                                         const axutil_env_t *env,
                                         axis2_key_type_t type);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * @param receiver_certificate
     * returns status of the op.
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_receiver_certificate(rampart_context_t *rampart_context,
            const axutil_env_t *env,
            void *receiver_certificate);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_receiver_certificate_type(rampart_context_t *rampart_context,
            const axutil_env_t *env,
            axis2_key_type_t type);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param user
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_user(rampart_context_t *rampart_context,
                             const axutil_env_t *env,
                             axis2_char_t *user);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param password
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_password(rampart_context_t *rampart_context,
                                 const axutil_env_t *env,
                                 axis2_char_t *password);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param prv_key_password
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_prv_key_password(rampart_context_t *rampart_context,
                                         const axutil_env_t *env,
                                         axis2_char_t *prv_key_password);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param pwcb_function
     * @param ctx
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_pwcb_function(rampart_context_t *rampart_context,
                                      const axutil_env_t *env,
                                      password_callback_fn pwcb_function,
                                      void *user_params);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param is_replayed_function
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_replay_detect_function(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        rampart_is_replayed_fn is_replayed_function,
        void *user_params);
    
    /**
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns user parameters for replay detector function or NULL
     */
    AXIS2_EXTERN void * AXIS2_CALL
    rampart_context_get_rd_user_params(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param password_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_password_type(rampart_context_t *rampart_context,
                                      const axutil_env_t *env,
                                      axis2_char_t *password_type);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param ttl
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_ttl(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        int ttl);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_need_millisecond_precision(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_bool_t need_millisecond_precision);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_clock_skew_buffer(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        int skew_buffer);

    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param rd_val
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_rd_val(rampart_context_t *rampart_context,
                               const axutil_env_t *env,
                               axis2_char_t *rd_val);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param private_key_file
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_private_key_file(rampart_context_t *rampart_context,
                                         const axutil_env_t *env,
                                         axis2_char_t *private_key_file);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param cerficate_file
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_certificate_file(rampart_context_t *rampart_context,
                                         const axutil_env_t *env,
                                         axis2_char_t *certificate_file);
    
	/**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param key
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_add_key(rampart_context_t *rampart_context,
                                const axutil_env_t *env,
                                oxs_key_t *key);

    /**********************************************************8*/

    /*Getters of the above set functions*/
    /**
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    rampart_context_get_policy_node(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void *AXIS2_CALL
    rampart_context_get_prv_key(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
    rampart_context_get_prv_key_type(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void *AXIS2_CALL
    rampart_context_get_certificate(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
    rampart_context_get_certificate_type(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void *AXIS2_CALL
    rampart_context_get_receiver_certificate(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
    rampart_context_get_receiver_certificate_type(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_user(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_password(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_prv_key_password(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN password_callback_fn AXIS2_CALL
    rampart_context_get_pwcb_function(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context     
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rampart_is_replayed_fn AXIS2_CALL
    rampart_context_get_replay_detect_function(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void * AXIS2_CALL
    rampart_context_get_pwcb_user_params(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN int AXIS2_CALL
    rampart_context_get_ttl(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_get_need_millisecond_precision(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    AXIS2_EXTERN int AXIS2_CALL
    rampart_context_get_clock_skew_buffer(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    rampart_context_get_rd_val(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */


    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_password_type(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL
    rampart_context_get_keys(rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param key_id
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN oxs_key_t* AXIS2_CALL
    rampart_context_get_key(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_char_t* key_id);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param hash
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN oxs_key_t* AXIS2_CALL
    rampart_context_get_key_using_hash(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_char_t* hash);

    /*End of Getters */

    /*Rampart specific functions */
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rp_secpolicy_t *AXIS2_CALL
    rampart_context_get_secpolicy(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param secpolicy
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_secpolicy(rampart_context_t *rampart_context,
                                  const axutil_env_t *env,
                                  rp_secpolicy_t *secpolicy);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rampart_callback_t *AXIS2_CALL
    rampart_context_get_password_callback(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_password_callback(rampart_context_t *rampart_context,
                                          const axutil_env_t *env,
                                          rampart_callback_t *password_callback_module);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param password_callback_module
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN auth_password_func AXIS2_CALL
    rampart_context_get_auth_password_function(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param authentication_with_password
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_auth_password_function(rampart_context_t *rampart_context,
            const axutil_env_t *env,
            auth_password_func authenticate_with_password);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN auth_digest_func AXIS2_CALL
    rampart_context_get_auth_digest_function(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param authentication_with_digest
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_auth_digest_function(rampart_context_t *rampart_context,
            const axutil_env_t *env,
            auth_digest_func authenticate_with_digest);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rampart_authn_provider_t *AXIS2_CALL
    rampart_context_get_authn_provider(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void *AXIS2_CALL
    rampart_context_get_replay_detector(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN void *AXIS2_CALL
    rampart_context_get_sct_provider(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param authn_provider
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_authn_provider(rampart_context_t *rampart_context,
       const axutil_env_t *env,
       rampart_authn_provider_t *authn_provider);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param replay_detector
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
	
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	rampart_context_set_replay_detector(rampart_context_t *rampart_context,
       const axutil_env_t *env,
       void *replay_detector);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param sct_module
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
	rampart_context_set_sct_provider(rampart_context_t *rampart_context,
       const axutil_env_t *env,
       void *sct_module);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_get_require_timestamp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_get_require_ut(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rp_property_type_t AXIS2_CALL
    rampart_context_get_binding_type(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_include_timestamp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_include_username_token(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param server_side
     * @param is_inpath
     * @param token_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN axis2_bool_t AXIS2_CALL
	rampart_context_is_include_supporting_token(
		rampart_context_t *rampart_context, const axutil_env_t *env,
		axis2_bool_t server_side, axis2_bool_t is_inpath, 
		rp_property_type_t token_type);
    /**
     *
     * @param rampart_context
     * @param server_side
     * @param is_inpath
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_include_protection_saml_token(
        rampart_context_t *rampart_context, axis2_bool_t server_side, 
        axis2_bool_t is_inpath, const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param token_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN rp_property_t * AXIS2_CALL
	rampart_context_get_supporting_token(
		rampart_context_t *rampart_context,
		const axutil_env_t *env, rp_property_type_t token_type);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_password_callback_class(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_authn_module_name(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_replay_detector_name(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context     
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_sct_provider_name(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_encrypt_before_sign(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_encrypt_signature(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param soap_envelope
     * @param nodes_to_encrypt
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_get_nodes_to_encrypt(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axiom_soap_envelope_t *soap_envelope,
        axutil_array_list_t *nodes_to_encrypt);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param soap_envelope
     * @param nodes_to_sign
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_get_nodes_to_sign(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axiom_soap_envelope_t *soap_envelope,
        axutil_array_list_t *nodes_to_sign);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param soap_envelope
     * @param nodes_to_encrypt
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_get_elements_to_encrypt(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axiom_soap_envelope_t *soap_envelope,
        axutil_array_list_t *nodes_to_encrypt);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param soap_envelope
     * @param nodes_to_sign
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_get_elements_to_sign(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axiom_soap_envelope_t *soap_envelope,
        axutil_array_list_t *nodes_to_sign);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * @param for_encryption
     * @param sever_side
     * @param is_inpath
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rp_property_t *AXIS2_CALL
    rampart_context_get_token(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_bool_t for_encryption,
        axis2_bool_t server_side,
        axis2_bool_t is_inpath);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rp_property_t *AXIS2_CALL
    rampart_context_get_endorsing_token(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param env pointer to environment struct,Must not be NULL.
     * @param token
     * @returns whether derived key needed or not                                                                                                        
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_check_is_derived_keys(
        const axutil_env_t *env,
        rp_property_t *token);

    /**
     * @param env pointer to environment struct,Must not be NULL.
     * @param token
     * @returns derived key version. NULL on error.                                                                                                        
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_derived_key_version(
        const axutil_env_t *env, 
        rp_property_t *token);

    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_enc_sym_algo(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_enc_asym_algo(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_asym_sig_algo(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_sym_sig_algo(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_digest_mtd(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_encryption_user(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param token
     * @param token_type
     * @param server_side
     * @param is_inpath
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_token_include(
        rampart_context_t *rampart_context,
        rp_property_t *token,
        rp_property_type_t token_type,
        axis2_bool_t server_side,
        axis2_bool_t is_inpath,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param token
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_key_identifier(
        rampart_context_t *rampart_context,
        rp_property_t *token,
        const axutil_env_t *env);
    /**
     *
     * @param token_type
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_token_type_supported(
        rp_property_type_t token_type,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param token
     * @param identifier
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_key_identifier_type_supported(
        rampart_context_t *rampart_context,
        rp_property_t *token,
        axis2_char_t *identifier,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_layout(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /** 
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_check_whether_to_encrypt(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_check_whether_to_sign(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_user_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_password_type_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_certificate_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_receiver_certificate_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_private_key_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_ttl_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_clock_skew_buffer_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_need_millisecond_precision_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_rd_val_from_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN oxs_key_t *AXIS2_CALL
    rampart_context_get_encryption_session_key(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param session_key
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_encryption_session_key(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        oxs_key_t *session_key);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN oxs_key_t *AXIS2_CALL
    rampart_context_get_signature_session_key(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param session_key
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_signature_session_key(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        oxs_key_t *session_key);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_increment_ref(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_sig_confirmation_reqd(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_encryption_token_id(
        rampart_context_t *rampart_context,
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_signature_token_id(
        rampart_context_t *rampart_context,
        const axutil_env_t *env, 
        axis2_msg_ctx_t* msg_ctx);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param sct_id
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_encryption_token_id(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_char_t *sct_id, 
        axis2_msg_ctx_t* msg_ctx);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param sct_id
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_signature_token_id(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_char_t *sct_id, 
        axis2_msg_ctx_t* msg_ctx);


    /* Return the saml token of token type set in the rampart context */
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param token_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rampart_saml_token_t * AXIS2_CALL
    rampart_context_get_saml_token(rampart_context_t *rampart_context,
                                        const axutil_env_t *env,
										rampart_st_type_t token_type);

    /* Add a saml token */
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param token
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_add_saml_token(rampart_context_t *rampart_context,
                                    const axutil_env_t *env,
                                    rampart_saml_token_t *token);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param tokens
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

     AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_saml_tokens(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axutil_array_list_t *tokens);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN issued_token_callback_func AXIS2_CALL
    rampart_context_get_issued_token_aquire_function(
        rampart_context_t *rampart_context, 
	const axutil_env_t *env);  
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param issued_token_aquire
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_issued_token_aquire_function(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        issued_token_callback_func issued_token_aquire);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN int AXIS2_CALL
    rampart_context_get_encryption_derived_key_len(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN int AXIS2_CALL
    rampart_context_get_signature_derived_key_len(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    /**
     *
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

    AXIS2_EXTERN rp_algorithmsuite_t *AXIS2_CALL
    rampart_context_get_algorithmsuite(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    
    /**
     * Get the key manager from rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param Pointer to environment struct
     * @returns pointer Key manager struct
     */
    AXIS2_EXTERN oxs_key_mgr_t * AXIS2_CALL
    rampart_context_get_key_mgr(
    	rampart_context_t *rampart_context,
    	const axutil_env_t *env);

    /**
     * Set the key manager to rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param Pointer to environment struct
     * @param key_mgr Pointer to key manager struct.
     * @returns status of the operation. AXIS2_SUCCESS on success AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_key_mgr(
        rampart_context_t *rampart_context, 
	const axutil_env_t *env, 
        oxs_key_mgr_t *key_mgr); 
    
    /**
     * Get the pkcs12 file name from rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param Pointer to environment struct
     * @returns PKCS12 file name
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_pkcs12_file_name(
    	rampart_context_t *rampart_context,
    	const axutil_env_t *env);

    /**
     * Set the a node list to the context. These nodes will be append to
     * the Security header
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @param tokens the token list as an array
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_custom_tokens(rampart_context_t *rampart_context,
                                        const axutil_env_t *env,
                                        axutil_array_list_t *tokens); 

    /**
     * Get the node or the token list as an array. If the size is 0
     * that means there are no custom tokens specified by the client
     * @param rampart_context
     * @param env pointer to environment struct,Must not be NULL.
     * @returns the custom tokens list 
     */
    AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL
    rampart_context_get_custom_tokens(rampart_context_t *rampart_context,
                                        const axutil_env_t *env);

    /**
     * Get the receiver certificate file name from rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns Receiver certificate file name
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_context_get_receiver_certificate_file(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
      
    /**
     * Get the found_cert_in_shp from rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns axis2_bool_t
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_get_found_cert_in_shp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    
    /**
     * Set the certificate found status to rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param found_cert_in_shp boolean value which specify the certificate found status
     * @returns status of the operation
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_found_cert_in_shp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_bool_t found_cert_in_shp);
    
    /**
     * Get the certificate found in shp from rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns oxs_x509_cert_t Client certificate found when processing sec header, otherwise NULL
     */   
    AXIS2_EXTERN oxs_x509_cert_t *AXIS2_CALL
    rampart_context_get_receiver_cert_found_in_shp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);
    
    /**
     * Set the found_cert_in_shp to rampart context.
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param cert pointer to the certficate
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_receiver_cert_found_in_shp(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        oxs_x509_cert_t *cert);

    AXIS2_EXTERN void * AXIS2_CALL
    rampart_context_get_key_store_buff(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_key_store_buff(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        void *key_store_buf,
        int length);

    /**
     * Set the function used to store security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param store_fn funtion pointer used to store sct
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_store_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        store_security_context_token_fn store_fn);

    /**
     * Set the function used to get security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param get_fn funtion pointer used to get stored sct
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_obtain_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        obtain_security_context_token_fn get_fn);

    /**
     * Set the function used to delete security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param delete_fn funtion pointer used to delete stored sct
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_delete_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        delete_security_context_token_fn delete_fn);

    /**
     * Set the user parameters used to invoke security context token related funtions
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param user_params pointer to user params
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_security_context_token_user_params(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        void* user_params);

    /**
     * Set the function used to validate security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param validate_fn funtion pointer used to validate sct
     * @returns status of the operation
     */    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_context_set_validate_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env,
        validate_security_context_token_fn validate_fn);

    /**
     * Get the function used to store security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns untion pointer used to store sct
     */    
    AXIS2_EXTERN store_security_context_token_fn AXIS2_CALL
    rampart_context_get_store_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * Get the function used to get security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns funtion pointer used to get stored sct
     */    
    AXIS2_EXTERN obtain_security_context_token_fn AXIS2_CALL
    rampart_context_get_obtain_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * Get the function used to delete security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns funtion pointer used to delete stored sct
     */    
    AXIS2_EXTERN delete_security_context_token_fn AXIS2_CALL
    rampart_context_get_delete_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * Get the user parameters used to invoke security context token related funtions
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @param user_params pointer to user params
     * @returns pointer to user parameter.
     */    
    AXIS2_EXTERN void* AXIS2_CALL
    rampart_context_get_security_context_token_user_params(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * Get the function used to validate security context token
     * @param rampart_context Pointer to rampart context struct.
     * @param env Pointer to environment struct
     * @returns funtion pointer used to validate sct
     */    
    AXIS2_EXTERN validate_security_context_token_fn AXIS2_CALL
    rampart_context_get_validate_security_context_token_fn(
        rampart_context_t *rampart_context,
        const axutil_env_t *env);

    /**
     * check whether different keys are needed for encryption and signature
     * @param env pointer to environment struct
     * @param rampart_context rampart context
     * @return AXIS2_TRUE if different keys are needed. AXIS2_FALSE otherwise.
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_context_is_different_session_key_for_enc_and_sign(
        const axutil_env_t *env,
        rampart_context_t *rampart_context);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_receiver_certificate_file(
	rampart_context_t *rampart_context,
	const axutil_env_t *env,
	axis2_char_t *receiver_certificate_file);


    
#ifdef __cplusplus
}
#endif
#endif
