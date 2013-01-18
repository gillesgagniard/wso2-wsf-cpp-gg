
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

#ifndef SECCONV_SECURITY_CONTEXT_TOKEN_H
#define SECCONV_SECURITY_CONTEXT_TOKEN_H

/**
  * @file secconv_security_context_token.h
  * @brief security context token
  */

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <oxs_buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct security_context_token_t security_context_token_t;

    /**
     * Creates security context token 
     * @param env Pointer to environment struct
     * @returns Security context token if success. NULL otherwise.
     */
    AXIS2_EXTERN security_context_token_t *AXIS2_CALL
    security_context_token_create(
        const axutil_env_t * env);

    /**
     * Free security context token 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_free(
        security_context_token_t *sct, 
        const axutil_env_t *env);

    /**
     * Get shared secret from security context token. Callers should not free returned buffer
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns shared secret if success. NULL otherwise.
     */
    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
    security_context_token_get_secret(
        security_context_token_t * sct, 
        const axutil_env_t * env);

    /**
     * Get global id of security context token. 
     * This id will be used when token is not included in the message
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns global id if success. NULL otherwise.
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    security_context_token_get_global_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env);
    
    /**
     * Get local id of security context token. 
     * This id will be used when token is included in the message
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns local id if success. NULL otherwise.
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    security_context_token_get_local_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env);

    /**
     * Set shared secret of security context token. After this method is called, ownership of 
     * the buffer will be with security context token. Users should not free it.
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param buffer Pointer to shared secret
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_secret(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        oxs_buffer_t *buffer);

    /**
     * Set global identifier of security context token. After this method is called, ownership of 
     * global_id will be with security context token. Users should not free it.
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param global_id Global identifier of security context token
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_global_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        axis2_char_t *global_id);
    
    /**
     * Set local identifier of security context token. After this method is called, ownership of 
     * local_id will be with security context token. Users should not free it.
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param local_id Local identifier of security context token
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_local_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        axis2_char_t *local_id);

    /**
     * Set WS-SecureConversation version 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param is_sc10 Boolean denoting whether we need security context token as in WS-SecConv 1.0
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_is_sc10(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axis2_bool_t is_sc10);

    /**
     * Get shared secret as axiom_node. Shared secret will be included inside 
     * 'RequestedProofToken' node. This is acording to WS-Trust specification 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns valid axiom_node if success. NULL otherwise.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_requested_proof_token(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    /**
     * Get local id of security context token as axiom node. 
     * This id will be used when token is included in the message
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns valid axiom node if success. NULL otherwise.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_attached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    /**
     * Get global id of security context token as axiom node. 
     * This id will be used when token is not included in the message
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns valid axiom node if success. NULL otherwise.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_unattached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    /**
     * Get axiom node representation of security context token. 
     * This will be included in the message if the token needs to be sent in the message
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns valid axiom node if success. NULL otherwise.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_token(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    /**
     * Set shared secret of security context token from proof token. This proof token will be given
     * by STS.
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param node Pointer to proof token axiom node
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_requested_proof_token(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    /**
     * Set local identifier of security context token from attached reference node. 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param node Pointer to attached reference axiom node
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_attached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    /**
     * Set global identifier of security context token from unattached reference node. 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param node Pointer to unattached reference axiom node
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_unattached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    /**
     * Set axiom representation of security context token
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param node Pointer to security context token axiom node
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_token(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    /**
     * Increment the reference of security context token
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns AXIS2_SUCCESS if success. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_increment_ref(
        security_context_token_t *sct,
        const axutil_env_t * env);

    /**
     * Serializes the security context token. Caller should take the ownership of returned value
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @returns serialized security context token if success. NULL otherwise
     */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    security_context_token_serialize(
        security_context_token_t *sct, 
        const axutil_env_t *env);

    /**
     * Deserializes the security context token. 
     * @param sct Pointer to secuirty context token struct
     * @param env Pointer to environment struct
     * @param serialised_node serialised string representation of security context token
     * @returns serialized security context token if success. NULL otherwise
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_deserialize(
        security_context_token_t *sct, 
        const axutil_env_t *env, 
        axis2_char_t *serialised_node);
   
#ifdef __cplusplus
}
#endif
#endif                          /*SECCONV_SECURITY_CONTEXT_TOKEN_H */
