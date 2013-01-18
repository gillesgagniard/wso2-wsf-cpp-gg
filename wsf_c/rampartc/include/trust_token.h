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
#ifndef TRUST_TOKEN_H
#define TRUST_TOKEN_H

/**
  * @file trust_token.h
  * @brief Holds function declarations and data for token
  */

#include <axiom.h>
#include <axutil_utils.h>
#include <trust_constants.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* Security token states. */
    typedef enum {
        ISSUED = 1,
        EXPIRED,
        CANCELED,
        RENEWED
    }trust_token_state_t;

    typedef struct trust_token trust_token_t;

    /**
     *Create trust token with given id, token node and life element data
     *@param env		const pointer to axutil environment
     *@param id			Token identifier
     *@param toke_node	Actual token axiom node
     *@param life_node	Life axiom node containing created and expire dates
     *@returns pointer to trust_token_t
     */
    AXIS2_EXTERN trust_token_t* AXIS2_CALL
    trust_token_create(
        const axutil_env_t *env,
        axis2_char_t *id,
        axiom_node_t *token_node,
        axiom_node_t *life_node);

    /**
     *Create trust token with given id, token node, created date and expire date
     *@param env		const pointer to axutil environment
     *@param id			Token identifier
     *@param toke_node	Actual token axiom node
     *@param created	Date which token is created
     *@param expire		Date which token will expire
     *@returns pointer to trust_token_t
     */
    AXIS2_EXTERN trust_token_t* AXIS2_CALL 
    trust_token_create_with_dates(
        const axutil_env_t *env,
        axis2_char_t *id,
        axiom_node_t *token_node,
        axutil_date_time_t *created,
        axutil_date_time_t *expire);

    /**
     *Process the life element of the token which represent by the following xml format
     *assign values to related fields.
     *<wst:LifeTime>
     *	<wsu:Created>...</wsu:Created>
     *	<wsu:Expires>...</wsu:Expires>
     *</wst:LifeTime>
     *@param env		const pointer to axutil environment
     *@param life_node	Axiom node containing created and expire dates
     *@param token		Trust token containing token data
     *@returns status of the life element processing
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_process_life_elem(
        const axutil_env_t *env,
        axiom_node_t *life_node,
        trust_token_t *token);

    /**
     *Get the change status of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axis2_bool_t whether the token is changed or not
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL 
    trust_token_is_changed(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the change status of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param changed	Bollean value representing the if token is changed	
     *@returns axis2_status_t whether the operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_changed(
        const axutil_env_t *env,
        trust_token_t *token,
        axis2_bool_t changed);

    /**
     *Get the state of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns trust_token_state_t token's state can be ISSUED, EXPIRED, CANCELLED, RENEWED
     */
    AXIS2_EXTERN trust_token_state_t AXIS2_CALL 
    trust_token_get_state(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the state of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param state		State of the trust token
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_state(
        const axutil_env_t *env,
        trust_token_t *token,
        trust_token_state_t state);

    /**
     *Get the actual token om node of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axiom_node_t axiom node pointer for token
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
    trust_token_get_token(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the actual token om node of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param token_node axiom node pointer for token
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_token(
        const axutil_env_t *env,
        trust_token_t *token,
        axiom_node_t *token_node);

    /**
     *Get the identifier of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axis2_char_t identifier string of token
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
    trust_token_get_id(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Get the actual previous token om node of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axiom_node_t axiom node pointer for previous token
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    trust_token_get_previous_token(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the actual token om node of trust token's previous token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param prev_token axiom node pointer for previous token
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_previous_token(
        const axutil_env_t *env,
        trust_token_t *token,
        axiom_node_t *prev_token);

    /* **
     * @return Returns the secret.

     public byte[] getSecret() {
     return secret;
     } */

     /**
     * @param secret The secret to set.

     public void setSecret(byte[] secret) {
     this.secret = secret;
     }*/

    /**
     *Get the attached reference of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axiom_node_t axiom node pointer for attached reference
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
    trust_token_get_attached_reference(
        const axutil_env_t *env, 
        trust_token_t *token);

    /**
     *Set the attached reference of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param attached_reference axiom node pointer for attached reference
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_attached_reference(
        const axutil_env_t *env,
        trust_token_t *token,
        axiom_node_t *attached_reference);

    /**
     *Get the unattached reference of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axiom_node_t axiom node pointer for unattached reference
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
    trust_token_get_unattached_reference(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the unattached reference of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param attached_reference axiom node pointer for unattached reference
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_unattached_reference(
        const axutil_env_t *env,
        trust_token_t *token,
        axiom_node_t *unattached_reference);

    /**
     *Get the created date of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axutil_date_time_t ceated date
     */
    AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
    trust_token_get_created(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the created date of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param created	date which token is created
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_created(
        const axutil_env_t *env,
        trust_token_t *token,
        axutil_date_time_t *created);

    /**
     *Get the expire date of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axutil_date_time_t expire date
     */
    AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
    trust_token_get_expires(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the expire date of trust token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param expire		Expire date of token
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_set_expires(
        const axutil_env_t *env,
        trust_token_t *token,
        axutil_date_time_t *expire);

    /**
     *Get the issuer's address of token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@returns axis2_char_t* issuer's address
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
    trust_token_get_issuer_address(
        const axutil_env_t *env,
        trust_token_t *token);

    /**
     *Set the issuer's address of token
     *@param env		const pointer to axutil environment
     *@param token		Trust token structure
     *@param issuer_address issure's address string
     *@returns axis2_status_t whether the set operation is successful or not
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_token_set_issuer_address(
        const axutil_env_t *env,
        trust_token_t *token,
        axis2_char_t *issuer_address);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL 
    trust_token_process_life_elem(
        const axutil_env_t *env,
        axiom_node_t *life_node,
        trust_token_t *token);
	

#ifdef __cplusplus
}
#endif

#endif   /*TRUST_TOKEN_H*/

