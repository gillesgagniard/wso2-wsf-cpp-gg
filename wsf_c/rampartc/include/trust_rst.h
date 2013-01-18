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

#ifndef TRUST_RST_H
#define TRUST_RST_H

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <trust_constants.h>
#include <trust_entropy.h>
#include <trust_claims.h>
#include <trust_life_time.h>
#include <rp_issued_token.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
   typedef struct trust_rst trust_rst_t;
    
   /* Create RST Context*/
   AXIS2_EXTERN trust_rst_t * AXIS2_CALL
   trust_rst_create(
           const axutil_env_t *env);
    
    /* Populate RST Context from axiom_node*/
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_populate_rst(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *rst_node);
    
    /*Build RST message from the created RST Context */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rst_build_rst(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *parent);

	/*Automated RST building with RelyingParty's policy*/
	AXIS2_EXTERN axiom_node_t * AXIS2_CALL
	trust_rst_build_rst_with_issued_token_assertion(
		trust_rst_t *rst,
		const axutil_env_t *env,
		rp_issued_token_t *issued_token);

    
    /* Getters & Setters */
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_attr_context(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_attr_context(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *attr_context);
    
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_token_type(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_token_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *token_type);
    
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_request_type(
        trust_rst_t *rst,
        const axutil_env_t *env);
 
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_request_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *request_type);
    
	AXIS2_EXTERN axis2_char_t * AXIS2_CALL
	trust_rst_get_wsa_action(
			trust_rst_t *rst,
			const axutil_env_t *env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_rst_set_wsa_action(
			trust_rst_t *rst,
			const axutil_env_t *env,
			axis2_char_t *wsa_action);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_applies_to_addr(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_appliesto(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *applies_to_addr);
    
    
    AXIS2_EXTERN trust_claims_t * AXIS2_CALL
    trust_rst_get_claims(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_claims(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_claims_t *claims);
    
    AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
    trust_rst_get_entropy(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_entropy(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_entropy_t *entropy);
    
    
    AXIS2_EXTERN  trust_life_time_t * AXIS2_CALL
    trust_rst_get_life_time(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_life_time(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_life_time_t *life_time);
    
    
    /*Key and Token Parameter Extensions*/
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_key_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *key_type);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_key_type(
        trust_rst_t *rst,
        const axutil_env_t *env);
        
      
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_key_size(
        trust_rst_t *rst,
        const axutil_env_t *env,
        int key_size);
    
    AXIS2_EXTERN int AXIS2_CALL
    trust_rst_get_key_size(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_authentication_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *authentication_type);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_authentication_type(
        trust_rst_t *rst,
        const axutil_env_t *env);

    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_signature_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *signature_algorithm);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_signature_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_encryption_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *encryption_algorithm);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_encryption_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_canonicalization_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *canonicalization_algorithm);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_canonicalization_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env);

    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_computedkey_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *computedkey_algorithm);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_computedkey_algorithm(
        trust_rst_t *rst,
        const axutil_env_t *env);


   
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_desired_encryption(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *desired_encryption_key);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rst_get_desired_encryption(
        trust_rst_t *rst,
        const axutil_env_t *env);


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_proof_encryption(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *proof_encryption_key);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rst_get_proof_encryption(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_usekey(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *usekey_key);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_rst_get_usekey(
        trust_rst_t *rst,
        const axutil_env_t *env);
    /*FIX Usekey attr @Sig*/


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_signwith(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *signwith);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_signwith(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_encryptwith(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *encryptwith);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_encryptwith(
        trust_rst_t *rst,
        const axutil_env_t *env);
     
    
    /*Trust Version 1 -2005/02 - http://schemas.xmlsoap.org/ws/2005/02/trust */
    /*Trust Version 2 -2005/12 - http://docs.oasis-open.org/ws-sx/ws-trust/200512 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_wst_ns_uri(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_wst_ns_uri(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *wst_ns_uri);
    
    
    
    
    AXIS2_EXTERN void AXIS2_CALL
    trust_rst_free(
        trust_rst_t *rst,
        const axutil_env_t *env);
    
    
#ifdef __cplusplus
}
#endif

#endif 


