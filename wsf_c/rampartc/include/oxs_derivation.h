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

#ifndef OXS_DERIVATION_H
#define OXS_DERIVATION_H


/**
  * @file oxs_derivation.h
  * @brief The Key derivation module for OMXMLSecurity 
  */

/**
* @defgroup oxs_derivation Derivation
* @ingroup oxs
* @{
*/
#include <axis2_defines.h>
#include <axutil_env.h>
#include <oxs_key.h>
#include <oxs_buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif


    /**
     * Derive Key depending on the secret key @secret 
     * Caller must free memory for derived key
     * @param env pointer to environment struct
     * @param secret The secret is the shared secret that is exchanged (note that if two secrets 
     * were securely exchanged, possible as part of an initial exchange, they are concatenated in 
     * the order they were sent/received)
     * @param derived_key The derived key. Caller must create and free
	 * @param build_fresh Whether to build fresh or build using details in derived key
     * (in case of recovering the derive key from xml)
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     *
     **/
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_derivation_derive_key(
        const axutil_env_t *env,
        oxs_key_t *secret,
        oxs_key_t *derived_key,
        axis2_bool_t build_fresh);

    /**
     * Build the <wsc:DerivedKeyToken> depending a given derived key @derived_key
     * The token will be attached to the parent @parent
     * @param env pointer to environment struct
     * @param derived_key The derived key to be used to get information
     * @param parent The parent node to be attached to
     * @param stref_uri Security Token Reference URI
     * @param stref_val_type Security Token Reference Valut Type
     * @param wsc_ns_uri namespace uri of ws-secconv version
     * @return the built axiom node
     */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_derivation_build_derived_key_token(
        const axutil_env_t *env,
        oxs_key_t *derived_key,
        axiom_node_t *parent,
        axis2_char_t *stref_uri,
        axis2_char_t *stref_val_type, 
        axis2_char_t *wsc_ns_uri);

    /**
     * Build the <wsc:DerivedKeyToken> depending a given derived key @derived_key
     * The token will be attached to the parent @parent
     * @param env pointer to environment struct
     * @param derived_key The derived key to be used to get information
     * @param parent The parent node to be attached to
     * @param stre Security Toekn Reference element
     * @param wsc_ns_uri namespace uri of ws-secconv version
     * @return the built axiom node
     */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_derivation_build_derived_key_token_with_stre(
        const axutil_env_t *env,
        oxs_key_t *derived_key,
        axiom_node_t *parent,    
        axiom_node_t *stre,
        axis2_char_t *wsc_ns_uri);

    /**
     * Extract information from an AXIOM node of typ <wsse:DerivedKeyToken> and build a key
     * If the (optional) session_key is NULL then extract it form the refered EncryptedKey. 
     * Otherwise use it to Derive a new key using information available in the dk_token.
     * @param env pointer to environment struct
     * @param dk_token The <wsse:DerivedKeyToken> axiom node
     * @param root_node The root node, which the search scope limited to
     * @param session_key The session key, which is the base for the key derivation.
     * @param return the derived key on SUCCESS or NULL on failure
     * */
    AXIS2_EXTERN oxs_key_t * AXIS2_CALL
    oxs_derivation_extract_derived_key_from_token(
        const axutil_env_t *env,
        axiom_node_t *dk_token,
        axiom_node_t *root_node,
        oxs_key_t *session_key);

    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* OXS_DERIVATION_H */
