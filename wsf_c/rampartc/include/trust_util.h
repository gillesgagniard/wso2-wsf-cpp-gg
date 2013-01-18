
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

#ifndef TRUST_UTIL
#define TRUST_UTIL

/**
* @file trust_util.h
* @brief contains generic operations related to trust module
*/

#include <stdio.h>
#include <stdlib.h>
#include <axiom.h>
#include <axutil_utils.h>
#include <axutil_string.h>

#include <trust_constants.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        TRUST_ALLOW = 0,
        TRUST_NOT_ALLOW
    } trust_allow_t;

    typedef enum
    {
        TRUST_OK = 0,
        TRUST_NOT_OK
    } trust_ok_t;

    /**
     * Create the RST Element for Issuance binding.
     * <wst:RequestSecurityToken>
     *      ...
     *      ...
     * </wst:RequestSecurityToken>
     * @param env   pointer to environment struct
     * @param wst_verson integer representing wst version
     * @param context   string representing contest of the request, can be NULL
     * @returns  RST axiom node, NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_rst_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axis2_char_t * context);

    /**
     * Create the RSTR Element for Issuance binding.
     * <wst:RequestSecurityTokenResponse>
     *      ...
     *      ...
     * </wst:RequestSecurityTokenResponse>
     * @param env   pointer to environment struct
     * @param wst_verson integer representing wst version
     * @param context   string representing contest of the request, can be NULL
     * @returns  RSTR axiom node, NULL if error ocurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_rstr_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axis2_char_t * context);

    /**
    * Create the RSTRC Element for Issuance binding.
    * <wst:RequestSecurityTokenResponseCollection>
    *      ...
    *      ...
    * </wst:RequestSecurityTokenResponseCollection>
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @returns  RSTRC axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_rstr_collection_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri);

    /**
    * Create the RequestType Element for Issuance binding.
    * <wst:RequestType> .... </wst:RequestType>
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @param parent_node parent axiom node
    * @param request_type string representing request type
    * @returns  RequestType axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_request_type_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * request_type);

    /**
    * Create the TokenType Element for Issuance binding.
    * <wst:TokenType> .... </wst:TokenType>
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @param parent_node parent axiom node
    * @param token_type string representing token type
    * @returns  TokenType axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_token_type_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * token_type);

    /**
     * Create the AppliesTo Element for Issuance binding.
     * AppliesTo element Specifies the scope for which the security token is desired.
     * Same as TokenType. AppliesTo is higher in precedence than TokenType
     * <wsp:AppliesTo>
     *      <wsa:EndpointReference>
     *          <wsa:Address> ... </wsa:Address>
     *      </wsa:EndpointReference>
     * </wsp:AppliesTo>
     * @param env   pointer to environment struct
     * @param wst_verson integer representing wst version
     * @param parent_node parent axiom node
     * @param token_type string representing token type
     * @returns  TokenType axiom node, NULL if error ocurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_applies_to_element(
        const axutil_env_t * env,
        axiom_node_t * parent_node,
        const axis2_char_t * address,
        const axis2_char_t * addressing_ns);

    /**
     *Claims	:Requests a set of specific claims. These claims are identified by using the
     *			 service's policy
     *@Dialect	:URI to indicate the syntax of the claims
    **/

    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_util_create_claims_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * dialect_uri);

    /**
    * Create the RequestedSecurityToken Element for Issuance binding.
    * <wst:RequestedSecurityToken> .... </wst:RequestedSecurityToken>
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @param parent_node parent axiom node
    * @returns  RequestedSecurityToken axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_requested_security_token_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * sec_token_node);


    /**
    * Create the RequestedProofToken Element for Issuance binding.
    * <wst:RequestedProofToken> .... </wst:RequestedProofToken>
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @param parent_node parent axiom node
    * @returns  RequestedSecurityToken axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_requsted_proof_token_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t *req_proof_token);

    /**
     * Create the Entropy Element for Issuance binding. User must set the content.
     * <wst:Entropy> .... </wst:Entropy>
     * Entropy element specifies the entropy that is to be used for creating the key
     * according to the service's policy.
     * @param env   pointer to environment struct
     * @param wst_verson integer representing wst version
     * @param parent_node parent axiom node
     * @returns  Entropy axiom node, NULL if error ocurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_entropy_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node);

    /**
    * Create the ComputedKey Element for Issuance binding.
    * <wst:ComputedKey> .... </wst:ComputedKey>
    * User must set the inside content for this node.
    * @param env   pointer to environment struct
    * @param wst_verson integer representing wst version
    * @param parent_node parent axiom node
    * @returns  RequestedSecurityToken axiom node, NULL if error ocurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_computed_key_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node);

    /**
      * Create BinarySecret element. This contains base64 encoded binary secret or key.
      * And also contain @Type attribute.
      * @param env pointer to environment struct
      * @param wst_version integer representing wst version
      * @param parent_node pointer to parent axiom node
      * @param enc_secret string representing encoded secret
      * @param bin_sec_type Type of the binary secret
      * @returns BinarySecret element or NULL if error occurred.
      */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_binary_secret_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * enc_secret,
        axis2_char_t * bin_sec_type);

    /**
     * Create ComputedKeyAlgorithm element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param algo_id Algorithm identifier
     * @returns ComputedKeyAlgorithm element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_computed_key_algo_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * algo_id);

    /**
      * Create KeySize element.
      * @param env pointer to environment struct
      * @param wst_version integer representing wst version
      * @param parent_node pointer to parent axiom node
      * @param key_size Key size string
      * @returns KeySize element or NULL if error occurred.
      */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_key_size_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * key_size);

    /**
      * Create KeyType element.
      * @param env pointer to environment struct
      * @param wst_version integer representing wst version
      * @param parent_node pointer to parent axiom node
      * @param key_type Key type string
      * @returns KeySize element or NULL if error occurred.
      */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_key_type_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * key_type);

    
    /*AuthenticationType*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_authentication_type_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * authentication_type);

   /*SignatureAlgorithm*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_signature_algo_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * signature_algo);
    
    /*EncryptionAlgorithm*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_encryption_algo_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * encryption_algo);
        
    /*CanonicalizationAlgorithm*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_canonicalization_algo_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * canonicalization_algo);

    /*ComputedKeyAlgorithm*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_computedkey_algo_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * computedkey_algo);
    
   /*(Desired)Encryption*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_desired_encryption_element(
        const axutil_env_t * env,
        axis2_char_t * wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * encryption_key); /*@param encryption_key - This can be either a key or a STR*/
   
   /*ProofEncryption*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_proof_encryption_element(
        const axutil_env_t * env,
        axis2_char_t * wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * proof_encryption_key); /*@param encryption_key - This can be either a key or a STR*/

    /*UseKey*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_usekey_element(
        const axutil_env_t * env,
        axis2_char_t * wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * usekey_key); /*@param encryption_key - This can be either a key or a STR*/

   /*SignWith*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_signwith_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * signwith);
       
   /*EncryptWith*/
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_encryptwith_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axis2_char_t * encryptwith);
 
    /**
     * Create LifeTime element.
     *
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @returns LifeTime element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_life_time_element(
        const axutil_env_t * env,
        axiom_node_t * parent_node,
        axis2_char_t *wst_ns_uri,
        int ttl);

    /**
     * Create RequestedAttachedReference element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @returns RequestedAttachedReference element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_req_attached_reference_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node);

    /**
     * Create RequestedUnAttachedReference element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @returns RequestedUnAttachedReference element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_req_unattached_reference_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node);

    /**
     * Create EncryptedData element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param enc_data encrypted data string
     * @returns EncryptedData element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_encrypted_data_element(
        const axutil_env_t * env,
        axiom_node_t * parent_node,
        axis2_char_t * enc_data);

    /**
     * Create RenewTarget element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param token_renew_pending_node
     * @returns RenewTarget element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_renew_traget_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * token_renew_pending_node);

    /**
    * Create AllowPostdating element.
    * @param env pointer to environment struct
    * @param wst_version integer representing wst version
    * @param parent_node pointer to parent axiom node
    * @returns AllowPostdating element or NULL if error occurred.
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_allow_postdating_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node);

    /**
     * Create Renewing element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param allow_flag
     * @param ok_flag
     * @returns Renewing element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_renewing_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        trust_allow_t allow_flag,
        trust_ok_t ok_flag);

    /**
     * Create CancelTarget element.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param token_cancel_pending_node
     * @returns CancelTarget element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_cancel_target_element(
        const axutil_env_t * env,
        axis2_char_t *wst_ns_uri,
        axiom_node_t * parent_node,
        axiom_node_t * token_cancel_pending_node);

    /**
     * Create Status element for validation response.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @param parent_node pointer to parent axiom node
     * @param token_cancel_pending_node
     * @returns Status element or NULL if error occurred.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_util_create_validation_response_element(
        const axutil_env_t * env,
        axiom_node_t * parent_node,
        axis2_char_t *wst_ns_uri,
        axis2_char_t * code,
        axis2_char_t * reason);

	/* Generate random se*/
	AXIS2_EXTERN axiom_node_t * AXIS2_CALL
	trust_util_create_random_session_key_proof_token_element(
		const axutil_env_t * env,
		axis2_char_t *wst_ns_uri);

    /**
     * Returns the namespace uri of WST according to the version.
     * @param env pointer to environment struct
     * @param wst_version integer representing wst version
     * @returns namespace uri according to version.
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_util_get_wst_ns(
        const axutil_env_t * env,
        int wst_version);

#ifdef __cplusplus
}
#endif
#endif                          /*TRUST_UTIL_H */
