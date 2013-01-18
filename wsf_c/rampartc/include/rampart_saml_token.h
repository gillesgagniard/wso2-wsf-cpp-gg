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

#ifndef RAMPART_SAML_TOKEN_H
#define RAMPART_SAML_TOKEN_H

#include <rampart_saml_token.h>
#include <oxs_saml_token.h>
#include <axutil_utils.h>
#include <axiom.h>
#include <axis2_msg_ctx.h>
#include <oxs_key.h>
#include <rp_property.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
/*
 * Rampart saml token subject confirmation types. Rampart support both holder 
 * of key and sender vouches methods of subject confiramtions.
 */
typedef enum 
{
    RAMPART_ST_CONFIR_TYPE_UNSPECIFIED = 0,
    RAMPART_ST_CONFIR_TYPE_SENDER_VOUCHES,
    RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY
} rampart_st_confir_type_t;

typedef enum
{
    RAMPART_ST_TYPE_UNSPECIFIED = 0,
    RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN,
    RAMPART_ST_TYPE_SIGNATURE_TOKEN,
    RAMPART_ST_TYPE_ENCRYPTION_TOKEN,
    RAMPART_ST_TYPE_PROTECTION_TOKEN
} rampart_st_type_t;

typedef struct rampart_saml_token_t rampart_saml_token_t;

    /**
     *
     * @param env pointer to environment struct,Must not be NULL.
     * @param assertion
     * @param type
     * returns
     */

AXIS2_EXTERN rampart_saml_token_t *AXIS2_CALL
rampart_saml_token_create(const axutil_env_t *env, axiom_node_t *assertion, 
                          rampart_st_confir_type_t type);
    /**
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */


AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_free(rampart_saml_token_t *tok, const axutil_env_t *env);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param assertion
     * returns
     */

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_assertion(rampart_saml_token_t *tok, const axutil_env_t *env, 
                                 axiom_node_t *assertion);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
rampart_saml_token_get_assertion(rampart_saml_token_t *tok, const axutil_env_t *env);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param assertion
     * returns
     */

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_type(rampart_saml_token_t *tok, const axutil_env_t *env, 
                            rampart_st_confir_type_t type);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */

AXIS2_EXTERN rampart_st_confir_type_t AXIS2_CALL
rampart_saml_token_get_type(rampart_saml_token_t *tok, const axutil_env_t *env);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param key
     * returns
     */

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_key_value(rampart_saml_token_t *tok, const axutil_env_t *env, 
                                 oxs_key_t *key);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
rampart_saml_token_get_str(rampart_saml_token_t *tok, const axutil_env_t *env);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param str
     * returns
     */

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_str(rampart_saml_token_t *tok, const axutil_env_t *env, 
                           axiom_node_t *str);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param is_token_added
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_is_added_to_header(rampart_saml_token_t *tok, 
                                      const axutil_env_t *env,
                                      axis2_bool_t is_token_added);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_saml_token_is_added_to_header(rampart_saml_token_t *tok, 
                                      const axutil_env_t *env);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * @param token_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_token_type(rampart_saml_token_t *tok,
								  const axutil_env_t *env,
								  rampart_st_type_t token_type);
    /**
     *
     * @param tok
     * @param env pointer to environment struct,Must not be NULL.
     * returns
     */

AXIS2_EXTERN rampart_st_type_t AXIS2_CALL
rampart_saml_token_get_token_type(rampart_saml_token_t *tok,
								  const axutil_env_t *env);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_session_key(rampart_saml_token_t *tok, 
								   const axutil_env_t *env,
								   oxs_key_t *key);


AXIS2_EXTERN oxs_key_t * AXIS2_CALL
rampart_saml_token_get_session_key(rampart_saml_token_t *tok, 
								   const axutil_env_t *env);
#ifdef __cplusplus
}
#endif


#endif 


