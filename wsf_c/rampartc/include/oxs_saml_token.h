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

#ifndef OXS_SAML_TOKEN_H
#define OXS_SAML_TOKEN_H

#include <oxs_tokens.h>
#include <oxs_axiom.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* TODO OXS_ST_KEY_ID_VALUE_TYPE looks odd. Rename it properly */
#define OXS_ST_KEY_ID_VALUE_TYPE    "http://docs.oasis-open.org/wss/oass-wss-saml-token-profile-1.0#SAMLAssertionID"

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_key_identifier_reference_local(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion);
AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_key_identifier_reference_remote(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion, 
                                             axiom_node_t *auth_bind);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_embeded_reference(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_get_from_key_identifer_reference(const axutil_env_t *env, 
                                                    axiom_node_t *key_id,
                                                    axiom_node_t *scope);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_get_from_embeded_reference(const axutil_env_t *env, 
                                                  axiom_node_t *embeded);


#ifdef __cplusplus
}
#endif


#endif 

