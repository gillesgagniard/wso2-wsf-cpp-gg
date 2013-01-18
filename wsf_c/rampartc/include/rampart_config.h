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

#ifndef RAMPART_CONFIG_H
#define RAMPART_CONFIG_H

/**
  * @file rampart_config.h
  * @brief The Rampart Config, in which user configurations are stored
  */

/**
 * @defgroup rampart_config Rampart Config
 * @ingroup rampart_utils
 * @{
 */

#include <axis2_util.h>
#include <axis2_defines.h>
/*#include <axutil_utils_defines.h>*/
#include <axutil_env.h>
#include <rampart_saml_token.h>
#include <rampart_issued_token.h>

/*#include <rp_includes.h>
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
*/

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_config_t rampart_config_t;

    /**
     * Create a rampart_config which can be used to get rampart specific configurations from user
     * @param env pointer to environment struct,Must not be NULL.
     * @return ramaprt_config_t* on successful creation. Else NULL; 
     */
    AXIS2_EXTERN rampart_config_t *AXIS2_CALL
    rampart_config_create(
        const axutil_env_t *env);

    /**
     * Frees a rampart_config.
     * @param rampart_config the rampart_config
     * @param env pointer to environment struct,Must not be NULL.
     */
    AXIS2_EXTERN void AXIS2_CALL
    rampart_config_free(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    /**
     * set username needed to build username token
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * @param user name of the user
     * @returns status of the op. AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_username(
        rampart_config_t *rampart_config,
        const axutil_env_t *env,
        axis2_char_t *user);

    /**
     * set password of the user. Will be used to build UsernameToken
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * @param password password of the user
     * @returns status of the op.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_password(
        rampart_config_t *rampart_config,
        const axutil_env_t *env,
        axis2_char_t *password);

    /**
     * set password type needed. Will be used to build UsernameToken
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * @param password_type type of the password. (hash/plain)
     * @returns status of the op.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_password_type(
        rampart_config_t *rampart_config,
        const axutil_env_t *env,
        axis2_char_t *password_type);

    /**
     * sets time to live parameter needed by Timestamp element
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * @param ttl time to live value in seconds
     * @returns status of the op.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_ttl(
        rampart_config_t *rampart_config,
        const axutil_env_t *env,
        int ttl);

    /**
     * Sets saml token needed to build/process the message
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not b e NULL.
     * @param saml SAML token used to build/process the message
     * @returns status of the op.
     */
	AXIS2_EXTERN int AXIS2_CALL
	rampart_config_add_saml_token(
        rampart_config_t *rampart_config, 
		const axutil_env_t *env, 
		rampart_saml_token_t *saml);

    /**
     * sets function pointer used to aquire issued token
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * @param issued_token_aquire function pointer from which issued token will be obtained
     * @returns status of the op.
     */
	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	rampart_config_set_issued_token_aquire_function(
        rampart_config_t *rampart_config,
		const axutil_env_t *env,
		issued_token_callback_func issued_token_aquire);

    /**
     * Gets stored username
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns username stored in rampart config
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_username(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    /**
     * Gets stored password
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns password stored in rampart config
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_password(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    /**
     * Gets stored password type
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns password type stored in rampart config
     */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_password_type(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    /**
     * Gets stored time to live
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns time to live parameter stored in rampart config
     */
    AXIS2_EXTERN int AXIS2_CALL
    rampart_config_get_ttl(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    /**
     * Gets stored SAML token
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns SAML token stored in rampart config
     */
	AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
	rampart_config_get_saml_tokens(
        rampart_config_t *rampart_config, 
		const axutil_env_t *env);    

    /**
     * Gets stored issued token aquire function pointer
     * @param rampart_config rampart configuration structure
     * @param evn pointer to environment struct,Must not be NULL.
     * returns issued token aquire function pointer stored in rampart config
     */
	AXIS2_EXTERN issued_token_callback_func AXIS2_CALL
	rampart_config_get_issued_token_aquire_function(
        rampart_config_t *rampart_config, 
		const axutil_env_t *env);    

    /* @} */
#ifdef __cplusplus
}
#endif

#endif /* RAMPART_CONFIG_H */

