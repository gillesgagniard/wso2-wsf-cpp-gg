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

#include <axutil_utils_defines.h>
#include <axis2_defines.h>
#include <axutil_date_time.h>
#include <axutil_env.h>
#include <axis2_msg_ctx.h>
#include <rampart_authn_provider.h>
#include <rampart_credentials.h>
#include <rampart_callback.h>
#include <rampart_replay_detector.h>
#include <rampart_sct_provider.h>

/**
* @file rampart_util.h
* @brief Utilities of rampart
*/

/**
* @defgroup rampart_util Utils
* @ingroup rampart_utils
* @{
*/

#ifndef RAMPART_UTIL_H
#define RAMPART_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Load the credentials module
     * User MUST free memory
     * @param env pointer to environment struct
     * @param cred_module_name name of the credentails module to be loaded
     * @return the loaded credentails module
     */
    AXIS2_EXTERN rampart_credentials_t* AXIS2_CALL
    rampart_load_credentials_module(
        const axutil_env_t *env,
        axis2_char_t *cred_module_name);

    /**
     * Call credentials module
     * User MUST free memory of username and password
     * @param env pointer to environment struct
     * @param cred_module the credentails module
     * @param ctx the message context
     * @param username reference to the returned username
     * @param password reference to the returned password
     * @return the status of the operation
     */
    AXIS2_EXTERN rampart_credentials_status_t AXIS2_CALL
    rampart_call_credentials(
        const axutil_env_t *env,
        rampart_credentials_t *cred_module,
        axis2_msg_ctx_t *ctx,
        axis2_char_t **username,
        axis2_char_t **password);

    /**
     * Load authentication module
     * User MUST free memory
     * @param env pointer to environment struct
     * @param auth_module_name name of the authentication module
     * @return created athenticaiton module
     */
    AXIS2_EXTERN rampart_authn_provider_t* AXIS2_CALL
    rampart_load_auth_module(
        const axutil_env_t *env,
        axis2_char_t *auth_module_name);

    /**
     * Load replay detection module
     * User MUST free memory
     * @param env pointer to environment struct
     * @param replay_detector_name name of the replay detection module
     * @return created replay detection module
     */
    AXIS2_EXTERN rampart_replay_detector_t* AXIS2_CALL
    rampart_load_replay_detector(
        const axutil_env_t *env,
        axis2_char_t *replay_detector_name);

    /**
     * Load security context token provider
     * User MUST free memory
     * @param env pointer to environment struct
     * @param sct_provider_name name of the security context token provider 
     * @return created security context token provider module
     */
    AXIS2_EXTERN rampart_sct_provider_t* AXIS2_CALL
    rampart_load_sct_provider(
        const axutil_env_t *env,
        axis2_char_t *sct_provider_name);

    /**
     * Load the password callback module
     * User MUST free memory
     * @param env pointer to environment struct
     * @callback_module_name the name of the callback module
     * @return the loaded callback module
     */
    AXIS2_EXTERN rampart_callback_t* AXIS2_CALL
    rampart_load_pwcb_module(
        const axutil_env_t *env,
        axis2_char_t *callback_module_name);


    /**
     * Call auth module
     * @param env pointer to environment struct
     * @param authp the authentication module
     * @param  username the username in the UsernameToken
     * @param  password the password in the UsernameToken
     * @param  nonce the nonce in the UsernameToken. Can be NULL if plain text password is used.
     * @param  created created time in UsernameToken. Can be NULL if plain text password is used.
     * @param password_type  the type of the password. either plain text of digest
     * @param msg_ctx the message context
     * @return status of the operation
     */
    AXIS2_EXTERN rampart_authn_provider_status_t AXIS2_CALL
    rampart_authenticate_un_pw(
        const axutil_env_t *env,
        rampart_authn_provider_t *authp,
        const axis2_char_t *username,
        const axis2_char_t *password,
        const axis2_char_t *nonce,
        const axis2_char_t *created,
        const axis2_char_t *password_type,
        axis2_msg_ctx_t *msg_ctx);


    /**
     * Gets the password of given user.
     * @env the environment
     * @callback_module callback module structure
     * @username the name of the user to get the password
     * @return the password for the user or NULL if failed
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    rampart_callback_password(
        const axutil_env_t *env,
        rampart_callback_t *callback_module,
        const axis2_char_t *username);

	/**
	 * Get the password for pkcs12 key store.
	 * @env pointer to environment struct
	 * @callback pointer to rampart callback module
	 * @username name of the pkcs12 owner
	 * @return the password for the user or NULL if username is incorrect
	 */
	AXIS2_EXTERN axis2_char_t * AXIS2_CALL
	rampart_callback_pkcs12_password(
	    const axutil_env_t *env,
	    rampart_callback_t *callback_module,
	    const axis2_char_t *username);	

    /**
     * Generates time.
     * User MUST free memory
     * @param ttl Time to live. The time difference between created and expired in mili seconds.
     * @param with_millisecond  shows whether millisecond precision is needed or not
     * @return generated time
     **/
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    rampart_generate_time(
        const axutil_env_t *env, 
        int ttl, 
        axis2_bool_t with_millisecond);

    /**
     * Check if @dt1 < @dt2. if not returns a false
     * @param env pointer to environment struct
     * @param dt1 date time 1.
     * @param dt2 date time 2.
     * @return AXIS2_SUCCESS if dt1 < dt2. AXIS2_FALSE otherwise
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_compare_date_time(
        const axutil_env_t *env, 
        axis2_char_t *dt1, 
        axis2_char_t *dt2);

    /* @} */
#ifdef __cplusplus
}
#endif

#endif    /* RAMPART_UTIL_H */


