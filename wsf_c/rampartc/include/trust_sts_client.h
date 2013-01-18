
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

#ifndef TRUST_STS_CLIENT
#define TRUST_STS_CLIENT

/**
  * @file trust_sts_client.h
  * @brief contains the specific sts client interface
  */

#include <stdio.h>
#include <stdlib.h>
#include <axiom.h>
#include <axutil_utils.h>
#include <axis2_client.h>
#include <rp_includes.h>
#include <rp_secpolicy.h>
#include <neethi_policy.h>
#include <neethi_util.h>
#include <rampart_util.h>
#include <trust_constants.h>
#include <trust_util.h>
#include <trust_policy_util.h>
#include <trust_token.h>
#include <rampart_config.h>
#include <trust_rst.h>
#include <trust_rstr.h>
#include <trust_context.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct trust_sts_client trust_sts_client_t;

    AXIS2_EXTERN trust_sts_client_t *AXIS2_CALL
    trust_sts_client_create(
        const axutil_env_t * env);

    AXIS2_EXTERN void AXIS2_CALL
    trust_sts_client_free(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env);

    
    /*Send RST to the specified STS/IP. RST Node that is built from RST_Context should be passed*/
    AXIS2_EXTERN void AXIS2_CALL
    trust_sts_client_request_security_token(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        trust_context_t *trust_context);


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_sts_client_process_policies(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        neethi_policy_t * issuer_policy,
        neethi_policy_t * service_policy);


    AXIS2_EXTERN axis2_svc_client_t *AXIS2_CALL
    trust_sts_client_get_svc_client(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * action,
        axis2_char_t * address_version, 
        axis2_bool_t is_soap11);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_sts_client_set_issuer_address(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * address);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_sts_client_set_home_dir(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * directory);

    AXIS2_EXTERN oxs_buffer_t* AXIS2_CALL
    trust_sts_client_request_security_token_using_policy(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        trust_context_t *trust_context,
        neethi_policy_t *issuer_policy,
        axis2_char_t *address_version,
        axis2_bool_t is_soap11,
        rampart_context_t *rampart_context);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_sts_client_set_issuer_policy_location(
    	trust_sts_client_t * sts_client,
    	const axutil_env_t * env,
    	axis2_char_t * file_path);

	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	trust_sts_client_get_issuer_policy_location(
    	trust_sts_client_t * sts_client,
	    const axutil_env_t * env);

	AXIS2_EXTERN axis2_char_t *AXIS2_CALL
	trust_sts_client_get_service_policy_location(
	    trust_sts_client_t * sts_client,
	    const axutil_env_t * env);

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_sts_client_set_service_policy_location(
    	trust_sts_client_t * sts_client,
    	const axutil_env_t * env,
	    axis2_char_t * file_path);

		AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_sts_client_set_auth_info(
		trust_sts_client_t * sts_client,
		const axutil_env_t * env,
		axis2_char_t *username,
		axis2_char_t *password,
		axis2_char_t * auth_type);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_sts_client_set_issued_token(
		trust_sts_client_t * sts_client,
		const axutil_env_t * env,
		rampart_saml_token_t *saml_token);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_sts_client_set_issued_token_func(
		trust_sts_client_t * sts_client,
		const axutil_env_t * env,
			issued_token_callback_func issue_token_func);



#ifdef __cplusplus
}
#endif
#endif                          /*TRUST_STS_CLIENT_H */
