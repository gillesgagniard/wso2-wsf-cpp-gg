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

#ifndef RAMPART_SCT_PROVIDER_H
#define RAMPART_SCT_PROVIDER_H

/**
  * @file rampart_sct_provider.h
  * @brief Security context token provider module for rampart 
  */

/**
* @defgroup sct_provider Security Context Token provider
* @ingroup rampart_utils
* @{
*/

#include <axis2_defines.h>
#include <axutil_env.h>
#include <rampart_context.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_sct_provider_ops rampart_sct_provider_ops_t;
    typedef struct rampart_sct_provider rampart_sct_provider_t;

    struct rampart_sct_provider_ops
    {
        /* This function will be called to get previously stored sct. If secure conversation token 
         * is referred by this method, then sct_id will be not null. However, if security context 
         * token (pre-agreed and established offline) is refered then sct_id might be NULL. 
         * is_encryption is passed, so that if pre-agreed sct is different for encryption and 
         * signature, then it could be accessed. sct_id_type can be RAMPART_SCT_ID_TYPE_LOCAL 
         * or RAMPART_SCT_ID_TYPE_GLOBAL. user_param will be whatever stored using 
         * rampart_context_set_security_context_token_user_params. 
         */
        obtain_security_context_token_fn obtain_security_context_token;

        /* This function will be used to store sct. Global id, local id will be given so function 
         * writer can store them in anyway. Get or Delete method will use any of the Global id or 
         * local id, so Store function writer should be ready for that. 
         */
        store_security_context_token_fn store_security_context_token;

        /* This function will be called to delete previously stored sct. sct_id_type can be 
         * RAMPART_SCT_ID_TYPE_LOCAL or RAMPART_SCT_ID_TYPE_GLOBAL
         */
        delete_security_context_token_fn delete_security_context_token;

        /* Validates whether security context token is valid or not. Normally, we can directly send 
         * true as response. But if syntax of security context token is altered/added by using 
         * extensible mechanism (e.g having sessions, etc.) then user can implement this method. 
         * Axiom representation of the sct will be given as the parameter, because if sct is 
         * extended, we don't know the syntax. Method writer can implement whatever needed.
         */
        validate_security_context_token_fn validate_security_context_token;

        /* This function will be called to get the user paramters. It will be called only when 
         * loading sct_provider module. If user_params are not needed, this method can return NULL
         */
        void* (AXIS2_CALL*
        get_user_params)(
            const axutil_env_t *env);

        /* This function will be called to free security context token provider module */
        axis2_status_t (AXIS2_CALL*
        free)(
            rampart_sct_provider_t *sct_provider,
            const axutil_env_t* env);
    };

    struct rampart_sct_provider
    {
        rampart_sct_provider_ops_t *ops;
		axutil_param_t *param;
    };

    /*************************** Function macros **********************************/
#define RAMPART_SCT_PROVIDER_FREE(sct_provider, env) \
        ((sct_provider)->ops->free(sct_provider, env))

    /** @} */
#ifdef __cplusplus
}
#endif

#endif  /* RAMPART_SCT_PROVIDER_H */


