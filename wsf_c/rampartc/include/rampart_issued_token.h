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
 */

#ifndef RAMPART_ISSUED_TOKEN_H
#define RAMPART_ISSUED_TOKEN_H

#include <rp_property.h>
#include <rp_includes.h>
#include <rp_secpolicy.h>
#include <axutil_property.h>
#include <axis2_key_type.h>
#include <axis2_msg_ctx.h>
#include <axutil_array_list.h>
#include <axiom.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct rampart_issued_token_t rampart_issued_token_t;

	typedef rampart_issued_token_t *(AXIS2_CALL * issued_token_callback_func)(
		const axutil_env_t *env,
		rp_property_t *issued_token,
        void *ctx);
    /**
     *
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */


	AXIS2_EXTERN rampart_issued_token_t * AXIS2_CALL
	rampart_issued_token_create(
		const axutil_env_t *env);

    /**
     *
     * @param token
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	rampart_issued_token_free(
		rampart_issued_token_t *token, 
		const axutil_env_t *env);

    /**
     *
     * @param issued_token
     * @param env pointer to environment struct,Must not be NULL.
     * @param token
     * @param token_type
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	rampart_issued_token_set_token(
		rampart_issued_token_t *issued_token, 
		const axutil_env_t *env, void *token, 
		rp_property_type_t token_type);
    /**
     *
     * @param token
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN rp_property_type_t AXIS2_CALL
	rampart_issued_token_get_token_type(
		rampart_issued_token_t *token, 
		const axutil_env_t *env);

    /**
     *
     * @param token
     * @param env pointer to environment struct,Must not be NULL.
     * @returns status of the op.                                                                                                        
     * AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */

	AXIS2_EXTERN void * AXIS2_CALL
	rampart_issued_token_get_token(
		rampart_issued_token_t *token, 
		const axutil_env_t *env);

#ifdef __cplusplus
}
#endif

#endif

