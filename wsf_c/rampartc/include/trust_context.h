
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

#ifndef TRUST_CONTEXT_H
#define TRUST_CONTEXT_H

/**
  * @file trust_context.h
  * @brief Holds function declarations and data for data
  */

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <axis2_msg_ctx.h>
#include <axis2_addr.h>
#include <trust_constants.h>
#include <trust_rst.h>
#include <trust_rstr.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct trust_context trust_context_t;

    AXIS2_EXTERN trust_context_t *AXIS2_CALL
        	trust_context_create(
            const axutil_env_t * env);
    
    AXIS2_EXTERN  void AXIS2_CALL
            trust_context_free( 
			trust_context_t *trust_context,           
            const axutil_env_t * env);
    
    
    /*Populate RST_CONTEXT : Often used in STS/IP side */
   	AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_context_process_rst(
		trust_context_t *trust_context,
    	const axutil_env_t * env,    
    	axis2_msg_ctx_t * in_msg_ctx);
    
    /*Populate RSTR_CONTEXT : Often used in Token Requestor side*/
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_context_process_rstr(
		trust_context_t *trust_context,
        const axutil_env_t * env,
        axis2_msg_ctx_t * in_msg_ctx);
    
    /*Build RST Node from created RST_CONTEXT */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
	trust_context_build_rst_node(
		trust_context_t *trust_context,
    	const axutil_env_t * env);
    
    /*Build RSTR Node from created RSTR_CONTEXT */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
	trust_context_build_rstr_node(
		trust_context_t *trust_context,
    	const axutil_env_t * env);
    
    
    /*Get Populated RST_CONTEXT */
    AXIS2_EXTERN trust_rst_t* AXIS2_CALL
	trust_context_get_rst(
		trust_context_t *trust_context,
    	const axutil_env_t * env);
    
    /*Get Populated RSTR_CONTEXT */
    AXIS2_EXTERN trust_rstr_t* AXIS2_CALL
	trust_context_get_rstr(
		trust_context_t *trust_context,
    	const axutil_env_t * env);
    
    /*Set RST_CONTEXT */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_set_rst(
		trust_context_t *trust_context,
    	const axutil_env_t * env,    
    	trust_rst_t *rst);
    
    /*Set RSTR_CONTEXT */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
	trust_context_set_rstr(
		trust_context_t *trust_context,
    	const axutil_env_t * env,
    	trust_rstr_t *rstr);
    
    
 
    
#ifdef __cplusplus
}
#endif
#endif                          /*TRUST_CONTEXT_H */
