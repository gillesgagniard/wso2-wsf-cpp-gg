/**
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


#include <axiom_soap_header.h>
#include <axis2_msg_ctx.h>

#ifndef RAMPART_HANDLER_UTIL_H
#define RAMPART_HANDLER_UTIL_H

/**
  * @file rampart_handler_util.h
  * @brief Utilities related to handlers 
  */

/**
* @defgroup rampart_handler_util Handler Utilities
* @ingroup rampart_utils
* @{
*/
#ifdef __cplusplus
extern "C"
{
#endif

    /**
    * Get the security header from the header block
    * @param env pointer to environment struct
    * @param msg_ctx message context
    * @param soap_header header block 
    * @return security soap header node
    */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    rampart_get_security_header(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_soap_header_t *soap_header);

    /**
    * Creates a SOAP fault based on params described below and store in msg_ctx
    * @param env pointer to environment struct
    * @param sub_code the text of the Subcode element of a SOAP fault message
    * @param reason_text the text in soapenv:Reason element
    * @param detail_node_text the text in the soapenv:Detail element
    * @param msg_ctx the msg_ctx 
    * @return void
    */
    AXIS2_EXTERN void AXIS2_CALL
    rampart_create_fault_envelope(
        const axutil_env_t *env,
        const axis2_char_t *sub_code,
        const axis2_char_t *reason_text,
        const axis2_char_t *detail_node_text,
        axis2_msg_ctx_t *msg_ctx);

    /**
     * Get rampart configurations from the message context
     * @param env pointer to environment struct
     * @param msg_ctx message context
     * @param param_name name of the parameter of the configuration
     * @return the loaded configuration params
     */
    AXIS2_EXTERN void *AXIS2_CALL
    rampart_get_rampart_configuration(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_char_t *param_name);

    /**
     * Check wether rampart is engaged or not
     * @param env pointer to environment struct
     * @param msg_ctx message context
     * @return if engaged returns AXIS2_TRUE, else returns AXIS2_FALSE
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    rampart_is_rampart_engaged(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx);

    /** @} */
#ifdef __cplusplus
}
#endif


#endif /*RAMPART_HANDLER_UTIL_H*/
