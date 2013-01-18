/*
 *   Copyright 2003-2004 The Apache Software Foundation.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <axutil_utils_defines.h>
#include <axis2_defines.h>
#include <axutil_env.h>
#include <axiom_soap.h>
#include <axis2_msg_ctx.h>
#include <oxs_asym_ctx.h>
#include <oxs_xml_encryption.h>
#include <rampart_context.h>
#include <oxs_key_mgr.h>
/**
  * @file rampart_sec_header_processor.h
  * @brief Processes a message depending on it's security related claims 
  */

/**
* @defgroup sec_header_processor Security Header Processor
* @ingroup rampart_utils
* @{
*/

#ifndef RAMPART_SEC_HEADER_PROCESSOR_H
#define RAMPART_SEC_HEADER_PROCESSOR_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * Processes a message depending on it's security related claims.
    * This is the main module in the infow of a message if rampart is enabled.
    * Processing is depending on the order of tokens apear in the @sec_node
    * Also the module will check for security policy settings	
    * @param env pointer to environment struct
    * @param msg_ctx message context
    * @param soap_envelope the SOAP envelope
    * @param sec_node The security element
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_shp_process_sec_header(const axutil_env_t *env,
                                axis2_msg_ctx_t *msg_ctx,
                                rampart_context_t *rampart_context,
                                axiom_soap_envelope_t *soap_envelope,
                                axiom_node_t *sec_node);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_shp_add_security_context_token(
        const axutil_env_t* env,
        axis2_char_t* identifier,
        axis2_char_t* key_name,
        rampart_context_t* rampart_context,
        axis2_msg_ctx_t* msg_ctx);


    /* @} */
#ifdef __cplusplus
}
#endif

#endif    /* !RAMPART_SEC_HEADER_PROCESSOR_H */
