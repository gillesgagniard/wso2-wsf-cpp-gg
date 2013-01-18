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
#include <axutil_env.h>
#include <axis2_msg_ctx.h>
#include <rampart_context.h>
/**
  * @file rampart_policy_validator.h
  * @brief Verifies whether the message complies with the security policy reqmnt
  */

/**
* @defgroup rampart_policy_validator PolicyValidator
* @ingroup rampart_utils
* @{
*/

#ifndef RAMPART_POLICY_VALIDATOR_H
#define RAMPART_POLICY_VALIDATOR_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * Validate security policies, those cannot be checked on the fly
    * @param env pointer to environment struct
    * @param rampart_context the Rampart Context
    * @param sec_node The security element
    * @param msg_ctx message context
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_pv_validate_sec_header(
        const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axiom_node_t *sec_node,
        axis2_msg_ctx_t *msg_ctx);


    /* @} */
#ifdef __cplusplus
}
#endif

#endif    /* !RAMPART_POLICY_VALIDATOR_H */
