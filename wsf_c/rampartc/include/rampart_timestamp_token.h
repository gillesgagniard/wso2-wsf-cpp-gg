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

#ifndef RAMPART_TIMESTAMP_TOKEN_H
#define RAMPART_TIMESTAMP_TOKEN_H

/**
  * @file rampart_timestamp_token.h
  * @brief Timestamp token related functions. 
  */

/**
* @defgroup rampart_timestamp_token Timestamp Token
* @ingroup rampart_utils
* @{
*/

#ifdef __cplusplus
extern "C"
{
#endif

#include <axutil_env.h>
    /**
     * Builds timestamp token.
     * @param env pointer to environment struct
     * @param sec_node security node
     * @param ttl Time to live. The time difference btwn Created and Expired. If it is zero or less
     * than zero, then Expired element will not be created. 
     * @param with_millisecond shows whether millisecond precision is needed
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    axis2_status_t AXIS2_CALL
    rampart_timestamp_token_build(
        const axutil_env_t *env,
        axiom_node_t *sec_node,
        int ttl, 
        axis2_bool_t with_millisecond);

    /**
     * Validates time stamp token. Validation is based in expiration time of the Expired element.
     * @param env pointer to environment struct
     * @param msg_ctx pointer to message context structure
     * @param ts_node Timestamp node
     * @param clock_skew_buffer buffer of allowable skew of time between sender and receiver
     * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    axis2_status_t AXIS2_CALL
    rampart_timestamp_token_validate(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_node_t *ts_node,
        int clock_skew_buffer);

    /* @} */
#ifdef __cplusplus
}
#endif


#endif /*RAMPART_TIMESTAMP_TOKEN_H*/
