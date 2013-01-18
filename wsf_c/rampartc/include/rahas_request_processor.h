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

#ifndef RAHAS_REQUEST_PROCESSOR_H
#define RAHAS_REQUEST_PROCESSOR_H

/**
 * @file rahas_request_processor.h
 * @brief Process requests related to secure conversation.
 */

/**
* @defgroup rahas SecurityContextToken Issuer
* @{
*/

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Processes issue request
     * @param env pointer to environment struct
     * @param rst request security token struct
     * @param rstr request security token response struct
     * @param msg_ctx message context structure
     * @param trust_version Trust specification. Can be TRUST_VERSION_05_02 or TRUST_VERSION_05_12
     * @return AXIS2_SUCCESS if processed successfully. AXIS2_FAILURE otherwise.
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rahas_process_issue_request(
        const axutil_env_t *env, 
        trust_rst_t *rst, 
        trust_rstr_t *rstr,
        axis2_msg_ctx_t *msg_ctx,
        int trust_version);

    /** @} */

#ifdef __cplusplus
}
#endif

#endif    /* RAHAS_REQUEST_PROCESSOR_H */
