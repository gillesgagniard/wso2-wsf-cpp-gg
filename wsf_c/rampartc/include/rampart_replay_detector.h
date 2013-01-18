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

#ifndef RAMPART_REPLAY_DETECTOR_H
#define RAMPART_REPLAY_DETECTOR_H

/**
* @file rampart_replay_detector.h
* @brief The replay_detector module for rampart 
*/

/**
* @defgroup rampart_replay_detector Replay Detector
* @ingroup rampart_utils
* @{
*/

#include <axis2_defines.h>
#include <axutil_env.h>
#include <axis2_msg_ctx.h>
#include <rampart_context.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_replay_detector_ops rampart_replay_detector_ops_t;
    typedef struct rampart_replay_detector rampart_replay_detector_t;

    struct rampart_replay_detector_ops
    {
        /**
         * Check whether the message is replayed or not. If not replayed, message fields have to be 
         * stored to check replay status of future messages
         * @param rrd the replay detector struct
         * @param env pointer to environment struct
         * @param msg_ctx message context
         * @param rampart_context rampart context struct
         * @return the status of the check
         */
        axis2_status_t (AXIS2_CALL*
        is_replayed)(
            rampart_replay_detector_t *rrd,
            const axutil_env_t* env,
            axis2_msg_ctx_t *msg_ctx,
            rampart_context_t *rampart_context);

        /**
         * The free function to free all resources allocated
         * @param rrd the replay detector structure
         * @param env pointer to environment struct
         * @return AXIS2_SUCCESS on success. AXIS2_FAILURE otherwise.
         */
        axis2_status_t (AXIS2_CALL*
        free)(
            rampart_replay_detector_t *rrd,
            const axutil_env_t* env);
    };

    struct rampart_replay_detector
    {
        rampart_replay_detector_ops_t *ops;
		axutil_param_t *param;
    };

    
    /**
     * A linked list based implementation for replay detection.
     * This doesnt require addressing headers to be present. If the user doesn't give any replay
     * detection function, then this will be used.
     * @param env pointer to environment struct,Must not be NULL.
     * @param msg_ctx message context structure
     * @param rampart_context rampart context structure
     * @param user_params parameters given by user. (Not used in this method)
     * @returns status of the op. AXIS2_SUCCESS on success and AXIS2_FAILURE on error          
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_replay_detector_default(
        const axutil_env_t *env,
        axis2_msg_ctx_t* msg_ctx,
        rampart_context_t *rampart_context,
        void *user_params);

    /*************************** Function macros **********************************/
#define RAMPART_REPLAY_DETECTOR_IS_REPLAYED(replay_detector, env, msg_ctx, rampart_context) \
      ((replay_detector)->ops->is_replayed(replay_detector, env, msg_ctx, rampart_context))

#define RAMPART_REPLAY_DETECTOR_FREE(replay_detector, env) \
        ((replay_detector)->ops->free(replay_detector, env))

    /** @} */
#ifdef __cplusplus
}
#endif

#endif /* RAMPART_REPLAY_DETECTOR_H */

