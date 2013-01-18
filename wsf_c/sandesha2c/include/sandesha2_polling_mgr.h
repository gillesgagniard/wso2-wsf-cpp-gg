/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SANDESHA2_POLLING_MGR_H
#define SANDESHA2_POLLING_MGR_H

/**
 * @file sandesha2_polling_mgr.h
 * @brief Sandesha Polling Manager Interface
 * This class is responsible for sending MakeConnection requests. This is a 
 * separate thread that keeps running. Will do MakeConnection based on the 
 * request queue or randomly.
 */

#include <axutil_allocator.h>
#include <axutil_env.h>
#include <axutil_error.h>
#include <axutil_string.h>
#include <axutil_utils.h>
#include <axis2_conf_ctx.h>
#include <sandesha2_msg_ctx.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_sender_mgr.h>

#ifdef __cplusplus
extern "C"
{
#endif

            
axis2_status_t AXIS2_CALL 
sandesha2_polling_mgr_start (
    const axutil_env_t *env, 
    axis2_conf_ctx_t *conf_ctx,
    sandesha2_storage_mgr_t *storage_mgr,
    sandesha2_sender_mgr_t *sender_mgr,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    const axis2_char_t *internal_sequence_id,
    axis2_char_t *sequence_id,
    const axis2_char_t *reply_to);
            
/** @} */
#ifdef __cplusplus
}
#endif
#endif /* SANDESHA2_POLLING_MGR_H */
