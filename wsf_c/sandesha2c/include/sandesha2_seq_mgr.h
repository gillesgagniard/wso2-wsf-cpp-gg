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

#ifndef SANDESHA2_SEQ_MGR_H
#define SANDESHA2_SEQ_MGR_H

/**
 * @file sandesha2_seq_mgr.h
 * @brief Sandesha In Memory Sequence Manager Interface
 */

#include <axutil_allocator.h>
#include <axutil_env.h>
#include <axutil_utils_defines.h>
#include <axutil_error.h>
#include <axutil_string.h>
#include <axutil_utils.h>
#include <sandesha2_storage_mgr.h>
#include <sandesha2_msg_ctx.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct sandesha2_seq_property_mgr;
struct sandesha2_next_msg_mgr;

/** @defgroup sandesha2_seq_mgr In Memory Sequence Manager
  * @ingroup sandesha2
  * @{
  */

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
sandesha2_seq_mgr_setup_new_incoming_sequence(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *create_seq_msg, 
    struct sandesha2_seq_property_mgr *seq_prop_mgr,
    struct sandesha2_next_msg_mgr *next_msg_mgr);
       
/**
 * Takes the internal_seq_id as the param. Not the seq_id
 * @param internal_seq_id
 * @param config_ctx
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_seq_mgr_update_last_activated_time(
    const axutil_env_t *env,
    axis2_char_t *property_key,
    struct sandesha2_seq_property_mgr *seq_prop_mgr);
    
AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_seq_mgr_has_seq_timedout(
    const axutil_env_t *env,
    axis2_char_t *property_key,
    struct sandesha2_seq_property_mgr *seq_prop_mgr,
    axis2_svc_t *svc
    /*axis2_conf_ctx_t *conf_ctx*/);
        
AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_seq_mgr_setup_new_outgoing_sequence(
    const axutil_env_t *env,
    axis2_msg_ctx_t *first_app_msg,
    axis2_char_t *int_seq_id,
    axis2_char_t *spec_version,
    struct sandesha2_seq_property_mgr *seq_prop_mgr);

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* SANDESHA2_SEQ_MGR_H */
