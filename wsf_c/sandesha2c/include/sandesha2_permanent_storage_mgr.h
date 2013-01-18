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
 
#ifndef SANDESHA2_PERMANENT_STORAGE_MGR_H
#define SANDESHA2_PERMANENT_STORAGE_MGR_H

/**
  * @file sandesha2_permanent_storage_mgr.h
  * @brief 
  */

#include <axutil_utils_defines.h>
#include <axutil_env.h>
#include <axis2_conf_ctx.h>
#include <sandesha2_storage_mgr.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct sandesha2_response
{
    int soap_version;
    axis2_char_t *response_str;
} sandesha2_response_t;

/** 
 * @ingroup sandesha2_storage
 * @{
 */

AXIS2_EXTERN sandesha2_storage_mgr_t* AXIS2_CALL
sandesha2_permanent_storage_mgr_create(
    const axutil_env_t *env,
    axis2_char_t *dbname);

void * AXIS2_CALL
sandesha2_permanent_storage_mgr_get_dbconn(
    sandesha2_storage_mgr_t *storage_mgr,
    const axutil_env_t *env);

axis2_status_t AXIS2_CALL
sandesha2_permanent_storage_mgr_create_db(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /*SANDESHA2_PERMANENT_STORAGE_MGR_H*/
