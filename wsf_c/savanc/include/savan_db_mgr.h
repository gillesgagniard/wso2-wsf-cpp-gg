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

#ifndef SAVAN_DB_MGR_H
#define SAVAN_DB_MGR_H

/**
 * @file savan_db_mgr.h
 * @brief Savan Database Manager Interface
 */

#include <axutil_allocator.h>
#include <axutil_env.h>
#include <axutil_error.h>
#include <axutil_string.h>
#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <savan_subscriber.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C"
{
#endif


/** 
 * @brief Savan Database Manager Struct Impl
 *   Savan Database Manager
 */
typedef struct savan_db_mgr
{
    axis2_char_t *dbname;
}savan_db_mgr_t;

AXIS2_EXTERN savan_db_mgr_t * AXIS2_CALL
savan_db_mgr_create(
    const axutil_env_t *env,
    axis2_char_t *dbname);

AXIS2_EXTERN void AXIS2_CALL
savan_db_mgr_free(
    savan_db_mgr_t *db_mgr,
    const axutil_env_t *env);

AXIS2_EXTERN int 
savan_db_mgr_topic_find_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name);

AXIS2_EXTERN int 
savan_db_mgr_subs_find_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name);

AXIS2_EXTERN int 
savan_db_mgr_subs_retrieve_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_insert_subscriber(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_update_subscriber(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    savan_subscriber_t *subscriber);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_insert_topic(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    axis2_char_t *topic_name,
    axis2_char_t *topic_url);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_remove(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    axis2_char_t *sql_stmt_remove);

AXIS2_EXTERN savan_subscriber_t *AXIS2_CALL
savan_db_mgr_retrieve(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    int (*retrieve_func)(void *, int, char **, char **),
    axis2_char_t *sql_stmt_retrieve);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_update(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    axis2_char_t *sql_stmt_update);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
savan_db_mgr_retrieve_all(
    const axutil_env_t *env,
    const axis2_char_t *dbname,
    int (*find_func)(void *, int, char **, char **),
    axis2_char_t *sql_stmt_find);

AXIS2_EXTERN void * AXIS2_CALL
savan_db_mgr_get_dbconn(
    const axutil_env_t *env,
    const axis2_char_t *dbname);

axis2_char_t *AXIS2_CALL
savan_db_mgr_create_update_sql(
    const axutil_env_t *env,
    savan_subscriber_t *subscriber);

/**
 * This function will create the savan_db database if it is not aleardy exists
 * @param db_mgr database manager instance
 * @param env axis2c environment
 * @return status AXIS2_SUCCESS if success, AXIS2_FAILURE if failed.
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
savan_db_mgr_create_db(
    const axutil_env_t *env,
    const axis2_char_t *dbname);

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* SAVAN_DB_MGR_H */
