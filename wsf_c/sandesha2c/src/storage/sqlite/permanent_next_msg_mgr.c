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
 
#include "sandesha2_permanent_next_msg_mgr.h"
#include "sandesha2_permanent_bean_mgr.h"
#include <sandesha2_next_msg_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
#include <sandesha2_utils.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_thread.h>
#include <axutil_property.h>
#include <axutil_types.h>
#include <stdlib.h>
/** 
 * @brief Sandesha2 Permanent Next Message Manager Struct Impl
 *   Sandesha Sequence2 Permanent Next Message Manager 
 */ 
typedef struct sandesha2_permanent_next_msg_mgr
{
    sandesha2_next_msg_mgr_t next_msg_mgr;
    sandesha2_permanent_bean_mgr_t *bean_mgr;
    axutil_array_list_t *values;
} sandesha2_permanent_next_msg_mgr_t;

#define SANDESHA2_INTF_TO_IMPL(next_msg_mgr) \
    ((sandesha2_permanent_next_msg_mgr_t *) next_msg_mgr)

static int 
sandesha2_next_msg_find_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name)
{
    sandesha2_next_msg_bean_t *bean = NULL;
    int i = 0;
    sandesha2_bean_mgr_args_t *args = (sandesha2_bean_mgr_args_t *) not_used;
    const axutil_env_t *env = args->env;
    axutil_array_list_t *data_list = (axutil_array_list_t *) args->data;
    if(argc < 1)
    {
        args->data = NULL;
        return 0;
    }
    if(!data_list)
    {
        data_list = axutil_array_list_create(env, 0);
        args->data = data_list;
    }
    if(argc > 0)
    {
        bean = sandesha2_next_msg_bean_create(env);
    }
    for(i = 0; i < argc; i++)
    {
        if(0 == axutil_strcmp(col_name[i], "seq_id"))
        {
            sandesha2_next_msg_bean_set_seq_id(bean, env, argv[i]);
        }
        if(0 == axutil_strcmp(col_name[i], "internal_seq_id"))
        {
            sandesha2_next_msg_bean_set_internal_seq_id(bean, env, argv[i]);
        }
        if(0 == axutil_strcmp(col_name[i], "ref_msg_key"))
        {
            if(argv[i] && 0 != axutil_strcmp("(null)", argv[i]))
            {
                sandesha2_next_msg_bean_set_ref_msg_key(bean, env, argv[i]);
            }
        }
        if(0 == axutil_strcmp(col_name[i], "polling_mode"))
            sandesha2_next_msg_bean_set_polling_mode(bean, env, 
                AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_no"))
            sandesha2_next_msg_bean_set_next_msg_no_to_process(bean, env, 
                atol(argv[i]));
    }
    if(bean)
        axutil_array_list_add(data_list, env, bean);
    return 0;
}

static int 
sandesha2_next_msg_retrieve_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name)
{
    int i = 0;
    sandesha2_bean_mgr_args_t *args = (sandesha2_bean_mgr_args_t *) not_used;
    const axutil_env_t *env = args->env;
    sandesha2_next_msg_bean_t *bean = (sandesha2_next_msg_bean_t *) args->data;
    if(argc < 1)
    {
        args->data = NULL;
        return 0;
    }
    if(!bean && argc > 0)
    {
        bean = sandesha2_next_msg_bean_create(env);
        args->data = bean;
    }
    for(i = 0; i < argc; i++)
    {
        if(0 == axutil_strcmp(col_name[i], "seq_id"))
            sandesha2_next_msg_bean_set_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "internal_seq_id"))
            sandesha2_next_msg_bean_set_internal_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "ref_msg_key"))
            if(argv[i] && 0 != axutil_strcmp("(null)", argv[i]))
            {
                sandesha2_next_msg_bean_set_ref_msg_key(bean, env, argv[i]);
            }
        if(0 == axutil_strcmp(col_name[i], "polling_mode"))
        {
            sandesha2_next_msg_bean_set_polling_mode(bean, env, 
                AXIS2_ATOI(argv[i]));
        }
        if(0 == axutil_strcmp(col_name[i], "msg_no"))
            sandesha2_next_msg_bean_set_next_msg_no_to_process(bean, env, 
                atol(argv[i]));
    }
    return 0;
}

void AXIS2_CALL
sandesha2_permanent_next_msg_mgr_free(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_insert(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_remove(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    axis2_char_t *seq_id);

sandesha2_next_msg_bean_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_retrieve(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    axis2_char_t *seq_id);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_update(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean);

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_find(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean);

sandesha2_next_msg_bean_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_find_unique(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean);

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_retrieve_all(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env);

static const sandesha2_next_msg_mgr_ops_t next_msg_mgr_ops = 
{
    sandesha2_permanent_next_msg_mgr_free,
    sandesha2_permanent_next_msg_mgr_insert,
    sandesha2_permanent_next_msg_mgr_remove,
    sandesha2_permanent_next_msg_mgr_retrieve,
    sandesha2_permanent_next_msg_mgr_update,
    sandesha2_permanent_next_msg_mgr_find,
    sandesha2_permanent_next_msg_mgr_find_unique,
    sandesha2_permanent_next_msg_mgr_retrieve_all
};

AXIS2_EXTERN sandesha2_next_msg_mgr_t * AXIS2_CALL
sandesha2_permanent_next_msg_mgr_create(
    const axutil_env_t *env,
    axis2_char_t *dbname)
{
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;
    next_msg_mgr_impl = AXIS2_MALLOC(env->allocator, 
        sizeof(sandesha2_permanent_next_msg_mgr_t));

    next_msg_mgr_impl->values = axutil_array_list_create(env, 0);
    if(!next_msg_mgr_impl->values)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }
    next_msg_mgr_impl->bean_mgr = sandesha2_permanent_bean_mgr_create(env,
        dbname, SANDESHA2_BEAN_MAP_NEXT_MESSAGE);
    next_msg_mgr_impl->next_msg_mgr.ops = next_msg_mgr_ops;

    return &(next_msg_mgr_impl->next_msg_mgr);
}

void AXIS2_CALL
sandesha2_permanent_next_msg_mgr_free(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env)
{
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);

    if(next_msg_mgr_impl->bean_mgr)
    {
        sandesha2_permanent_bean_mgr_free(next_msg_mgr_impl->bean_mgr, env);
        next_msg_mgr_impl->bean_mgr = NULL;
    }
    if(next_msg_mgr_impl->values)
    {
        axutil_array_list_free(next_msg_mgr_impl->values, env);
        next_msg_mgr_impl->values = NULL;
    }
    if(next_msg_mgr_impl)
    {
        AXIS2_FREE(env->allocator, next_msg_mgr_impl);
        next_msg_mgr_impl = NULL;
    }
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_insert(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean)
{
    axis2_char_t sql_insert[1024];
	axis2_char_t *seq_id = NULL;
	axis2_char_t *internal_seq_id = NULL;
	axis2_char_t *ref_msg_key = NULL;
	axis2_bool_t polling_mode;
	long msg_no;
	sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;

    AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);

	seq_id = sandesha2_next_msg_bean_get_seq_id(bean, 
        env);
	internal_seq_id = sandesha2_next_msg_bean_get_internal_seq_id(
        bean, env);
	ref_msg_key = sandesha2_next_msg_bean_get_ref_msg_key(bean, env);
	polling_mode = sandesha2_next_msg_bean_is_polling_mode(bean, env);
    msg_no = sandesha2_next_msg_bean_get_next_msg_no_to_process(bean, env);
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);

    sprintf(sql_insert, "insert into next_msg(seq_id, internal_seq_id, "\
        "ref_msg_key,"\
        "polling_mode, msg_no) values('%s', '%s', '%s', %d, %ld);", seq_id, 
        internal_seq_id, ref_msg_key, polling_mode, msg_no);

    return sandesha2_permanent_bean_mgr_insert(next_msg_mgr_impl->bean_mgr, env,
        sql_insert);
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_remove(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    axis2_char_t *seq_id)
{
    axis2_char_t sql_remove[256];
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;

    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FALSE);
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);
    sprintf(sql_remove, "delete from next_msg where seq_id='%s'",
        seq_id);

    return sandesha2_permanent_bean_mgr_remove(next_msg_mgr_impl->bean_mgr, env, 
        sql_remove);
}

sandesha2_next_msg_bean_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_retrieve(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    axis2_char_t *seq_id)
{
    axis2_char_t sql_retrieve[256];
    sandesha2_next_msg_bean_t *bean = NULL;
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;

    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FALSE);
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);

    sprintf(sql_retrieve, "select seq_id, internal_seq_id, ref_msg_key, "\
        "polling_mode, msg_no from next_msg where seq_id='%s';", seq_id);
    bean = (sandesha2_next_msg_bean_t *) sandesha2_permanent_bean_mgr_retrieve(
        next_msg_mgr_impl->bean_mgr, env, sandesha2_next_msg_retrieve_callback, 
        sql_retrieve);

    return bean;
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_next_msg_mgr_update(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean)
{
    axis2_char_t sql_update[1024];
    axis2_bool_t ret = AXIS2_FALSE;
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;
	axis2_char_t *seq_id = NULL;
	axis2_char_t *internal_seq_id = NULL;
	axis2_char_t *ref_msg_key = NULL;
	axis2_bool_t polling_mode = AXIS2_FALSE;
	long msg_no;

    AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);
	seq_id = sandesha2_next_msg_bean_get_seq_id(bean, 
        env);
	internal_seq_id = sandesha2_next_msg_bean_get_internal_seq_id(
        bean, env);
    ref_msg_key = sandesha2_next_msg_bean_get_ref_msg_key(bean, env);
	polling_mode = sandesha2_next_msg_bean_is_polling_mode(bean, env);
    msg_no = sandesha2_next_msg_bean_get_next_msg_no_to_process(bean, env);

    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);

    sprintf(sql_update, "update next_msg set internal_seq_id='%s', "\
        "ref_msg_key='%s', polling_mode=%d"\
        ",msg_no=%ld where seq_id='%s';", internal_seq_id, ref_msg_key, 
        polling_mode, msg_no, seq_id);
    ret = sandesha2_permanent_bean_mgr_update(next_msg_mgr_impl->bean_mgr, env, 
        sql_update);

    return ret;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_find(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean)
{
    axis2_bool_t add_where = AXIS2_FALSE;
    axis2_char_t sql_find[1024];
	axis2_char_t *seq_id = NULL;
	axis2_char_t *internal_seq_id = NULL;
	long msg_no = 0;
    axutil_array_list_t *find_list = NULL;
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);

    if(bean)
    {
        seq_id = sandesha2_next_msg_bean_get_seq_id(bean, 
            env);
        internal_seq_id = sandesha2_next_msg_bean_get_internal_seq_id(
            bean, env);
        msg_no = sandesha2_next_msg_bean_get_next_msg_no_to_process(bean, env);
    }
    sprintf(sql_find, "select seq_id,internal_seq_id,ref_msg_key, polling_mode,"\
        "msg_no from next_msg");
    if(msg_no > 0)
    {
        sprintf(sql_find + axutil_strlen(sql_find), 
            " where msg_no=%ld", msg_no);
        add_where = AXIS2_TRUE;
    }
    if(seq_id)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where seq_id='%s'", seq_id);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and seq_id='%s'", seq_id);
    }
    if(internal_seq_id)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where internal_seq_id='%s'", internal_seq_id);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and internal_seq_id='%s'", internal_seq_id);
    }
    sprintf(sql_find + axutil_strlen(sql_find), ";");
    find_list = sandesha2_permanent_bean_mgr_find(next_msg_mgr_impl->bean_mgr, 
        env, sandesha2_next_msg_find_callback, sql_find);

    return find_list;
}

sandesha2_next_msg_bean_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_find_unique(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env,
    sandesha2_next_msg_bean_t *bean)
{
    int size = 0;
    sandesha2_next_msg_bean_t *result = NULL;
    axutil_array_list_t *find_list = NULL;
    AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);
    find_list = sandesha2_permanent_next_msg_mgr_find(next_msg_mgr, env, bean); 
    if(find_list)
        size = axutil_array_list_size(find_list, env);
    if(size == 1)
        result = (sandesha2_next_msg_bean_t *) axutil_array_list_get(
            find_list, env, 0);
    if(find_list)
        axutil_array_list_free(find_list, env);
    return result;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_next_msg_mgr_retrieve_all(
    sandesha2_next_msg_mgr_t *next_msg_mgr,
    const axutil_env_t *env)
{
    axis2_char_t *sql_find = NULL;
    sandesha2_permanent_next_msg_mgr_t *next_msg_mgr_impl = NULL;
    next_msg_mgr_impl = SANDESHA2_INTF_TO_IMPL(next_msg_mgr);
    sql_find = "select seq_id,internal_seq_id,ref_msg_key,polling_mode,"\
        "msg_no from next_msg";
    return (axutil_array_list_t *) sandesha2_next_msg_mgr_find(
        next_msg_mgr, env, NULL);
}

