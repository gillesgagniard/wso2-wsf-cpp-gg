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
 
#include "sandesha2_permanent_sender_mgr.h"
#include "sandesha2_permanent_bean_mgr.h"
#include <sandesha2_sender_mgr.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
#include <sandesha2_utils.h>
#include <sandesha2_sender_bean.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_thread.h>
#include <axutil_property.h>
#include <axutil_types.h>

/** 
 * @brief Sandesha2 Permanent Sender Manager Struct Impl
 *   Sandesha2 Permanent Sender Manager 
 */ 
typedef struct sandesha2_permanent_sender_mgr
{
    sandesha2_sender_mgr_t sender_mgr;
    sandesha2_permanent_bean_mgr_t *bean_mgr;
} sandesha2_permanent_sender_mgr_t;

#define SANDESHA2_INTF_TO_IMPL(sender_mgr) \
    ((sandesha2_permanent_sender_mgr_t *) sender_mgr)

static int 
sandesha2_sender_find_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name)
{
    int i = 0;
    sandesha2_sender_bean_t *bean = NULL;
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
    bean = sandesha2_sender_bean_create(env);
    for(i = 0; i < argc; i++)
    {
        if(0 == axutil_strcmp(col_name[i], "msg_id"))
            sandesha2_sender_bean_set_msg_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "msg_ctx_ref_key"))
            if(argv[i])
                sandesha2_sender_bean_set_msg_ctx_ref_key(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "internal_seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_internal_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "sent_count"))
            sandesha2_sender_bean_set_sent_count(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_no"))
            sandesha2_sender_bean_set_msg_no(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "send"))
            sandesha2_sender_bean_set_send(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "resend"))
            sandesha2_sender_bean_set_resend(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "time_to_send"))
            sandesha2_sender_bean_set_time_to_send(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_type"))
            sandesha2_sender_bean_set_msg_type(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "wsrm_anon_uri"))
            if(argv[i])
                sandesha2_sender_bean_set_wsrm_anon_uri(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "to_address"))
            if(argv[i])
                sandesha2_sender_bean_set_to_address(bean, env, argv[i]);
    }
    axutil_array_list_add(data_list, env, bean);
    return 0;
}

static int 
sandesha2_sender_retrieve_callback(
    void *not_used, 
    int argc, 
    char **argv, 
    char **col_name)
{
    int i = 0;
    sandesha2_bean_mgr_args_t *args = (sandesha2_bean_mgr_args_t *) not_used;
    const axutil_env_t *env = args->env;
    sandesha2_sender_bean_t *bean = (sandesha2_sender_bean_t *) args->data;
    if(argc < 1)
    {
        args->data = NULL;
        return 0;
    }
    if(!bean)
    {
        bean = sandesha2_sender_bean_create(env);
        args->data = bean;
    }
    for(i = 0; i < argc; i++)
    {
        if(0 == axutil_strcmp(col_name[i], "msg_id"))
            sandesha2_sender_bean_set_msg_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "msg_ctx_ref_key"))
            if(argv[i])
                sandesha2_sender_bean_set_msg_ctx_ref_key(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "internal_seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_internal_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "sent_count"))
            sandesha2_sender_bean_set_sent_count(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_no"))
            sandesha2_sender_bean_set_msg_no(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "send"))
            sandesha2_sender_bean_set_send(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "resend"))
            sandesha2_sender_bean_set_resend(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "time_to_send"))
            sandesha2_sender_bean_set_time_to_send(bean, env, atol(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "msg_type"))
            sandesha2_sender_bean_set_msg_type(bean, env, AXIS2_ATOI(argv[i]));
        if(0 == axutil_strcmp(col_name[i], "seq_id"))
            if(argv[i])
                sandesha2_sender_bean_set_seq_id(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "wsrm_anon_uri"))
            if(argv[i])
                sandesha2_sender_bean_set_wsrm_anon_uri(bean, env, argv[i]);
        if(0 == axutil_strcmp(col_name[i], "to_address"))
            if(argv[i])
                sandesha2_sender_bean_set_to_address(bean, env, argv[i]);
    }
    return 0;
}

void AXIS2_CALL
sandesha2_permanent_sender_mgr_free(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_insert(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_remove(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *msg_id);

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_retrieve(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *msg_id);

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_update(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean);

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_by_internal_seq_id(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *internal_seq_id);

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_by_sender_bean(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean);

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_unique(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean);

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_get_application_msg_to_send(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    const axis2_char_t *seq_id,
    const axis2_char_t *msg_id);

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_get_next_msg_to_send(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    const axis2_char_t *seq_id);

static const sandesha2_sender_mgr_ops_t sender_mgr_ops = 
{
    sandesha2_permanent_sender_mgr_free,
    sandesha2_permanent_sender_mgr_insert,
    sandesha2_permanent_sender_mgr_remove,
    sandesha2_permanent_sender_mgr_retrieve,
    sandesha2_permanent_sender_mgr_update,
    sandesha2_permanent_sender_mgr_find_by_internal_seq_id,
    sandesha2_permanent_sender_mgr_find_by_sender_bean,
    sandesha2_permanent_sender_mgr_find_unique,
    sandesha2_permanent_sender_mgr_get_application_msg_to_send,
    sandesha2_permanent_sender_mgr_get_next_msg_to_send
};

AXIS2_EXTERN sandesha2_sender_mgr_t * AXIS2_CALL
sandesha2_permanent_sender_mgr_create(
    const axutil_env_t *env,
    axis2_char_t *dbname)
{
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
    
    sender_mgr_impl = AXIS2_MALLOC(env->allocator, 
        sizeof(sandesha2_permanent_sender_mgr_t));

    sender_mgr_impl->bean_mgr = sandesha2_permanent_bean_mgr_create(env,
        dbname, SANDESHA2_BEAN_MAP_RETRANSMITTER);
    sender_mgr_impl->sender_mgr.ops = sender_mgr_ops;
    return &(sender_mgr_impl->sender_mgr);
}

void AXIS2_CALL
sandesha2_permanent_sender_mgr_free(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env)
{
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    if(sender_mgr_impl->bean_mgr)
    {
        sandesha2_permanent_bean_mgr_free(sender_mgr_impl->bean_mgr, env);
        sender_mgr_impl->bean_mgr = NULL;
    }
    if(sender_mgr_impl)
    {
        AXIS2_FREE(env->allocator, sender_mgr_impl);
        sender_mgr_impl = NULL;
    }
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_insert(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean)
{
    axis2_char_t sql_insert[1024];
    axis2_bool_t ret = AXIS2_FALSE;
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
	axis2_char_t *msg_id = NULL;
    axis2_char_t *msg_ctx_ref_key = NULL;
	axis2_char_t *internal_seq_id  = NULL;
	int sent_count =0;
	long msg_no = 0;
	axis2_bool_t send = AXIS2_FALSE;
	axis2_bool_t resend = AXIS2_FALSE;
	long time_to_send = 0;
	int msg_type = 0;
	axis2_char_t *seq_id = NULL;
	axis2_char_t *wsrm_anon_uri = NULL;
	axis2_char_t *to_address = NULL;

	AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);

    msg_id = sandesha2_sender_bean_get_msg_id(bean, env);
	msg_ctx_ref_key = sandesha2_sender_bean_get_msg_ctx_ref_key(bean, env);
	internal_seq_id = sandesha2_sender_bean_get_internal_seq_id(bean, env);
	sent_count = sandesha2_sender_bean_get_sent_count(bean, env);
	msg_no = sandesha2_sender_bean_get_msg_no(bean, env);
	send = sandesha2_sender_bean_is_send(bean, env);
	resend = sandesha2_sender_bean_is_resend(bean, env);
	time_to_send = sandesha2_sender_bean_get_time_to_send(bean, env);
	msg_type = sandesha2_sender_bean_get_msg_type(bean, env);
	seq_id = sandesha2_sender_bean_get_seq_id(bean, env);
	wsrm_anon_uri = sandesha2_sender_bean_get_wsrm_anon_uri(bean, env);
    to_address = sandesha2_sender_bean_get_to_address(bean, env);

    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    sprintf(sql_insert, "insert into sender(msg_id, msg_ctx_ref_key,"\
        "internal_seq_id, sent_count, msg_no, send, resend, time_to_send,"\
        "msg_type, seq_id, wsrm_anon_uri, to_address) values('%s', '%s', '%s',"\
        "%d, %ld, %d, %d, %ld, %d, '%s', '%s', '%s');", msg_id, msg_ctx_ref_key, 
        internal_seq_id, sent_count, msg_no, send, resend, time_to_send, 
        msg_type, seq_id, wsrm_anon_uri, to_address);

    ret = sandesha2_permanent_bean_mgr_insert(sender_mgr_impl->bean_mgr, env, sql_insert);

    return ret;
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_remove(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *msg_id)
{
    axis2_char_t sql_remove[256];
    axis2_bool_t ret = AXIS2_FALSE;
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Entry:sandesha2_permanent_sender_mgr_remove");
    AXIS2_PARAM_CHECK(env->error, msg_id, AXIS2_FALSE);
    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);
    sprintf(sql_remove, "delete from sender where msg_id='%s'", msg_id);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sql_remove:%s", sql_remove);
    ret = sandesha2_permanent_bean_mgr_remove(sender_mgr_impl->bean_mgr, env,
        sql_remove);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI,  
        "[sandesha2]Exit:sandesha2_permanent_sender_mgr_remove");
    return ret;
}

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_retrieve(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *msg_id)
{
    axis2_char_t sql_retrieve[256];
    sandesha2_sender_bean_t *ret = NULL;
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;

    AXIS2_PARAM_CHECK(env->error, msg_id, AXIS2_FALSE);
    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    sprintf(sql_retrieve, "select msg_id, msg_ctx_ref_key, "\
        "internal_seq_id, sent_count, msg_no, send, resend, time_to_send, "\
        "msg_type, seq_id, wsrm_anon_uri, to_address from sender "\
        "where msg_id='%s'", msg_id);
    ret = (sandesha2_sender_bean_t *) sandesha2_permanent_bean_mgr_retrieve(
        sender_mgr_impl->bean_mgr, env, sandesha2_sender_retrieve_callback, 
        sql_retrieve);

    return ret;
}

axis2_bool_t AXIS2_CALL
sandesha2_permanent_sender_mgr_update(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean)
{
    axis2_char_t sql_update[1024];
    axis2_bool_t ret = AXIS2_FALSE;
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
	axis2_char_t *msg_id = NULL;
	axis2_char_t *msg_ctx_ref_key = NULL;
	axis2_char_t *internal_seq_id = NULL;
	int sent_count = 0;
	long msg_no = 0;
	axis2_bool_t resend = AXIS2_FALSE;
	axis2_bool_t send = AXIS2_FALSE;
	long time_to_send = 0;
	int msg_type = 0;
	axis2_char_t *seq_id = NULL;
	axis2_char_t *wsrm_anon_uri  = NULL;
	axis2_char_t *to_address = NULL;

    AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);

    msg_id = sandesha2_sender_bean_get_msg_id(bean, env);
    msg_ctx_ref_key = sandesha2_sender_bean_get_msg_ctx_ref_key(bean, env);
    internal_seq_id = sandesha2_sender_bean_get_internal_seq_id(bean, env);
	sent_count= sandesha2_sender_bean_get_sent_count(bean, env);
	msg_no = sandesha2_sender_bean_get_msg_no(bean, env);
	send = sandesha2_sender_bean_is_send(bean, env);
	resend = sandesha2_sender_bean_is_resend(bean, env);
	time_to_send = sandesha2_sender_bean_get_time_to_send(bean, env);
	msg_type = sandesha2_sender_bean_get_msg_type(bean, env);
	seq_id = sandesha2_sender_bean_get_seq_id(bean, env);
    wsrm_anon_uri = sandesha2_sender_bean_get_wsrm_anon_uri(bean, env);
    to_address = sandesha2_sender_bean_get_to_address(bean, env);

    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    sprintf(sql_update, "update sender set msg_ctx_ref_key='%s'"\
        ", internal_seq_id='%s', sent_count=%d, msg_no=%ld, send=%d"\
        ", resend=%d, time_to_send=%ld, msg_type=%d, seq_id='%s'"\
        ", wsrm_anon_uri='%s', to_address='%s' where msg_id='%s';",
        msg_ctx_ref_key, internal_seq_id, sent_count, msg_no, send, resend,
        time_to_send, msg_type, seq_id, wsrm_anon_uri, to_address, msg_id);

    ret = sandesha2_permanent_bean_mgr_update(sender_mgr_impl->bean_mgr, env, 
        sql_update);

    return ret;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_by_internal_seq_id(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    axis2_char_t *internal_seq_id)
{
    axutil_array_list_t *find_list = NULL;
    axis2_char_t sql_find[1054];
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;

    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);
    
    sprintf(sql_find, "select msg_id, msg_ctx_ref_key, internal_seq_id, "\
        "sent_count, msg_no, send, resend, time_to_send, msg_type, seq_id, "\
        "wsrm_anon_uri, to_address from sender where internal_seq_id='%s';", 
        internal_seq_id);

    find_list = sandesha2_permanent_bean_mgr_find(sender_mgr_impl->bean_mgr, env, 
        sandesha2_sender_find_callback, sql_find);

    return find_list;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_by_sender_bean(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean)
{
    axis2_bool_t add_where = AXIS2_FALSE;
    axis2_char_t *msg_id = NULL;
	axis2_char_t *msg_ctx_ref_key = NULL;
	axis2_char_t *internal_seq_id = NULL;
	axis2_char_t *seq_id = NULL;
	long msg_no = 0;
	axis2_bool_t send = AXIS2_FALSE;
	long time_to_send = 0;
	int msg_type = 0;
    axutil_array_list_t *find_list = NULL;
    axis2_char_t sql_find[1024];
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;

    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    if(bean)
    {
        msg_id = sandesha2_sender_bean_get_msg_id(bean, 
            env);
        msg_ctx_ref_key = sandesha2_sender_bean_get_msg_ctx_ref_key(bean, env);
        internal_seq_id = sandesha2_sender_bean_get_internal_seq_id(bean, env);
        seq_id = sandesha2_sender_bean_get_seq_id(bean, env);
        msg_no = sandesha2_sender_bean_get_msg_no(bean, env);
        send = sandesha2_sender_bean_is_send(bean, env);
        time_to_send = sandesha2_sender_bean_get_time_to_send(bean, env);
        msg_type = sandesha2_sender_bean_get_msg_type(bean, env);
    }
    sprintf(sql_find, "select msg_id, msg_ctx_ref_key, internal_seq_id,"\
        "sent_count, msg_no, send, resend, time_to_send, msg_type, seq_id, "\
        "wsrm_anon_uri, to_address from sender");
    if(msg_ctx_ref_key)
    {
        sprintf(sql_find + axutil_strlen(sql_find), 
            " where msg_ctx_ref_key='%s'", msg_ctx_ref_key);
        add_where = AXIS2_TRUE;
    }
    if(time_to_send > 0)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where time_to_send <= %ld", time_to_send);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and time_to_send <= %ld", time_to_send);
    }
    if(msg_id)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where msg_id = '%s'", msg_id);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and msg_id = '%s'", msg_id);
    }

    if(internal_seq_id)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), " where internal_seq_id = '%s'", 
                    internal_seq_id);
        }
        else
        {
            sprintf(sql_find + axutil_strlen(sql_find), " and internal_seq_id = '%s'", 
                    internal_seq_id);
        }
    }
    
    if(seq_id)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), " where seq_id = '%s'", seq_id);
        }
        else
        {
            sprintf(sql_find + axutil_strlen(sql_find), " and seq_id = '%s'", seq_id);
        }
    }

    if(msg_no > 0)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where msg_no = %ld", msg_no);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and msg_no = %ld", msg_no);
    }
    if(msg_type != SANDESHA2_MSG_TYPE_UNKNOWN)
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where  msg_type= %d", msg_type);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and msg_type = %d", msg_type);
    }
    {
        if(!add_where)
        {
            add_where = AXIS2_TRUE;
            sprintf(sql_find + axutil_strlen(sql_find), 
                " where send = %d", send);
        }
        else
            sprintf(sql_find + axutil_strlen(sql_find),
                " and  send = %d", send);
    }

    sprintf(sql_find + axutil_strlen(sql_find), ";");

    find_list = sandesha2_permanent_bean_mgr_find(sender_mgr_impl->bean_mgr, env, 
        sandesha2_sender_find_callback, sql_find);

    return find_list;
}

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_find_unique(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    sandesha2_sender_bean_t *bean)
{
    int size = 0;
    sandesha2_sender_bean_t *result = NULL;
    axutil_array_list_t *find_list = NULL;
    AXIS2_PARAM_CHECK(env->error, bean, AXIS2_FALSE);
    find_list = sandesha2_permanent_sender_mgr_find_by_sender_bean(sender_mgr, 
        env, bean);
    if(find_list)
        size = axutil_array_list_size(find_list, env);
    if(size == 1)
       result = (sandesha2_sender_bean_t *) axutil_array_list_get(find_list, 
           env, 0);
    if(find_list)
        axutil_array_list_free(find_list, env);
    return result; 
}

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_get_application_msg_to_send(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    const axis2_char_t *seq_id,
    const axis2_char_t *msg_id)
{
    int i = 0;
    int index = 0;
    int match_list_size = 0;
    axutil_array_list_t *match_list = NULL;
    axis2_char_t sql_find[1024];
    /*long time_now = 0;*/
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
    sandesha2_sender_bean_t *result = NULL;

    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    sprintf(sql_find, "select msg_id, msg_ctx_ref_key, "\
        "internal_seq_id, sent_count, msg_no, send, resend, "\
        "time_to_send, msg_type, seq_id, wsrm_anon_uri, "\
        "to_address from sender where ");

    /*time_now = sandesha2_utils_get_current_time_in_millis(env);
    if(time_now > 0)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "time_to_send <= %ld ", time_now);
    }*/
    
    sprintf(sql_find + axutil_strlen(sql_find), "msg_type='%d'", SANDESHA2_MSG_TYPE_APPLICATION);

    if(seq_id)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "and internal_seq_id='%s'", seq_id);
    }
    
    if(msg_id)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "and msg_id='%s'", msg_id);
    }
        
    sprintf(sql_find + axutil_strlen(sql_find), " and send='%d'", AXIS2_TRUE);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sql_find:%s", sql_find);  

    match_list = sandesha2_permanent_bean_mgr_find(sender_mgr_impl->bean_mgr, env, 
            sandesha2_sender_find_callback, sql_find);
    match_list_size = axutil_array_list_size(match_list, env);

    /*
     * We carry on through the application message list to be sure that we send the lowest application 
     * message avaliable.
     */
    for(i = 0; i < match_list_size; i++)
    {
        sandesha2_sender_bean_t *bean = NULL;
        long result_msg_no = -1;
        long msg_no = -1;

        bean = (sandesha2_sender_bean_t *) axutil_array_list_get(match_list, env, i);
        
        msg_no = sandesha2_sender_bean_get_msg_no(bean, env);

        if(result)
        {
            result_msg_no = sandesha2_sender_bean_get_msg_no(result, env);
        }

        if(!result || result_msg_no > msg_no)
        {
            result = bean;
            index = i;
        }
    }

    result = axutil_array_list_remove(match_list, env, index);
    if(match_list)
    {
        int j = 0, sizej = 0;

        sizej = axutil_array_list_size(match_list, env);
        for(j = 0; j < sizej; j++)
        {
            sandesha2_sender_bean_t *temp_bean = NULL;
            temp_bean = axutil_array_list_get(match_list, env, j);
            sandesha2_sender_bean_free(temp_bean, env);
        }

        axutil_array_list_free(match_list, env);
    }

    return result;
}

sandesha2_sender_bean_t *AXIS2_CALL
sandesha2_permanent_sender_mgr_get_next_msg_to_send(
    sandesha2_sender_mgr_t *sender_mgr,
    const axutil_env_t *env,
    const axis2_char_t *seq_id)
{
    int i = 0;
    int index = 0;
    int match_list_size = 0;
    axutil_array_list_t *match_list = NULL;
    axis2_char_t sql_find[1024];
    long time_now = 0;
    sandesha2_permanent_sender_mgr_t *sender_mgr_impl = NULL;
    sandesha2_sender_bean_t *result = NULL;
    axis2_bool_t send_make_connection = AXIS2_TRUE;


    sender_mgr_impl = SANDESHA2_INTF_TO_IMPL(sender_mgr);

    sprintf(sql_find, "select msg_id, msg_ctx_ref_key, "\
        "internal_seq_id, sent_count, msg_no, send, resend, "\
        "time_to_send, msg_type, seq_id, wsrm_anon_uri, "\
        "to_address from sender where ");

    time_now = sandesha2_utils_get_current_time_in_millis(env);
    if(time_now > 0)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "time_to_send <= %ld ", time_now);
    }

    if(seq_id)
    {
        sprintf(sql_find + axutil_strlen(sql_find), "and internal_seq_id='%s'", seq_id);
    }

    sprintf(sql_find + axutil_strlen(sql_find), " and send=%d", AXIS2_TRUE);

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "sql_find:%s", sql_find);  

    match_list = sandesha2_permanent_bean_mgr_find(sender_mgr_impl->bean_mgr, env, 
            sandesha2_sender_find_callback, sql_find);
    match_list_size = axutil_array_list_size(match_list, env);

    /*
     * We either return an application message or an RM message. If we find
     * an application message first then we carry on through the list to be
     * sure that we send the lowest app message avaliable. If we hit a RM
     * message first then we are done.
     */
    for(i = 0; i < match_list_size; i++)
    {
        sandesha2_sender_bean_t *bean = NULL;

        int msg_type = -1;

        bean = (sandesha2_sender_bean_t *) axutil_array_list_get(match_list, env, i);
        msg_type = sandesha2_sender_bean_get_msg_type(bean, env);
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2]msg_type:%d", msg_type);
        if(msg_type == SANDESHA2_MSG_TYPE_ACK)
        {
            continue;
        }

        else if(msg_type == SANDESHA2_MSG_TYPE_MAKE_CONNECTION_MSG)
        {
            if(send_make_connection)
            {
                result = bean;
                index = i;
                send_make_connection = AXIS2_TRUE;
            }
        }
        else if(!result || send_make_connection)
        {
            result = bean;
            index = i;
            send_make_connection = AXIS2_FALSE;
        }
    }

    result = axutil_array_list_remove(match_list, env, index);
    if(match_list)
    {
        int j = 0, sizej = 0;

        sizej = axutil_array_list_size(match_list, env);
        for(j = 0; j < sizej; j++)
        {
            sandesha2_sender_bean_t *temp_bean = NULL;
            temp_bean = axutil_array_list_get(match_list, env, j);
            sandesha2_sender_bean_free(temp_bean, env);
        }

        axutil_array_list_free(match_list, env);
    }

    return result;
}

