
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

#include <stdio.h>
#include <axis2_const.h>
#include <axutil_error.h>
#include <axutil_utils_defines.h>
#include <axutil_utils.h>
#include <axutil_env.h>
#include <axutil_string.h>
#include <axutil_array_list.h>
#include <axiom_element.h>
#include <axiom_children_iterator.h>
#include <axiom_document.h>
#include <axiom_comment.h>
#include <oxs_constants.h>
#include <oxs_c14n.h>
#include "c14n_sorted_list.h"

#define N_C14N_DEBUG

#define DEFAULT_STACK_SIZE 16
#define INIT_BUFFER_SIZE 1024

#define c14n_ns_stack_push(save_stack, ctx) \
        (save_stack)->head = (ctx)->ns_stack->head; \
        (save_stack)->def_ns = (ctx)->ns_stack->def_ns;

#define c14n_ns_stack_pop(saved_stack, ctx) \
    (ctx)->ns_stack->head = (saved_stack)->head; \
    (ctx)->ns_stack->def_ns = (saved_stack)->def_ns;

#define c14n_ns_stack_set_default(ns, ctx) \
        ((ctx)->ns_stack->def_ns = (ns))

#define c14n_ns_stack_get_default(ctx) \
        ((ctx)->ns_stack->def_ns)

#define C14N_GET_ROOT_NODE_FROM_DOC_OR_NODE(doc, node, ctx) \
    ((doc) ? axiom_document_get_root_element((axiom_document_t *)(doc), \
        (ctx)->env) : c14n_get_root_node((node), (ctx)))

typedef enum {
    C14N_XML_C14N = 1,
    C14N_XML_C14N_WITH_COMMENTS,
    C14N_XML_EXC_C14N,
    C14N_XML_EXC_C14N_WITH_COMMENTS,
} c14n_algo_t;

typedef struct c14n_ns_stack {
    int head; /*index of the currnt stack TOP*/
    int size; /*total size allocated for current stack*/
    axiom_namespace_t **stack; /*namespace array*/
    axiom_namespace_t *def_ns; /*default ns in current scope*/
} c14n_ns_stack_t;

typedef struct c14n_buffer
{
    /* Required to manipulate multiple buffers */
    size_t *buffs_size;         /* Array containing actual sizes of buffers */
    axis2_char_t **buff;        /* Array of buffers */
    int cur_buff_index;         /* Current buffer */
    int cur_buff_pos;           /* Position of the current buffer */
    unsigned int no_buffers;    /* No of buffers */

    axis2_char_t *cur_buff;     /* current buffer; kept separately for performance */
    int cur_buff_size;          /* kept separately for performance */
} c14n_buffer_t;

typedef struct c14n_ctx {
    const axutil_env_t *env;
    axiom_document_t *doc;
    axis2_bool_t comments;
    c14n_buffer_t *outbuffer;
    axis2_bool_t exclusive;
    axutil_array_list_t *ns_prefixes;
    axiom_node_t *node;
    c14n_ns_stack_t *ns_stack;
} c14n_ctx_t;

/*Function prototypes for ns stack*/
static c14n_ns_stack_t*
c14n_ns_stack_create(
    const c14n_ctx_t *ctx
);

static void
c14n_ns_stack_free(
    c14n_ctx_t *ctx
);

static axis2_status_t
c14n_ns_stack_find(
    axiom_namespace_t *ns,
    c14n_ctx_t *ctx
);

static axis2_status_t
c14n_ns_stack_add(
    axiom_namespace_t *ns,
    const c14n_ctx_t *ctx
);

/*ns stack implementation*/

static c14n_ns_stack_t*
c14n_ns_stack_create(
    const c14n_ctx_t *ctx)
{
    c14n_ns_stack_t *ns_stack = NULL;
    ns_stack = (c14n_ns_stack_t *) (AXIS2_MALLOC(ctx->env->allocator, sizeof(c14n_ns_stack_t)));
    if(!ns_stack)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(ctx->env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n ns stack. Insufficient memory");
        return NULL;
    }

    ns_stack->head = 0;
    ns_stack->size = 0;
    ns_stack->stack = NULL;
    ns_stack->def_ns = NULL;
    return ns_stack;
}

static axis2_status_t
c14n_ns_stack_add(
    axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    c14n_ns_stack_t *ns_stack = ctx->ns_stack;

    if(!ns_stack->stack)
    {
        ns_stack->stack = (axiom_namespace_t **) (AXIS2_MALLOC(ctx->env->allocator,
            sizeof(axiom_namespace_t*) * DEFAULT_STACK_SIZE));
        if(!ns_stack->stack)
        {
            AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
        else
            ns_stack->size = DEFAULT_STACK_SIZE;
    }
    else if(ns_stack->head >= ns_stack->size)
    {
        int size = 2 * ns_stack->size;
        axiom_namespace_t **tmp_stack = (axiom_namespace_t **) (AXIS2_MALLOC(ctx->env->allocator,
            sizeof(axiom_namespace_t*) * size));
        if(tmp_stack)
        {
            /*int i = 0;*/
            /* TODO:DONE use memcpy for this.*/
            /*for (i=0; i<ns_stack->size; i++)
             tmp_stack[i] = (ns_stack->stack)[i];*/
            memcpy(tmp_stack, ns_stack, sizeof(axiom_namespace_t*) * ns_stack->size);

            ns_stack->size = size;

            AXIS2_FREE(ctx->env->allocator, ns_stack->stack);
            ns_stack->stack = tmp_stack;
        }
        else
        {
            AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
    }

    /*if memory overflow occur we won't be here*/
    (ns_stack->stack)[ns_stack->head] = ns;
    (ns_stack->head)++;

    return AXIS2_SUCCESS;
}

/*
 * Find process should  find if the ns has the same prefix but diff uri
 * Eg: <a xmlns:x="a">
 *      <b xmlns:x="b">
 *       <c xmlns:x="a"/>
 *      </b>
 *     </a>
 * */
static axis2_status_t
c14n_ns_stack_find(
    axiom_namespace_t *ns,
    c14n_ctx_t *ctx)
{
    axis2_char_t *prefix = axiom_namespace_get_prefix(ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri(ns, ctx->env);
    int i;
    c14n_ns_stack_t *ns_stack = ctx->ns_stack;
    if(ns_stack->stack) /*Is this necessary?*/
    {
        for(i = ns_stack->head - 1; i >= 0; i--)
        {
            axis2_char_t *prefix_i = axiom_namespace_get_prefix((ns_stack->stack)[i], ctx->env);

            if(axutil_strcmp(prefix_i, prefix) == 0)
            {
                axis2_char_t *uri_i = axiom_namespace_get_uri((ns_stack->stack)[i], ctx->env);
                if(axutil_strcmp(uri_i, uri) == 0)
                    return AXIS2_SUCCESS;
                else
                    return AXIS2_FAILURE;
            }
            else
                continue;

        }
    }
    return AXIS2_FAILURE;
}

static void
c14n_ns_stack_free(
    c14n_ctx_t *ctx)
{
    if(ctx->ns_stack->stack)
    {
        AXIS2_FREE(ctx->env->allocator, ctx->ns_stack->stack);
    }
    AXIS2_FREE(ctx->env->allocator, ctx->ns_stack);
    ctx->ns_stack = NULL;
}

static c14n_buffer_t *
c14n_buffer_create(
    const axutil_env_t *env)
{
    c14n_buffer_t *buffer = (c14n_buffer_t *)AXIS2_MALLOC(env->allocator, sizeof(c14n_buffer_t));
    if(!buffer)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot create c14n_buffer structure. Insufficient memory");
        return NULL;
    }

    buffer->buffs_size = (size_t *)AXIS2_MALLOC(env->allocator, sizeof(size_t) * DEFAULT_STACK_SIZE);
    if(!buffer->buffs_size)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot create c14n_buffer size array structure. Insufficient memory");
        AXIS2_FREE(env->allocator, buffer);
        return NULL;
    }

    buffer->buff = (axis2_char_t **)
        AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t *) * DEFAULT_STACK_SIZE);
    if(!buffer->buff)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot create c14n_buffer array structure. Insufficient memory");
        AXIS2_FREE(env->allocator, buffer);
        AXIS2_FREE(env->allocator, buffer->buffs_size);
        return NULL;
    }

    buffer->buff[0] = (axis2_char_t *)
        AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t) * INIT_BUFFER_SIZE);
    if(!buffer->buff[0])
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Cannot create c14n buffer. Insufficient memory");
        AXIS2_FREE(env->allocator, buffer);
        AXIS2_FREE(env->allocator, buffer->buffs_size);
        AXIS2_FREE(env->allocator, buffer->buff);
        return NULL;
    }

    buffer->cur_buff = buffer->buff[0];
    buffer->cur_buff_pos = 0;
    buffer->no_buffers = DEFAULT_STACK_SIZE;
    buffer->buffs_size[0] = INIT_BUFFER_SIZE;
    buffer->cur_buff_index = 0;
    buffer->cur_buff_size = INIT_BUFFER_SIZE;

    return buffer;
}

static void
c14n_create_new_buffer(
    c14n_buffer_t * buffer,
    const axutil_env_t *env,
    int length)
{
    int curr_buff = buffer->cur_buff_index;
    int buff_size = buffer->cur_buff_size * 2;
    while(length > buff_size)
    {
        buff_size *= 2;
    }
    if(curr_buff == buffer->no_buffers - 1)
    {
        axis2_char_t ** temp_buff = NULL;
        size_t *temp_size = NULL;
        int i = 0;
        int buffer_size = buffer->no_buffers * 2;

        temp_buff = (axis2_char_t **)
            AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t *) * buffer_size);
        if(!temp_buff)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Insufficient memory to create buffer");
            return;
        }

        temp_size = (size_t *)AXIS2_MALLOC(env->allocator, sizeof(size_t) * buffer_size);
        if(!temp_size)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Insufficient memory to create buffer");
            return;
        }

        for(i = 0; i <= curr_buff; ++i)
        {
            temp_buff[i] = buffer->buff[i];
            temp_size[i] = buffer->buffs_size[i];
        }

        AXIS2_FREE(env->allocator, buffer->buff);
        AXIS2_FREE(env->allocator, buffer->buffs_size);
        buffer->no_buffers = buffer_size;
        buffer->buff = temp_buff;
        buffer->buffs_size = temp_size;
    }

    buffer->buff[++curr_buff] = (axis2_char_t *)
        AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t) * buff_size);
    if(!buffer->buff[curr_buff])
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Insufficient memory to create buffer");
        return;
    }

    ++(buffer->cur_buff_index);
    buffer->buffs_size[curr_buff] = buff_size;
    buffer->cur_buff_pos = 0;
    buffer->cur_buff = buffer->buff[curr_buff];
    buffer->cur_buff_size = buff_size;
}

static int
c14_buffer_get_total_data_size(
    c14n_buffer_t *buffer,
    const axutil_env_t *env)
{
    int i = 0;
    int length = 0;
    int cur_buff = buffer->cur_buff_index;
    for(i = 0; i < cur_buff; ++i)
    {
        length += buffer->buffs_size[i];
    }

    length += buffer->cur_buff_pos;
    return length;
}

static void
c14n_buffer_copy_data(
    c14n_buffer_t *buffer,
    const axutil_env_t *env,
    axis2_char_t *output)
{
    int i = 0;
    int cur_buff = buffer->cur_buff_index;
    for(i = 0; i < cur_buff; ++i)
    {
        memcpy(output, buffer->buff[i], buffer->buffs_size[i]);
        output += buffer->buffs_size[i];
    }

    memcpy(output, buffer->buff[cur_buff], buffer->cur_buff_pos);
}

static void
c14n_buffer_free(
    c14n_buffer_t *buffer,
    const axutil_env_t *env)
{
    int i = 0;
    int cur_buff = buffer->cur_buff_index;
    for(i = 0; i <= cur_buff; ++i)
    {
        AXIS2_FREE(env->allocator, buffer->buff[i]);
    }
    AXIS2_FREE(env->allocator, buffer->buff);
    AXIS2_FREE(env->allocator, buffer->buffs_size);
    AXIS2_FREE(env->allocator, buffer);
}

#define C14N_BUFFER_ADD_CHAR(buffer, env, ch)\
{\
    int cur_buff_pos = buffer->cur_buff_pos++;\
    if(cur_buff_pos == buffer->cur_buff_size)\
    {\
        c14n_create_new_buffer(buffer, env, 0);\
        cur_buff_pos = buffer->cur_buff_pos++;\
    }\
\
    buffer->cur_buff[cur_buff_pos] = ch;\
}

#define C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, str, length)\
{\
    int diff = buffer->cur_buff_size - buffer->cur_buff_pos;\
    if(length <= diff)\
    {\
        memcpy(buffer->cur_buff + buffer->cur_buff_pos, str, length);\
        buffer->cur_buff_pos += length;\
    }\
    else\
    {\
        memcpy(buffer->cur_buff + buffer->cur_buff_pos, str, diff);\
        c14n_create_new_buffer(buffer, env, length - diff);\
        memcpy(buffer->cur_buff, str + diff, length-diff);\
        buffer->cur_buff_pos = length - diff;\
    }\
}

#define C14N_BUFFER_ADD_STRING(buffer, env, str)\
{\
    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, str, axutil_strlen(str));\
}

/* Function Prototypes */

static axis2_status_t
c14n_apply_on_element(
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_namespace_axis(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_namespace_axis_exclusive(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_attribute_axis(
    const axiom_element_t *ele,
    const c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_node(
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static void
c14n_apply_on_comment(
    axiom_node_t *node,
    c14n_buffer_t *buffer,
    const axutil_env_t *env);

static int
attr_compare(
    const void *a1,
    const void *a2,
    const void *context);

static int
ns_prefix_compare(
    const void *ns1,
    const void *ns2,
    const void *context);

static int
ns_uri_compare(
    const void *ns1,
    const void *ns2,
    const void *context);

static void
c14n_add_normalize_attribute(
    axis2_char_t *attval,
    c14n_ctx_t *ctx);

static void
c14n_add_normalize_text(
    axis2_char_t *text,
    c14n_ctx_t *ctx);

static void
c14n_apply_on_namespace(
    const void *ns,
    const void *ctx);

static axis2_bool_t
c14n_need_to_declare_ns(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axis2_bool_t
c14n_ns_visibly_utilized(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axis2_bool_t
c14n_no_output_ancestor_uses_prefix(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axiom_node_t*
c14n_get_root_node(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx);

static c14n_algo_t
c14n_get_algorithm(
    const axis2_char_t* algo);

/*static axis2_bool_t
c14n_in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx
    );
*/

/* Implementations */

static void
c14n_ctx_free(
    c14n_ctx_t *ctx)
{
    c14n_ns_stack_free(ctx);
    AXIS2_FREE(ctx->env->allocator, ctx);
}

static c14n_ctx_t*
c14n_init(
    const axutil_env_t *env,
    axiom_document_t *doc,
    axis2_bool_t comments,
    c14n_buffer_t *outbuffer,
    axis2_bool_t exclusive,
    axutil_array_list_t *ns_prefixes,
    axiom_node_t *node)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) (AXIS2_MALLOC(env->allocator, sizeof(c14n_ctx_t)));
    if(!ctx)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n structure. Insufficient memory");
        return NULL;
    }
    ctx->env = env;
    ctx->doc = doc;
    ctx->comments = comments;
    ctx->exclusive = exclusive;
    ctx->ns_prefixes = ns_prefixes;
    ctx->node = node;
    ctx->outbuffer = outbuffer;
    ctx->ns_stack = c14n_ns_stack_create(ctx);
    if(!ctx->ns_stack)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n strucure. ns stack creation failed");
        AXIS2_FREE(env->allocator, ctx);
        ctx = NULL;
    }
    return ctx;
}

/*static axis2_bool_t
c14n_in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx
    )
{
    
    return AXIS2_SUCCESS;
}*/

static axiom_node_t*
c14n_get_root_node(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx)
{
    const axiom_node_t *parent = NULL;
    const axiom_node_t *prv_parent = NULL;

    parent = node;
    while(parent)
    {
        prv_parent = parent;
        parent = axiom_node_get_parent((axiom_node_t *) parent, ctx->env);
    }
    return (axiom_node_t *) prv_parent;
}

static c14n_algo_t
c14n_get_algorithm(
    const axis2_char_t* algo)
{
    if(axutil_strcmp(algo, OXS_HREF_XML_C14N) == 0)
        return C14N_XML_C14N;

    if(axutil_strcmp(algo, OXS_HREF_XML_C14N_WITH_COMMENTS) == 0)
        return C14N_XML_C14N_WITH_COMMENTS;

    if(axutil_strcmp(algo, OXS_HREF_XML_EXC_C14N) == 0)
        return C14N_XML_EXC_C14N;

    if(axutil_strcmp(algo, OXS_HREF_XML_EXC_C14N_WITH_COMMENTS) == 0)
        return C14N_XML_EXC_C14N_WITH_COMMENTS;

    return 0; /*c14n_algo_t enum starts with 1*/
}

static axis2_status_t
oxs_c14n_apply_stream(
    const axutil_env_t *env,
    axiom_document_t *doc,
    axis2_bool_t comments,
    c14n_buffer_t *outbuffer,
    axis2_bool_t exclusive,
    axutil_array_list_t *ns_prefixes,
    axiom_node_t *node)
{
    c14n_ctx_t *ctx = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    if(!outbuffer)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]outbuffer is not given to do c14n");
        return AXIS2_FAILURE;
    }

    ctx = c14n_init(env, doc, comments, outbuffer, exclusive, ns_prefixes, node);
    if(!ctx)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] c14n structure creating failed");
        return AXIS2_FAILURE;
    }

    if(!node)
    {
        node = C14N_GET_ROOT_NODE_FROM_DOC_OR_NODE(doc, node, ctx);
        if(!node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]cannot find node to apply c14n");
            return AXIS2_FAILURE;
        }
    }

    status = c14n_apply_on_node(node, ctx);
    c14n_ctx_free(ctx);
    return status;
}

static axis2_status_t
oxs_c14n_apply(
    const axutil_env_t *env,
    axiom_document_t *doc,
    axis2_bool_t comments,
    axis2_char_t **outbuf,
    axis2_bool_t exclusive,
    axutil_array_list_t *ns_prefixes,
    axiom_node_t *node)
{
    c14n_buffer_t *outbuffer = c14n_buffer_create(env);
    if(oxs_c14n_apply_stream(env, doc, comments, outbuffer, exclusive, ns_prefixes, node)
        == AXIS2_SUCCESS)
    {
        int len = c14_buffer_get_total_data_size(outbuffer, env);
        if(len > 0)
        {
            *outbuf = (axis2_char_t *)AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t) * len + 1);
            c14n_buffer_copy_data(outbuffer, env, *outbuf);
            (*outbuf)[len] = '\0';
            c14n_buffer_free(outbuffer, env);
            return AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]invalid c14n output length");
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]applying c14n failed");
    }
    c14n_buffer_free(outbuffer, env);
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_c14n_apply_algo(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axis2_char_t **outbuf,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node,
    const axis2_char_t *algo)
{
    axiom_document_t *pdoc = (axiom_document_t *)doc;
    axutil_array_list_t *pns_prefixes = (axutil_array_list_t *)ns_prefixes;
    axiom_node_t *pnode = (axiom_node_t *)node;
    switch(c14n_get_algorithm(algo))
    {
        case C14N_XML_C14N:
            return oxs_c14n_apply(env, pdoc, AXIS2_FALSE, outbuf, AXIS2_FALSE, pns_prefixes, pnode);
        case C14N_XML_C14N_WITH_COMMENTS:
            return oxs_c14n_apply(env, pdoc, AXIS2_TRUE, outbuf, AXIS2_FALSE, pns_prefixes, pnode);
        case C14N_XML_EXC_C14N:
            return oxs_c14n_apply(env, pdoc, AXIS2_FALSE, outbuf, AXIS2_TRUE, pns_prefixes, pnode);
        case C14N_XML_EXC_C14N_WITH_COMMENTS:
            return oxs_c14n_apply(env, pdoc, AXIS2_TRUE, outbuf, AXIS2_TRUE, pns_prefixes, pnode);
        default:
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Invalid c14n algorithm [%s]", algo);
            return AXIS2_FAILURE;
    }
}

static axis2_status_t
c14n_apply_on_text(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    const axutil_env_t *env = ctx->env;
    axiom_text_t *text = (axiom_text_t *) axiom_node_get_data_element(node, env);

    if(text)
    {
        axis2_char_t *textval = (axis2_char_t*) axiom_text_get_text(text, env);
        if(!textval)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]cannot get text from node");
            return AXIS2_FAILURE;
        }

        c14n_add_normalize_text(textval, ctx);
    }

    return AXIS2_SUCCESS;
}

static axis2_status_t
c14n_apply_on_node(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    switch(axiom_node_get_node_type(node, ctx->env))
    {
        case AXIOM_ELEMENT:
            c14n_apply_on_element(node, ctx);
            break;
        case AXIOM_TEXT:
            c14n_apply_on_text(node, ctx);
            break;
        case AXIOM_COMMENT:
            if(ctx->comments)
            {
                c14n_apply_on_comment(node, ctx->outbuffer, ctx->env);
                break;
            }
        case AXIOM_DOCTYPE:
        case AXIOM_PROCESSING_INSTRUCTION:
        default:
            ;
    }

    return AXIS2_SUCCESS;
}

static void
c14n_apply_on_comment(
    axiom_node_t *node,
    c14n_buffer_t *buffer,
    const axutil_env_t *env)
{
    axis2_char_t *comment = axiom_comment_get_value((axiom_comment_t*) axiom_node_get_data_element(
        node, env), env);
    if(comment)
    {
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, "<!--", 4);
        C14N_BUFFER_ADD_STRING(buffer, env, comment);
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, "-->", 3);
    }
}

static axis2_status_t
c14n_apply_on_element(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axis2_status_t res = AXIS2_SUCCESS;
    axiom_element_t *ele = NULL;
    axiom_namespace_t *ns = NULL;
    c14n_ns_stack_t *save_stack = NULL;
    axiom_node_t *child_node = NULL;
    const axutil_env_t *env = ctx->env;
    c14n_buffer_t *buffer = ctx->outbuffer;

    axis2_char_t *prefix = NULL;
    axis2_ssize_t prefix_len = 0;
    axis2_char_t *localname = NULL;
    axis2_ssize_t localname_len = 0;

    ele = (axiom_element_t *) axiom_node_get_data_element(node, env);
    if(!ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] cannot find valid element to apply c14n");
        return AXIS2_FAILURE;
    }

    ns = axiom_element_get_namespace(ele, env, node);
    save_stack = c14n_ns_stack_create(ctx);
    c14n_ns_stack_push(save_stack, ctx); /*save current ns stack*/

    /*print start tag*/
    C14N_BUFFER_ADD_CHAR(buffer, env, '<');
    if(ns)
    {
        prefix = axiom_namespace_get_prefix(ns, env);
        prefix_len = axutil_strlen(prefix);
        if(prefix_len > 0)
        {
            C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, prefix, prefix_len);
            C14N_BUFFER_ADD_CHAR(buffer, env, ':');
        }
    }
    localname = axiom_element_get_localname(ele, env);
    localname_len = axutil_strlen(localname);
    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, localname, localname_len);

    if(ctx->exclusive)
        res = c14n_apply_on_namespace_axis_exclusive(ele, node, ctx);
    else
        res = c14n_apply_on_namespace_axis(ele, node, ctx);

    /*
     * edited the code so that the same fn does both exc and non-exc.
     * have to be careful here!
     */

    if(!res)
        return res;

    res = c14n_apply_on_attribute_axis(ele, ctx);

    if(!res)
        return res;
    C14N_BUFFER_ADD_CHAR(buffer, env, '>');

    /*process child elements*/
    child_node = axiom_node_get_first_child(node, env);
    while(child_node)
    {
        c14n_apply_on_node(child_node, ctx);
        child_node = axiom_node_get_next_sibling(child_node, env);
    }

    /*print end tag*/
    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"</", 2);
    if(ns)
    {
        if(prefix_len > 0)
        {
            C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, prefix, prefix_len);
            C14N_BUFFER_ADD_CHAR(buffer, env, ':');
        }
    }
    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, localname, localname_len);
    C14N_BUFFER_ADD_CHAR(buffer, env, '>');

    c14n_ns_stack_pop(save_stack, ctx); /*restore to previous ns stack */

    /*since save_stack is used just to memorize the head of the stack,
     * we don't have to worry about freeing its members*/
    AXIS2_FREE(env->allocator, save_stack);
    return res;
}

static int
ns_uri_compare(
    const void *ns1,
    const void *ns2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;

    if(ns1 == ns2)
        return 0;
    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    return (axutil_strcmp((const axis2_char_t *) axiom_namespace_get_uri((axiom_namespace_t *) ns1,
        ctx->env), (const axis2_char_t *) axiom_namespace_get_uri((axiom_namespace_t *) ns2,
        ctx->env)));
}

static int
ns_prefix_compare(
    const void *ns1,
    const void *ns2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;

    if(ns1 == ns2)
        return 0;
    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    return (axutil_strcmp((const axis2_char_t *) axiom_namespace_get_prefix(
        (axiom_namespace_t *) ns1, ctx->env), (const axis2_char_t *) axiom_namespace_get_prefix(
        (axiom_namespace_t *) ns2, ctx->env)));
}

static int
attr_compare(
    const void *a1,
    const void *a2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;
    axiom_attribute_t *attr1 = NULL;
    axiom_attribute_t *attr2 = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_namespace_t *ns2 = NULL;
    int res;

    if(a1 == a2)
        return 0;
    if(!a1)
        return -1;
    if(!a2)
        return 1;

    attr1 = (axiom_attribute_t *) a1;
    attr2 = (axiom_attribute_t *) a2;
    ns1 = axiom_attribute_get_namespace((axiom_attribute_t *) a1, ctx->env);
    ns2 = axiom_attribute_get_namespace((axiom_attribute_t *) a2, ctx->env);

    if(ns1 == ns2)
        return axutil_strcmp(
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a1, ctx->env),
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a2, ctx->env));

    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    res = axutil_strcmp(axiom_namespace_get_uri(ns1, ctx->env), axiom_namespace_get_uri(ns2,
        ctx->env));

    if(res == 0)
        return axutil_strcmp(
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a1, ctx->env),
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a2, ctx->env));
    else
        return res;

}

static void
c14n_apply_on_attribute(
    const void *attribute,
    const void *context)
{
    const axutil_env_t *env = ((c14n_ctx_t *)context)->env;
    c14n_buffer_t *buffer = ((c14n_ctx_t *)context)->outbuffer;
    axiom_attribute_t *attr = (axiom_attribute_t *) attribute;
    axiom_namespace_t *ns = axiom_attribute_get_namespace(attr, env);
    axis2_char_t *attvalue = NULL;

    C14N_BUFFER_ADD_CHAR(buffer, env, ' ');
    if(ns)
    {
        axis2_char_t *prefix = axiom_namespace_get_prefix(ns, env);

        if(axutil_strlen(prefix) > 0)
        {
            C14N_BUFFER_ADD_STRING(buffer, env, prefix);
            C14N_BUFFER_ADD_CHAR(buffer, env, ':');
        }
    }
    C14N_BUFFER_ADD_STRING(buffer, env, axiom_attribute_get_localname(attr, env));
    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, "=\"", 2);

    /* Normalize the text before output */
    attvalue = axiom_attribute_get_value(attr, env);
    c14n_add_normalize_attribute(attvalue, (c14n_ctx_t *)context);
    C14N_BUFFER_ADD_CHAR(buffer, env, '\"');
}

static axis2_status_t
c14n_apply_on_attribute_axis(
    const axiom_element_t *ele,
    const c14n_ctx_t *ctx)
{
    axutil_hash_t *attr_ht = NULL;
    axutil_hash_index_t *hi = NULL;

    attr_ht = axiom_element_get_all_attributes((axiom_element_t *) ele, ctx->env);

    if(attr_ht)
    {
        c14n_sorted_list_t *attr_list = c14n_sorted_list_create(ctx->env);
        for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
        {
            void *v = NULL;
            axutil_hash_this(hi, NULL, NULL, &v);

            if(v)
            {
                C14N_SORTED_LIST_INSERT(&attr_list, v, ctx, attr_compare, ctx->env);
            }
        }

        C14N_SORTED_LIST_ITERATE(attr_list, ctx, c14n_apply_on_attribute, ctx->env);
        C14N_SORTED_LIST_FREE_CONTAINER(attr_list, ctx->env);
    }

    return AXIS2_SUCCESS;

    /* TODO: Still need to add the "xml" attrs of the parents in case of doc subsets
     * and non-exclusive c14n
     * */
}

static void
c14n_add_normalize_text(
    axis2_char_t *text,
    c14n_ctx_t *ctx)
{
    int original_size = axutil_strlen(text);
    c14n_buffer_t *buffer = ctx->outbuffer;
    const axutil_env_t *env = ctx->env;

    while(original_size > 0)
    {
        size_t i = 0;

        /* scan buffer until the next special character (&, <, >, \x0D) these need to be escaped,
         * otherwise XML will not be valid*/
        axis2_char_t *pos = (axis2_char_t*) strpbrk(text, "&<>\x0D");
        if(pos)
        {
            i = pos - text;
        }
        else
        {
            i = original_size;
        }

        /* copy everything until the special character */
        if(i > 0)
        {
            C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,text, i);
            text += i;
            original_size -= i;
        }

        /* replace the character with the appropriate sequence */
        if(original_size > 0)
        {
            switch(text[0])
            {
                case '&':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&amp;", 5);
                    break;
                case '>':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&gt;", 4);
                    break;
                case '<':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&lt;", 4);
                    break;
                case '\x0D':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&#xD;", 5);
                    break;
                default:
                    ;
            }

            ++text;
            --original_size;
        }
    }
}

static void
c14n_add_normalize_attribute(
    axis2_char_t *attval,
    c14n_ctx_t *ctx)
{
    int original_size = axutil_strlen(attval);
    c14n_buffer_t *buffer = ctx->outbuffer;
    const axutil_env_t *env = ctx->env;

    while(original_size > 0)
    {
        size_t i = 0;

        /* scan buffer until the next special character (&, <, ", \x09, \x0A, \x0D)
         * these need to be escaped, otherwise XML will not be valid*/
        axis2_char_t *pos = (axis2_char_t*) strpbrk(attval, "&<\"\x09\x0A\x0D");
        if(pos)
        {
            i = pos - attval;
        }
        else
        {
            i = original_size;
        }

        /* copy everything until the special character */
        if(i > 0)
        {
            C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,attval, i);
            attval += i;
            original_size -= i;
        }

        /* replace the character with the appropriate sequence */
        if(original_size > 0)
        {
            switch(attval[0])
            {
                case '&':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&amp;", 5);
                    break;
                case '<':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&lt;", 4);
                    break;
                case '"':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&quot;", 6);
                    break;
                case '\x09':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&#x9;", 5);
                    break;
                case '\x0A':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&#xA;", 5);
                    break;
                case '\x0D':
                    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env,"&#xD;", 5);
                    break;
                default:
                    ;
            }

            ++attval;
            --original_size;
        }
    }
}

static axis2_status_t
c14n_apply_on_namespace_axis(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axutil_hash_t *ns_ht = NULL;
    axutil_hash_index_t *hi = NULL;
    const axutil_env_t *env = ctx->env;

    c14n_sorted_list_t *out_list = c14n_sorted_list_create(env);

    ns_ht = axiom_element_get_namespaces(ele, env);

    if(ns_ht)
    {
        for(hi = axutil_hash_first(ns_ht, env); hi; hi = axutil_hash_next(env, hi))
        {
            void *v = NULL;
            axutil_hash_this(hi, NULL, NULL, &v);
            if(v)
            {
                axiom_namespace_t *ns = (axiom_namespace_t *) v;
                axis2_char_t *pfx = axiom_namespace_get_prefix(ns, env);
                axis2_char_t *uri = axiom_namespace_get_uri(ns, env);

                if(axutil_strlen(pfx) == 0)
                {
                    /*process for default namespace*/
                    if(axutil_strlen(uri) == 0)
                    {
                        if(c14n_ns_stack_get_default(ctx) != NULL)
                        {
                            c14n_ns_stack_set_default(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                env);
                        }

                    }
                    else
                    {
                        axiom_namespace_t *prev_def = c14n_ns_stack_get_default(ctx);

                        axis2_char_t *prev_def_uri = ((prev_def) ?
                            axiom_namespace_get_uri(prev_def, env) : NULL);

                        if(!prev_def_uri || axutil_strcmp(prev_def_uri, uri) != 0)
                        {
                            c14n_ns_stack_set_default(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                env);
                        }
                    }
                }
                else if(!c14n_ns_stack_find(ns, ctx))
                {
                    /*non-default namespace*/
                    c14n_ns_stack_add(ns, ctx);
                    C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                        env);
                }
            }
        }
    }

    C14N_SORTED_LIST_ITERATE(out_list, ctx, c14n_apply_on_namespace, env);
    C14N_SORTED_LIST_FREE_CONTAINER(out_list, env);

    return AXIS2_SUCCESS;
}

static axis2_status_t
c14n_apply_on_namespace_axis_exclusive(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axutil_hash_t *ns_ht = NULL;
    axutil_hash_index_t *hi = NULL;
    axiom_node_t *pnode = NULL;
    axiom_element_t *pele = NULL;
    axiom_namespace_t *ns = NULL;
    const axutil_env_t *env = ctx->env;

    c14n_sorted_list_t *out_list = c14n_sorted_list_create(env);

    pele = ele;
    pnode = node;

    /*treat the default namespace specially*/

    ns = axiom_element_get_namespace(pele, env, pnode);

    if(ns)
    {
        if(axutil_strlen(axiom_namespace_get_prefix(ns, env)) == 0)
        {
            axiom_namespace_t *def_ns = c14n_ns_stack_get_default(ctx);
            if(def_ns || axutil_strlen(axiom_namespace_get_uri(ns, env)) != 0)
            {
                if(ns_uri_compare(ns, def_ns, ctx) != 0)
                {
                    c14n_ns_stack_set_default(ns, ctx);
                    C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare, env);
                }
            }
        }
    }

    while(pnode)
    {
        pele = axiom_node_get_data_element(pnode, env);
        ns_ht = axiom_element_get_namespaces(pele, env);

        if(ns_ht)
        {
            for(hi = axutil_hash_first(ns_ht, env); hi; hi = axutil_hash_next(env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axis2_char_t *pfx = NULL;
                    ns = (axiom_namespace_t *) v;

                    pfx = axiom_namespace_get_prefix(ns, env);

                    if(axutil_strlen(pfx) == 0)
                    {
                        /* process for default namespace.
                         * NOTE: This part was taken out of here due to the 
                         * search thruogh parent-axis
                         * */
                    }
                    else if(!c14n_ns_stack_find(ns, ctx))
                    {
                        /*non-default namespace*/
                        if(c14n_need_to_declare_ns(ele, node, ns, ctx))
                        {
                            c14n_ns_stack_add(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                env);
                        }
                    }
                }
            }
        }
        pnode = axiom_node_get_parent(pnode, env);
    } /*while*/
    C14N_SORTED_LIST_ITERATE(out_list, ctx, c14n_apply_on_namespace, env);
    C14N_SORTED_LIST_FREE_CONTAINER(out_list, env);

    return AXIS2_SUCCESS;
}

static void
c14n_apply_on_namespace(
    const void *namespace,
    const void *context)
{
    axiom_namespace_t *ns = (axiom_namespace_t *) namespace;
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;
    c14n_buffer_t *buffer = ctx->outbuffer;
    const axutil_env_t *env = ctx->env;

    axis2_char_t *pfx = axiom_namespace_get_prefix(ns, env);
    axis2_char_t *uri = axiom_namespace_get_uri(ns, env);
    int length = 0;

    if((length = axutil_strlen(pfx)) > 0)
    {
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, " xmlns:", 7);
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, pfx, length);
    }
    else
    {
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, " xmlns", 6);
    }

    C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, "=\"", 2);

    if((length = axutil_strlen(uri)) > 0)
    {
        C14N_BUFFER_ADD_STRING_WITH_LENGTH(buffer, env, uri, length);
    }

    C14N_BUFFER_ADD_CHAR(buffer, env, '\"');
}

static axis2_bool_t
c14n_need_to_declare_ns(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_bool_t vu = c14n_ns_visibly_utilized(ele, node, ns, ctx);

    if(vu || (ctx->ns_prefixes &&
        axutil_array_list_contains(ctx->ns_prefixes, ctx->env,
        (void*) (axiom_namespace_get_prefix((axiom_namespace_t*) ns, ctx->env)))))
        return c14n_no_output_ancestor_uses_prefix(ele, node, ns, ctx);

    return AXIS2_FALSE;
}

static axis2_bool_t
c14n_ns_visibly_utilized(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_bool_t vu = AXIS2_FALSE;
    axiom_namespace_t *ns_ele = NULL;

    axis2_char_t *pfx = axiom_namespace_get_prefix((axiom_namespace_t*) ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env);
    axis2_char_t *pfx_ele = NULL;
    axis2_char_t *uri_ele = NULL;
    ns_ele = axiom_element_get_namespace((axiom_element_t*) ele, ctx->env, (axiom_node_t *) node);

    if(ns_ele) /* return AXIS2_FALSE; TODO:check */
    {
        pfx_ele = axiom_namespace_get_prefix(ns_ele, ctx->env);
        uri_ele = axiom_namespace_get_uri(ns_ele, ctx->env);
    }
    if((axutil_strcmp(pfx, pfx_ele) == 0) && (axutil_strcmp(uri, uri_ele) == 0))
        vu = AXIS2_TRUE;
    else
    {
        axutil_hash_t *attr_ht =
            axiom_element_get_all_attributes((axiom_element_t *) ele, ctx->env);
        axutil_hash_index_t *hi = NULL;
        if(attr_ht)
        {
            for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axiom_attribute_t *attr = (axiom_attribute_t*) v;
                    axiom_namespace_t *ns_attr = axiom_attribute_get_namespace(attr, ctx->env);
                    axis2_char_t *attr_pfx = NULL;

                    /*if in_nodelist(attr) {*/
                    if(ns_attr)
                        attr_pfx = axiom_namespace_get_prefix(ns_attr, ctx->env);

                    if(axutil_strcmp(attr_pfx, pfx) == 0)
                    {
                        vu = AXIS2_TRUE;
                        if(ctx->env)
                            AXIS2_FREE(ctx->env->allocator, hi);
                        break;
                    }
                    /*}*/
                }
            }
        }

    }

    return vu;
}

static axis2_bool_t
in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx)
{
    axiom_node_t *pnode = NULL;
    pnode = axiom_node_get_parent((axiom_node_t *) node, ctx->env);

    while(pnode)
    {
        if(ctx->node == pnode)
            return AXIS2_TRUE;
        pnode = axiom_node_get_parent((axiom_node_t *) pnode, ctx->env);
    }

    return AXIS2_FALSE;
}

static axis2_bool_t
c14n_no_output_ancestor_uses_prefix(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_char_t *pfx = axiom_namespace_get_prefix((axiom_namespace_t*) ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env);

    axiom_node_t *parent_node = axiom_node_get_parent((axiom_node_t *) node, ctx->env);
    axiom_element_t *parent_element = NULL;
    axiom_namespace_t *parent_ns = NULL;
    axis2_char_t *parent_pfx = NULL;
    axis2_char_t *parent_uri = NULL;

    /* assuming the parent  of an element is always an element node in AXIOM*/
    while(parent_node)
    {
        axutil_hash_index_t *hi = NULL;
        axutil_hash_t *attr_ht = NULL;

        /* TODO:
         * HACK: since we only use a single node as the subset
         * the following hack should work instead of a more
         * general in_nodest()*/

        if(!in_nodeset(parent_node, ctx))
        {
            /*we reached a node beyond the nodeset,
             * so the prefix is not used*/
            return AXIS2_TRUE;
        }

        /* if (in_nodeset(parent)){*/
        parent_element = axiom_node_get_data_element((axiom_node_t *) parent_node, ctx->env);
        parent_ns = axiom_element_get_namespace((axiom_element_t *) parent_element, ctx->env,
            (axiom_node_t *) parent_node);

        if(parent_ns)
        {
            parent_pfx = axiom_namespace_get_prefix((axiom_namespace_t *) parent_ns, ctx->env);
            if(axutil_strcmp(pfx, parent_pfx) == 0)
            {
                parent_uri = axiom_namespace_get_uri((axiom_namespace_t*) parent_ns, ctx->env);
                return (!(axutil_strcmp(uri, parent_uri) == 0));
            }
        }

        attr_ht = axiom_element_get_all_attributes((axiom_element_t *) parent_element, ctx->env);
        if(attr_ht)
        {
            for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axiom_attribute_t *attr = (axiom_attribute_t*) v;
                    axiom_namespace_t *attr_ns = axiom_attribute_get_namespace(attr, ctx->env);
                    axis2_char_t *attr_pfx = NULL;
                    axis2_char_t *attr_uri = NULL;

                    if(attr_ns)
                    {
                        attr_pfx = axiom_namespace_get_prefix(attr_ns, ctx->env);
                        attr_uri = axiom_namespace_get_uri(attr_ns, ctx->env);

                        if(axutil_strcmp(attr_pfx, pfx) == 0)
                            return (!(axutil_strcmp(attr_uri, uri) == 0));
                        /*test for this case*/
                    }
                }
            }
        }
        /*}*/
        parent_node = axiom_node_get_parent((axiom_node_t *) parent_node, ctx->env);
    }

    return AXIS2_TRUE;
}

#if 0
static axis2_status_t
oxs_c14n_apply_stream_algo(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axutil_stream_t *stream,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node,
    const axis2_char_t* algo)
{
    switch(c14n_get_algorithm(algo))
    {
        case C14N_XML_C14N:
            return oxs_c14n_apply_stream(env, doc, AXIS2_FALSE, stream, AXIS2_FALSE, ns_prefixes,
                node);
        case C14N_XML_C14N_WITH_COMMENTS:
            return oxs_c14n_apply_stream(env, doc, AXIS2_TRUE, stream, AXIS2_FALSE, ns_prefixes,
                node);
        case C14N_XML_EXC_C14N:
            return oxs_c14n_apply_stream(env, doc, AXIS2_FALSE, stream, AXIS2_TRUE, ns_prefixes,
                node);
        case C14N_XML_EXC_C14N_WITH_COMMENTS:
            return oxs_c14n_apply_stream(env, doc, AXIS2_TRUE, stream, AXIS2_TRUE, ns_prefixes,
                node);
        default:
            /*TODO: set the error*/
            return AXIS2_FAILURE;
    }
}

static axis2_char_t*
c14n_normalize_text(
    axis2_char_t *text,
    const c14n_ctx_t *ctx
)
{
    axis2_char_t *buf = NULL;
    axis2_char_t *endpivot = NULL;
    axis2_char_t *p = NULL;
    axis2_char_t *old = NULL;
    int bufsz = INIT_BUFFER_SIZE;

    /* TODO:DONE a better buffer implementation */
    buf = (axis2_char_t *)(AXIS2_MALLOC(ctx->env->allocator,
            (sizeof(axis2_char_t) * bufsz) + 10));
    if (!buf)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY,
            AXIS2_FAILURE);
        return buf;
    }

    p = buf;
    endpivot = p + bufsz;

    old = text;

    while (*old !='\0')
    {
        if (p > endpivot)
        {
            int size = bufsz * 2;
            axis2_char_t *temp_buf = (axis2_char_t *)(AXIS2_MALLOC(
                    ctx->env->allocator, sizeof(axis2_char_t) * size + 10));

            if (!temp_buf)
            {
                AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY,
                    AXIS2_FAILURE);
                return buf;
            }

            memcpy(temp_buf, buf, sizeof(axis2_char_t) * bufsz + 10);

            p = temp_buf + (p - buf);

            AXIS2_FREE(ctx->env->allocator, buf);
            buf = temp_buf;
            bufsz = size;
            endpivot = buf + bufsz;
        }

        switch (*old)
        {
            case '&':
            *p++ = '&';
            *p++ = 'a';
            *p++ = 'm';
            *p++ = 'p';
            *p++ = ';';
            break;
            case '>':
            *p++ = '&';
            *p++ = 'g';
            *p++ = 't';
            *p++ = ';';
            break;
            case '<':
            *p++ = '&';
            *p++ = 'l';
            *p++ = 't';
            *p++ = ';';
            break;
            case '\x0D':
            *p++ = '&';
            *p++ = '#';
            *p++ = 'x';
            *p++ = 'D';
            *p++ = ';';
            break;
            default:
            *p++ = *old;
        }
        old ++;
    }
    *p++ = '\0';
    return buf;
}

static axis2_char_t*
c14n_normalize_attribute(
    axis2_char_t *attval,
    const c14n_ctx_t *ctx)
{
    axis2_char_t *buf = NULL;
    axis2_char_t *endpivot = NULL;
    axis2_char_t *p = NULL;
    axis2_char_t *old = NULL;
    int bufsz = INIT_BUFFER_SIZE;

    /* TODO:DONE a better buffer implementation */
    buf = (axis2_char_t *) (AXIS2_MALLOC(ctx->env->allocator, sizeof(axis2_char_t)
        * INIT_BUFFER_SIZE + 10));
    if(!buf)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return buf;
    }

    p = buf;
    endpivot = buf + bufsz;

    old = attval;

    while(*old != '\0')
    {
        if(p > endpivot)
        {
            int size = bufsz * 2;
            axis2_char_t *temp_buf = (axis2_char_t *) (AXIS2_MALLOC(ctx->env->allocator,
                sizeof(axis2_char_t) * size + 10));

            if(!temp_buf)
            {
                AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
                return buf;
            }

            memcpy(temp_buf, buf, sizeof(axis2_char_t) * bufsz + 10);

            p = temp_buf + (p - buf);

            AXIS2_FREE(ctx->env->allocator, buf);
            buf = temp_buf;
            bufsz = size;
            endpivot = buf + bufsz;
        }

        switch(*old)
        {
            case '&':
                *p++ = '&';
                *p++ = 'a';
                *p++ = 'm';
                *p++ = 'p';
                *p++ = ';';
                break;
            case '<':
                *p++ = '&';
                *p++ = 'l';
                *p++ = 't';
                *p++ = ';';
                break;
            case '"':
                *p++ = '&';
                *p++ = 'q';
                *p++ = 'u';
                *p++ = 'o';
                *p++ = 't';
                *p++ = ';';
                break;
            case '\x09':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = '9';
                *p++ = ';';
                break;
            case '\x0A':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = 'A';
                *p++ = ';';
                break;
            case '\x0D':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = 'D';
                *p++ = ';';
                break;
            default:
                *p++ = *old;
        }
        old++;
    }
    *p++ = '\0';
    return buf;
}

#endif
