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
 
#include <savan_filter_mod.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_types.h>
#include <axutil_file_handler.h>
#include <platforms/axutil_platform_auto_sense.h>
#include <savan_constants.h>
#include <savan_util.h>
#include <savan_error.h>
#include <libxslt/xsltutils.h>
#include <axiom_soap.h>
#include <axiom_soap_const.h>
#include <axiom_soap_envelope.h>
#include <axiom_element.h>
#include <axiom_node.h>

/**
 *
 */
/** 
 * @brief Savan XPath Filter Struct Impl
 *   Savan XPath Filter 
 */
typedef struct savan_xpath_filter_mod
{
    savan_filter_mod_t filtermod;
    axis2_char_t *dialect;
    axis2_char_t *filter_template_path;
    axis2_conf_t *conf;
} savan_xpath_filter_mod_t;

#define SAVAN_INTF_TO_IMPL(filtermod) ((savan_xpath_filter_mod_t *) filtermod)

static xsltStylesheetPtr 
savan_xpath_filter_mod_get_filter_template(
    const axutil_env_t *env,
    axis2_char_t *filter_template_path,
    xmlChar *filter);

static axis2_status_t 
savan_xpath_filter_mod_update_filter_template(
    xmlNodeSetPtr nodes,
    const xmlChar* value);

AXIS2_EXTERN void AXIS2_CALL
savan_xpath_filter_mod_free(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *env);

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_xpath_filter_mod_apply(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axiom_node_t *payload);

static const savan_filter_mod_ops_t savan_filter_mod_ops = 
{
    savan_xpath_filter_mod_free,
    savan_xpath_filter_mod_apply
};

AXIS2_EXTERN savan_filter_mod_t * AXIS2_CALL
savan_filter_mod_create(
    const axutil_env_t *env,
    axis2_conf_t *conf)
{
    savan_xpath_filter_mod_t *filtermodimpl = NULL;
    axis2_char_t *filter_template_path = NULL;
    
    filtermodimpl = AXIS2_MALLOC(env->allocator, sizeof(savan_xpath_filter_mod_t));
    if (!filtermodimpl)
    {
        AXIS2_HANDLE_ERROR(env, SAVAN_ERROR_FILTER_CREATION_FAILED, AXIS2_FAILURE);
        return NULL;
    }

    memset ((void *) filtermodimpl, 0, sizeof(savan_xpath_filter_mod_t));

    filter_template_path = savan_util_get_module_param(env, conf, SAVAN_FILTER_TEMPLATE_PATH);
    if(!filter_template_path)
    {
        savan_xpath_filter_mod_free((savan_filter_mod_t *) filtermodimpl, env);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[savan] Filter template path not set");
        return NULL;
    }

    filtermodimpl->filter_template_path = filter_template_path;

    filtermodimpl->dialect = NULL;
    filtermodimpl->conf = conf;
    filtermodimpl->filtermod.ops = &savan_filter_mod_ops;

    return (savan_filter_mod_t *) filtermodimpl;
}

AXIS2_EXTERN void AXIS2_CALL
savan_xpath_filter_mod_free(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *env)
{
    savan_xpath_filter_mod_t *filtermodimpl = NULL;
    filtermodimpl = SAVAN_INTF_TO_IMPL(filtermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Entry:savan_xpath_filter_mod_free");

    if(filtermodimpl->dialect)
    {
        AXIS2_FREE(env->allocator, filtermodimpl->dialect);
        filtermodimpl->dialect = NULL;
    }

    filtermodimpl->conf = NULL;

    if(filtermodimpl)
    {
        AXIS2_FREE(env->allocator, filtermodimpl);
        filtermodimpl = NULL;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_xpath_filter_mod_free");
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_xpath_filter_mod_apply(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axiom_node_t *payload)
{
    axis2_char_t *payload_string = NULL;
    xmlDocPtr payload_doc = NULL;
    xsltStylesheetPtr xslt_template_filter = NULL;
    xmlChar *xfilter = NULL;
    xmlDocPtr result_doc;
    savan_xpath_filter_mod_t *filtermodimpl = NULL;

    filtermodimpl = SAVAN_INTF_TO_IMPL(filtermod);

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
            "[savan] Entry:savan_xpath_filter_mod_apply");

	xfilter = (xmlChar *) savan_subscriber_get_filter(subscriber, env);
	if(!xfilter)
	{
		return AXIS2_FALSE;
	}

    payload_string = axiom_node_to_string(payload, env);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[savan] payload_string before applying filter %s:%s", xfilter, payload_string);

    payload_doc = (xmlDocPtr)xmlParseDoc((xmlChar*)payload_string);

    xslt_template_filter = (xsltStylesheetPtr) savan_xpath_filter_mod_get_filter_template(env, 
            filtermodimpl->filter_template_path, xfilter);

    result_doc = (xmlDocPtr)xsltApplyStylesheet(xslt_template_filter, payload_doc, NULL);

    if(result_doc)
    {
        /*free(payload_string);*/ /* In apache freeing this give seg fault:damitha */
	    xmlFreeDoc(result_doc);
        return AXIS2_TRUE;
    }

    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, "[savan] Exit:savan_xpath_filter_mod_apply");
    return AXIS2_FALSE;
}

static xsltStylesheetPtr 
savan_xpath_filter_mod_get_filter_template(
    const axutil_env_t *env,
    axis2_char_t *filter_template_path,
    xmlChar *filter)
{
    xsltStylesheetPtr xslt_template_xslt = NULL;
    xmlDocPtr xslt_template_xml = NULL;
    xmlChar* xpathExpr = NULL; 
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
	
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[savan] filter_template_path:%s", filter_template_path);

    xslt_template_xml = xmlParseFile(filter_template_path);
    xpathExpr = (xmlChar*)"//@select";
    xpathCtx = xmlXPathNewContext(xslt_template_xml);
    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    savan_xpath_filter_mod_update_filter_template(xpathObj->nodesetval, filter);

    xslt_template_xslt = xsltParseStylesheetDoc(xslt_template_xml);

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);

    return xslt_template_xslt;
}

static axis2_status_t 
savan_xpath_filter_mod_update_filter_template(
    xmlNodeSetPtr nodes,
    const xmlChar* value)
{
    int size;
    int i;
    size = (nodes) ? nodes->nodeNr : 0;
    for(i = size - 1; i >= 0; i--) 
	{
    	xmlNodeSetContent(nodes->nodeTab[i], value);
    	if (nodes->nodeTab[i]->type != XML_NAMESPACE_DECL)
        	nodes->nodeTab[i] = NULL;
    }
    return AXIS2_SUCCESS;
}

