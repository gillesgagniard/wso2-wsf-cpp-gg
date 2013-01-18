#include <axiom_namespace.h>
#include <axiom_element.h>
#include <axutil_env.h>
#include <axutil_string.h>
#include <stdio.h>

char *test_endpoint_serialize()
{
    axiom_namespace_t *ns = NULL;
    axiom_node_t *subs_node = NULL;
    axiom_element_t *subs_elem = NULL;
    axiom_node_t *endpoint_node = NULL;
    axiom_element_t *endpoint_elem = NULL;
    axiom_node_t *addr_node = NULL;
    axiom_element_t *addr_elem = NULL;
    axiom_attribute_t *url_attr = NULL;
    char *content = NULL;
    const axutil_env_t *env = NULL;
    axis2_char_t *nsurl = "http://ws.apache.org/ns/synapse";
    axis2_char_t *ns_prefix = "syn";
    axis2_char_t *notifyto = "http://localhost:9000/services/SimpleStockQuoteService";
    
    env = axutil_env_create_all("test.log", AXIS2_LOG_LEVEL_TRACE);
    /* Format of the message is as 
     * <subscription><syn:endpoint xmlns:syn="http://ws.apache.org/ns/synapse"><syn:address uri=
     * "http://localhost:9000/services/SimpleStockQuoteService" /></syn:endpoint></subscription>
     */
    printf("\ncontent1:<subscription><syn:endpoint xmlns:syn=\"http://ws.apache.org/ns/synapse\"><syn:address uri=\"http://localhost:9000/services/SimpleStockQuoteService\" /></syn:endpoint></subscription>");
    ns = axiom_namespace_create (env, nsurl, ns_prefix);

    subs_elem = axiom_element_create(env, NULL, "subscription", NULL, &subs_node);
    endpoint_elem = axiom_element_create(env, subs_node, "endpoint", ns, &endpoint_node);
    addr_elem = axiom_element_create(env, endpoint_node, "address", ns, &addr_node);
    url_attr = axiom_attribute_create(env, "url", notifyto, NULL);
    axiom_element_add_attribute(addr_elem, env, url_attr, addr_node);

    content = (char *) axiom_node_to_string(subs_node, env);
    printf("\n\ncontent2:%s\n\n", content);

    return content;
}

void test_endpoint_deserialize(char *content)
{
    axutil_qname_t *qname = NULL;
    axiom_node_t *subs_node = NULL;
    axiom_element_t *subs_element = NULL;
    axiom_node_t *endpoint_node = NULL;
    axiom_element_t *endpoint_element = NULL;
    axiom_node_t *address_node = NULL;
    axiom_element_t *address_element = NULL;
    axis2_char_t *address = NULL;
    const axutil_env_t *env = NULL;
    axis2_char_t *nsurl = "http://ws.apache.org/ns/synapse";

    env = axutil_env_create_all("test.log", AXIS2_LOG_LEVEL_TRACE);

    subs_node = axiom_node_create_from_buffer(env, content);
    subs_element = axiom_node_get_data_element(subs_node, env);
    if(!subs_element)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_OM_ELEMENT_EXPECTED, AXIS2_FAILURE);
        return;
    }

    qname = axutil_qname_create(env, "endpoint", nsurl, NULL);
    if(!qname)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return;
    }

    endpoint_element = axiom_element_get_first_child_with_qname(subs_element, env, qname, 
            subs_node, &endpoint_node);

    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    qname = axutil_qname_create(env, "address", nsurl, NULL);
    if(!qname)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return;
    }

    address_element = axiom_element_get_first_child_with_qname(endpoint_element, env, qname, 
            endpoint_node, &address_node);

    if(qname)
    {
        axutil_qname_free(qname, env);
    }

    address = axiom_element_get_attribute_value_by_name(address_element, env, "url");
    
    if(!address)
    {
        AXIS2_HANDLE_ERROR(env, AXIS2_ERROR_OM_ELEMENT_INVALID_STATE, AXIS2_FAILURE);
        return; 
    }

    printf("\naddress:%s\n\n", address);
}

