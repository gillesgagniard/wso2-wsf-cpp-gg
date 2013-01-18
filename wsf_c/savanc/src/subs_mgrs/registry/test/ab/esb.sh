#!/bin/bash
ab -T "text/xml; charset=UTF-8" -p esb_subscribe.xml -n 1000 -c 10 -H SOAPAction:\"http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe\" http://localhost:8280/services/SampleEventSource > esb_result.txt 
