#!/bin/bash
ab -T "application/soap+xml;charset=UTF-8" -p savanc_subscribe.xml -n 1000 -c 50 http://localhost:9091/axis2/services/weather > savanc_result.txt

