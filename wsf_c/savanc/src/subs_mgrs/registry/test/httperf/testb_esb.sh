#!/bin/bash
#insert
#httperf --hog --method post --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --add-header="SOAPAction:\"http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe\"``\n``" --wsesslog=1000,0,esb_input --max-piped-calls 1 --rate 1 --timeout 120 --server localhost --port 8280 --uri /services/SampleEventSource > esb_result.txt

#httperf --hog --method post --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --add-header="SOAPAction:\"http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe\"``\n``" --wsesslog=4,0,esb_input --max-piped-calls 2 --rate 2 --timeout 30 --server localhost --port 8281 --uri /services/SampleEventSource > esb_result.txt

#get_status
#httperf --hog --method POST --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=1000,0,esb_temp --max-piped-calls 8 --rate 8 --timeout 60 --server 10.100.1.44 --port 8280 --uri /services/SampleEventSource > esb_result.txt

httperf --hog --method POST --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=4,0,esb_temp --max-piped-calls 1 --rate 1 --timeout 60 --server localhost --port 8281 --uri /services/SampleEventSource > esb_result.txt

