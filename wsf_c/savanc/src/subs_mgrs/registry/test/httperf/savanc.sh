#!/bin/bash
#insert
#httperf --hog --method post --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=1000,0,savanc_input --max-piped-calls 5 --rate 2 --timeout 25 --server localhost --port 80 --uri /axis2/services/weather > savanc_result.txt
#httperf --hog --method post --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=4,0,savanc_input --max-piped-calls 2 --rate 2 --timeout 25 --server localhost --port 9090 --uri /axis2/services/weather > savanc_result.txt

#get_status
httperf --hog --method POST --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=1000,0,savanc_input2 --max-piped-calls 8 --rate 16 --timeout 60 --server localhost --port 80 --uri /axis2/services/weather > savanc_result.txt

#httperf --hog --method POST --add-header="Content-type:application/soap+xml;charset=UTF-8``\n``" --wsesslog=4,0,savanc_input2 --max-piped-calls 1 --rate 1 --timeout 60 --server localhost --port 80 --uri /axis2/services/weather > savanc_result.txt



