/*
* Copyright 2005-2009 WSO2, Inc. http://wso2.com
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


#include <stdio.h>
#include <ServiceClient.h>
#include <OMElement.h>
#include <iostream>
#include <WSFault.h>
#include <Environment.h>


using namespace std;
using namespace wso2wsf;

int main(int argc, char** argv)
{
	int fg = 0;
	char *flags;
	char *username;
	char *password;
	char *workstation;
	char *domain;
	char *address = "http://172.16.176.132:80/myservice/Service1.asmx";

	if(argc > 1){
		if(strcmp(argv[1], "-h") == 0){
			cout << endl << "Usage : %s [endpoint_url] (-n [username] [password] [flags] [domain] [workstation])" << argv[0] << endl;
			cout << "use -n option for NTLM HTTP Authentication" << endl;
            cout << "use -h for help" << endl;
            return 0;
		}
        else if (strcmp(argv[1], "-n") == 0)
        {
                if (argc > 3)
                {
                    username = argv[2];
                    password = argv[3];
                    flags = argv[4];
                    if(!flags)
                        fg = atoi(flags);
                    domain = argv[5];
                    workstation = argv[6];
                }
        }else
        {
                address = argv[1];
        }

        if (argc > 4)
        {
            if (strcmp(argv[2], "-n") == 0)
            {
                username = argv[3];
                password = argv[4];
                flags = argv[5];
                if(!flags)
                    fg = atoi(flags);
                domain = argv[6];
                workstation = argv[7];
            }
        }
	}
    cout << "Using endpoint:" << address;    

	Environment::initialize("ntlm_post.log", AXIS2_LOG_LEVEL_TRACE);

	ServiceClient sc(address);
   
	Options *options = sc.getOptions();

    if(username && password) 
    {
        options->setNTLMHTTPAuthInfo(username, password, fg,
                                    domain, workstation, AXIS2_HTTP_AUTH_TYPE_NTLM);
    }
    options->setHTTPMethod(AXIS2_HTTP_POST);
    options->setAction("http://tempuri.org/HelloWorld");

	OMNamespace * ns = new OMNamespace("http://tempuri.org", "ns1");
    OMElement * payloadElement = new OMElement(NULL,"HelloWorld", ns);
    payloadElement->setText("Hello World!");
    
    try
    {
        OMElement * response = sc.request(payloadElement, "");
        if (response)
        {
            cout << endl << "Response: " << response << endl;
        }
    }
    catch (WSFault & e)
    {
        if (sc.getLastSOAPFault())
        {
            cout << endl << "Response: " << sc.getLastSOAPFault() << endl;
        }
        else
        {
            cout << endl << "Response: " << e << endl;
        }
    }
    delete payloadElement;
}

