WSO2 WSF/C++
============

Upstream project : http://wso2.com/products/web-services-framework/cpp/
Upstream SVN trunk : https://svn.wso2.org/repos/wso2/trunk/wsf/cpp/

> The WSO2 Web Services Framework for C++ is one of the most comprehensive Web Services Frameworks available for the C++ world, providing simple APIs for implementing Web services and Web service clients.

This repository contains various bug fixes that are not integrated upstream, although some of them have been submitted.

As the original software, this WSF/C++ modification is licensed under the Apache License 2.0.

Build instructions
------------------

Linux build has been successfully tested on FC18 with the following configure command :

    ./configure --prefix=<PREFIX> --disable-wsclient --disable-sandesha --disable-savan --enable-openssl --with-openssl --with-axis2

This will yield a WSF/C++ installation with Rampart and SSL enabled.

The configure scripts are a bit tricky, so other flag combinations can entail unexpected results.
