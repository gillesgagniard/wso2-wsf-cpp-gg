# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
TESTS = link_list_test
check_PROGRAMS = link_list_test
noinst_PROGRAMS = link_list_test
link_list_test_SOURCES = link_list_test.c ../util/create_env.c

link_list_test_LDADD   =   \
                    $(top_builddir)/src/libaxutil.la 

INCLUDES = -I$(top_builddir)/include \
			-I$(CUTEST_HOME)/include \
			-I ../../../axiom/include \
			-I ../../../include \
		 	-I ../../../test/cutest/include


