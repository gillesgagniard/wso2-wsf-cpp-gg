
AUTOCONF = configure.in
!include $(AUTOCONF)

RAMPART = rampart
RAMPART_SOURCE_DIR = ..\..\

RAMPART_INTDIR = .\int.msvc

MAJOR_VER = 1
MINOR_VER = 3
PATCH_VER = 0

RAMPART_DIST_NAME = .\..\rampartc-$(MAJOR_VER).$(MINOR_VER).$(PATCH_VER)
RAMPART_DISTDIR = $(RAMPART_DIST_NAME)
RAMPART_SAMPLE_BIN_DIR = $(RAMPART_DISTDIR)\samples\bin\rampartc
RAMPART_SAMPLE_LIB_DIR = $(RAMPART_DISTDIR)\samples\lib\rampartc
RAMPART_SAMPLE_SERVICE_DIR = $(RAMPART_DISTDIR)\services
RAMPART_SAMPLE_DATA_DIR = $(RAMPART_DISTDIR)\samples\src\rampartc\data
RAMPART_SAMPLE_POLICY_DIR = $(RAMPART_DISTDIR)\samples\src\rampartc\secpolicy
RAMPART_SAMPLE_SRC_DIR = $(RAMPART_DISTDIR)\samples\src\rampartc

#rampart module

OMXMLSEC_SRC = $(RAMPART_SOURCE_DIR)\src\omxmlsec\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\tokens\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\c14n\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\openssl\*.c \
			   $(RAMPART_SOURCE_DIR)\src\omxmlsec\saml\*.c 

MOD_RAMPART_SRC = $(RAMPART_SOURCE_DIR)\src\core\*.c \
		  $(RAMPART_SOURCE_DIR)\src\handlers\*.c 

RAMPART_SRC = $(RAMPART_SOURCE_DIR)\src\util\*.c 

SECCONV_SRC = $(RAMPART_SOURCE_DIR)\src\secconv\*.c

TRUST_SRC = $(RAMPART_SOURCE_DIR)\src\trust\*.c

RAHAS_SRC = $(RAMPART_SOURCE_DIR)\src\rahas\*.c

MOD_RAMPART_INCLUDE_PATH = /I$(RAMPART_SOURCE_DIR)\include \
		           /I$(OPENSSL_BIN_DIR)\include \
			   /I$(AXIS2_BIN_DIR)\include

APPLINK_FILE = $(OPENSSL_BIN_DIR)\include\openssl\applink.c

AXIS2_LIBS = $(AXIS2_BIN_DIR)\lib
AXIS2_MODS = $(AXIS2_BIN_DIR)\modules

##################### compiler options

CC = @cl.exe 
CFLAGS = /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "AXIS2_DECLARE_EXPORT"   \
	 /D "AXIS2_SVR_MULTI_THREADED" /w /nologo $(AXIS2_INCLUDE_PATH) 

################### linker options

LD = @link.exe
LDFLAGS = /nologo /LIBPATH:$(AXIS2_LIBS) /LIBPATH:$(OPENSSL_BIN_DIR)\lib\VC \
	  /LIBPATH:$(AXIS2_BIN_DIR)\lib

SSL_LIB_FLAG = "MD"
!if "$(CRUNTIME)" == "/MT"
SSL_LIB_FLAG = "MT"
!endif

#debug symbols
!if "$(DEBUG)" == "1"
LIBS = $(LIBS) libeay32$(SSL_LIB_FLAG)d.lib ssleay32$(SSL_LIB_FLAG)d.lib
!else
LIBS = $(LIBS) libeay32$(SSL_LIB_FLAG).lib ssleay32$(SSL_LIB_FLAG).lib
!endif

####################
MT=mt.exe
MT="$(MT)"

!if "$(EMBED_MANIFEST)" == "0"
_VC_MANIFEST_EMBED_EXE=
_VC_MANIFEST_EMBED_DLL=
!else
_VC_MANIFEST_EMBED_EXE= if exist $@.manifest $(MT) -nologo -manifest $@.manifest -outputresource:$@;1
_VC_MANIFEST_EMBED_DLL= if exist $@.manifest $(MT) -nologo -manifest $@.manifest -outputresource:$@;2
!endif


#################### debug symbol

!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS) /D "_DEBUG" /Od /Z7 $(CRUNTIME)d
LDFLAGS = $(LDFLAGS) /DEBUG
!else
CFLAGS = $(CFLAGS) /D "NDEBUG" /O2 $(CRUNTIME)
LDFLAGS = $(LDFLAGS)
!endif

#################### hack!
CFLAGS = $(CFLAGS) /D "_WINSOCKAPI_"

distdir:
	if not exist $(RAMPART_DISTDIR)	mkdir $(RAMPART_DISTDIR)
	if not exist $(RAMPART_SAMPLE_BIN_DIR) mkdir $(RAMPART_SAMPLE_BIN_DIR)
	if not exist $(RAMPART_SAMPLE_LIB_DIR) mkdir $(RAMPART_SAMPLE_LIB_DIR)
	if not exist $(RAMPART_SAMPLE_DATA_DIR) mkdir $(RAMPART_SAMPLE_DATA_DIR)
	if not exist $(RAMPART_SAMPLE_POLICY_DIR) mkdir $(RAMPART_SAMPLE_POLICY_DIR)
	if not exist $(RAMPART_SAMPLE_SRC_DIR) mkdir $(RAMPART_SAMPLE_SRC_DIR)
	if not exist $(RAMPART_SAMPLE_SERVICE_DIR) mkdir $(RAMPART_SAMPLE_SERVICE_DIR)
	if not exist $(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo	mkdir $(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo
	if not exist $(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo	mkdir $(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo
	if not exist $(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts	mkdir $(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts	
	if not exist $(RAMPART_DISTDIR)\modules\rampart	mkdir $(RAMPART_DISTDIR)\modules\rampart
	if not exist $(RAMPART_DISTDIR)\modules\rahas mkdir $(RAMPART_DISTDIR)\modules\rahas
	if not exist $(RAMPART_DISTDIR)\include mkdir $(RAMPART_DISTDIR)\include                              
	if not exist $(RAMPART_DISTDIR)\lib mkdir $(RAMPART_DISTDIR)\lib                              

clean: 
	if exist $(RAMPART_DISTDIR) rmdir /S /Q $(RAMPART_DISTDIR)
	if exist $(RAMPART_INTDIR)  rmdir /S /Q $(RAMPART_INTDIR)

intdirs:
	if not exist $(RAMPART_INTDIR) mkdir $(RAMPART_INTDIR)

	if not exist $(RAMPART_INTDIR)\rahas mkdir $(RAMPART_INTDIR)\rahas
	if not exist $(RAMPART_INTDIR)\rampart mkdir $(RAMPART_INTDIR)\rampart
	if not exist $(RAMPART_INTDIR)\samples\callback\pwcb mkdir $(RAMPART_INTDIR)\samples\callback\pwcb
	if not exist $(RAMPART_INTDIR)\samples\authn_provider mkdir $(RAMPART_INTDIR)\samples\authn_provider
	if not exist $(RAMPART_INTDIR)\samples\replay_detector mkdir $(RAMPART_INTDIR)\samples\replay_detector
	if not exist $(RAMPART_INTDIR)\samples\sct_provider mkdir $(RAMPART_INTDIR)\samples\sct_provider
	if not exist $(RAMPART_INTDIR)\samples\services\sec_echo\ mkdir $(RAMPART_INTDIR)\samples\services\sec_echo
	if not exist $(RAMPART_INTDIR)\samples\services\secconv_echo\ mkdir $(RAMPART_INTDIR)\samples\services\secconv_echo
	if not exist $(RAMPART_INTDIR)\samples\services\saml_sts\ mkdir $(RAMPART_INTDIR)\samples\services\saml_sts
	if not exist $(RAMPART_INTDIR)\samples\client\sec_echo\ mkdir $(RAMPART_INTDIR)\samples\client\sec_echo
	if not exist $(RAMPART_INTDIR)\samples\client\saml_echo\ mkdir $(RAMPART_INTDIR)\samples\client\saml_echo
	if not exist $(RAMPART_INTDIR)\samples\client\issued_token\ mkdir $(RAMPART_INTDIR)\samples\client\issued_token
	if not exist $(RAMPART_INTDIR)\samples\client\saml_protect\ mkdir $(RAMPART_INTDIR)\samples\client\saml_protect
	if not exist $(RAMPART_INTDIR)\samples\credential_provider\ mkdir $(RAMPART_INTDIR)\samples\credential_provider

mod_rampart_sample_data:
	copy $(RAMPART_SOURCE_DIR)\samples\data\passwords.txt $(RAMPART_SAMPLE_DATA_DIR)

$(RAMPART_DISTDIR)\lib\rampart.dll : $(RAMPART_SRC) $(OMXMLSEC_SRC) $(SECCONV_SRC) $(TRUST_SRC)
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SRC) $(OMXMLSEC_SRC) $(SECCONV_SRC) $(TRUST_SRC) \
	$(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\*.obj $(LIBS) axutil.lib axiom.lib \
	axis2_parser.lib axis2_engine.lib neethi.lib /DLL /OUT:$(RAMPART_DISTDIR)\lib\rampart.dll \
	/IMPLIB:$(RAMPART_DISTDIR)\lib\rampart.lib
	-@$(_VC_MANIFEST_EMBED_DLL)

rampart : $(RAMPART_DISTDIR)\lib\rampart.dll

$(RAMPART_DISTDIR)\modules\rampart\mod_rampart.dll : $(MOD_RAMPART_SRC)
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(MOD_RAMPART_SRC) \
	$(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\rampart\ /c
	$(LD) /LIBPATH:$(RAMPART_DISTDIR)\lib $(LDFLAGS) $(RAMPART_INTDIR)\rampart\*.obj $(LIBS) axutil.lib axiom.lib rampart.lib\
	axis2_parser.lib axis2_engine.lib neethi.lib /DLL /OUT:$(RAMPART_DISTDIR)\modules\rampart\mod_rampart.dll \
	/IMPLIB:$(RAMPART_DISTDIR)\modules\rampart\mod_rampart.lib
	-@$(_VC_MANIFEST_EMBED_DLL)
	copy $(RAMPART_SOURCE_DIR)\src\data\module.xml $(RAMPART_DISTDIR)\modules\rampart

mod_rampart : $(RAMPART_DISTDIR)\modules\rampart\mod_rampart.dll

$(RAMPART_DISTDIR)\modules\rahas\mod_rahas.dll : $(RAHAS_SRC)
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAHAS_SRC) $(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\rahas\ /c
	$(LD) /LIBPATH:$(RAMPART_DISTDIR)\lib $(LDFLAGS) $(RAMPART_INTDIR)\rahas\*.obj $(LIBS) axutil.lib axiom.lib \
	axis2_parser.lib axis2_engine.lib neethi.lib rampart.lib \
	/DLL /OUT:$(RAMPART_DISTDIR)\modules\rahas\mod_rahas.dll /IMPLIB:$(RAMPART_DISTDIR)\modules\rahas\mod_rahas.lib
	-@$(_VC_MANIFEST_EMBED_DLL)
	copy $(RAMPART_SOURCE_DIR)\src\data\rahas_module.xml $(RAMPART_DISTDIR)\modules\rahas\module.xml

mod_rahas : $(RAMPART_DISTDIR)\modules\rahas\mod_rahas.dll

$(RAMPART_SAMPLE_LIB_DIR)\pwcb.dll : $(RAMPART_SOURCE_DIR)\samples\callback\pwcb.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\callback\pwcb.c \
	/Fo$(RAMPART_INTDIR)\samples\callback\ /c
	$(LD) $(LDFLAGS) $(LIBS) axutil.lib $(RAMPART_INTDIR)\samples\callback\*.obj \
	/DLL /OUT:$(RAMPART_SAMPLE_LIB_DIR)\pwcb.dll /IMPLIB:$(RAMPART_SAMPLE_LIB_DIR)\pwcb.lib
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_pwcb: $(RAMPART_SAMPLE_LIB_DIR)\pwcb.dll


$(RAMPART_SAMPLE_LIB_DIR)\authn.dll : $(RAMPART_SOURCE_DIR)\samples\authn_provider\authn_provider.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\authn_provider\authn_provider.c \
	/Fo$(RAMPART_INTDIR)\samples\authn_provider\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\authn_provider\*.obj rampart.lib \
	axutil.lib /LIBPATH:$(RAMPART_DISTDIR)\lib /DLL \
	/OUT:$(RAMPART_SAMPLE_LIB_DIR)\authn.dll
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_authn : $(RAMPART_SAMPLE_LIB_DIR)\authn.dll

$(RAMPART_SAMPLE_LIB_DIR)\rdflatfile.dll : $(RAMPART_SOURCE_DIR)\samples\replay_detector\*.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\replay_detector\*.c \
	/Fo$(RAMPART_INTDIR)\samples\replay_detector\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\replay_detector\*.obj rampart.lib \
	axutil.lib axis2_engine.lib /LIBPATH:$(RAMPART_DISTDIR)\lib /DLL \
	/OUT:$(RAMPART_SAMPLE_LIB_DIR)\rdflatfile.dll
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_rd: $(RAMPART_SAMPLE_LIB_DIR)\rdflatfile.dll

$(RAMPART_SAMPLE_LIB_DIR)\sctprovider.dll : $(RAMPART_SOURCE_DIR)\samples\sct_provider\sct_provider_stored_key.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\sct_provider\sct_provider_stored_key.c \
	/Fo$(RAMPART_INTDIR)\samples\sct_provider\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\sct_provider\sct_provider_stored_key.obj rampart.lib \
	axutil.lib axis2_engine.lib neethi.lib /LIBPATH:$(RAMPART_DISTDIR)\lib /DLL \
	/OUT:$(RAMPART_SAMPLE_LIB_DIR)\sctprovider.dll
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_sct_provider: $(RAMPART_SAMPLE_LIB_DIR)\sctprovider.dll

$(RAMPART_SAMPLE_LIB_DIR)\sctprovider_hashdb.dll : $(RAMPART_SOURCE_DIR)\samples\sct_provider\sct_provider_hash_map.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\sct_provider\sct_provider_hash_map.c \
	/Fo$(RAMPART_INTDIR)\samples\sct_provider\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\sct_provider\sct_provider_hash_map.obj rampart.lib \
	axutil.lib axis2_engine.lib neethi.lib /LIBPATH:$(RAMPART_DISTDIR)\lib /DLL \
	/OUT:$(RAMPART_SAMPLE_LIB_DIR)\sctprovider_hashdb.dll
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_sct_provider_hashdb: $(RAMPART_SAMPLE_LIB_DIR)\sctprovider_hashdb.dll

$(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo\sec_echo.dll : $(RAMPART_SOURCE_DIR)\samples\server\sec_echo\*.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) /I$(RAMPART_SOURCE_DIR)\samples\server\sec_echo \
	$(RAMPART_SOURCE_DIR)\samples\server\sec_echo\*.c $(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\samples\services\sec_echo\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\services\sec_echo\*.obj \
	axutil.lib axiom.lib axis2_parser.lib $(LIBS) axis2_engine.lib \
	axis2_http_receiver.lib axis2_http_sender.lib \
	rampart.lib /LIBPATH:$(RAMPART_DISTDIR)\lib \
        /DLL /OUT:$(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo\sec_echo.dll
	-@$(_VC_MANIFEST_EMBED_DLL)
	
	copy $(RAMPART_SOURCE_DIR)\samples\server\sec_echo\services.xml $(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo\

mod_rampart_services_sec_echo: $(RAMPART_SAMPLE_SERVICE_DIR)\sec_echo\sec_echo.dll


$(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts\saml_sts.dll : $(RAMPART_SOURCE_DIR)\samples\server\saml_sts\*.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) /I$(RAMPART_SOURCE_DIR)\samples\server\saml_sts \
	$(RAMPART_SOURCE_DIR)\samples\server\saml_sts\*.c /Fo$(RAMPART_INTDIR)\samples\services\saml_sts\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\services\saml_sts\*.obj \
	axutil.lib axiom.lib axis2_parser.lib $(LIBS) axis2_engine.lib /LIBPATH:$(RAMPART_DISTDIR)\lib\ \
	axis2_http_receiver.lib axis2_http_sender.lib rampart.lib \
        /DLL /OUT:$(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts\saml_sts.dll
	-@$(_VC_MANIFEST_EMBED_DLL)
	
	copy $(RAMPART_SOURCE_DIR)\samples\server\saml_sts\services.xml $(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts\

mod_rampart_services_saml_sts: $(RAMPART_SAMPLE_SERVICE_DIR)\saml_sts\saml_sts.dll

$(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo\secconv_echo.dll : $(RAMPART_SOURCE_DIR)\samples\server\secconv_echo\*.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) /I$(RAMPART_SOURCE_DIR)\samples\server\secconv_echo \
	$(RAMPART_SOURCE_DIR)\samples\server\secconv_echo\*.c $(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\samples\services\secconv_echo\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\services\secconv_echo\*.obj \
	axutil.lib axiom.lib axis2_parser.lib $(LIBS) axis2_engine.lib rampart.lib /LIBPATH:$(RAMPART_DISTDIR)\lib\
	axis2_http_receiver.lib axis2_http_sender.lib \
        /DLL /OUT:$(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo\secconv_echo.dll
	-@$(_VC_MANIFEST_EMBED_DLL)
	
	copy $(RAMPART_SOURCE_DIR)\samples\server\secconv_echo\services.xml $(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo\

mod_rampart_services_secconv_echo: $(RAMPART_SAMPLE_SERVICE_DIR)\secconv_echo\secconv_echo.dll

$(RAMPART_SAMPLE_BIN_DIR)\sec_echo.exe : $(RAMPART_SOURCE_DIR)\samples\client\sec_echo\echo.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) \
        $(RAMPART_SOURCE_DIR)\samples\client\sec_echo\echo.c \
        /Fo$(RAMPART_INTDIR)\samples\client\sec_echo\ /c
	$(LD) $(LDFLAGS) /FIXED:No $(RAMPART_INTDIR)\samples\client\sec_echo\echo.obj axutil.lib axiom.lib neethi.lib \
        axis2_parser.lib axis2_engine.lib /LIBPATH:$(RAMPART_DISTDIR)\lib rampart.lib /OUT:$(RAMPART_SAMPLE_BIN_DIR)\sec_echo.exe
	-@$(_VC_MANIFEST_EMBED_EXE)
			
mod_rampart_samples_sec_echo: $(RAMPART_SAMPLE_BIN_DIR)\sec_echo.exe

####### SAML Echo
$(RAMPART_SAMPLE_BIN_DIR)\saml_echo.exe : $(RAMPART_SOURCE_DIR)\samples\client\saml_echo\echo.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) \
        $(RAMPART_SOURCE_DIR)\samples\client\saml_echo\echo.c $(APPLINK_FILE) \
        /Fo$(RAMPART_INTDIR)\samples\client\saml_echo\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\client\saml_echo\echo.obj axutil.lib axiom.lib neethi.lib \
		axis2_parser.lib axis2_engine.lib /FIXED:NO /LIBPATH:$(RAMPART_DISTDIR)\lib rampart.lib /OUT:$(RAMPART_SAMPLE_BIN_DIR)\saml_echo.exe
	-@$(_VC_MANIFEST_EMBED_EXE)
			
mod_rampart_samples_saml_echo: $(RAMPART_SAMPLE_BIN_DIR)\saml_echo.exe	

$(RAMPART_SAMPLE_BIN_DIR)\issued_token_echo.exe : $(RAMPART_SOURCE_DIR)\samples\client\issued_token\echo.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) \
        $(RAMPART_SOURCE_DIR)\samples\client\issued_token\echo.c \
        /Fo$(RAMPART_INTDIR)\samples\client\issued_token\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\client\issued_token\echo.obj axutil.lib axiom.lib neethi.lib \
        axis2_parser.lib axis2_engine.lib /LIBPATH:$(RAMPART_DISTDIR)\lib rampart.lib /OUT:$(RAMPART_SAMPLE_BIN_DIR)\issued_token_echo.exe
	-@$(_VC_MANIFEST_EMBED_EXE)
			
mod_rampart_samples_issued_token: $(RAMPART_SAMPLE_BIN_DIR)\issued_token_echo.exe	

$(RAMPART_SAMPLE_BIN_DIR)\saml_protect_echo.exe : $(RAMPART_SOURCE_DIR)\samples\client\saml_protect\echo.c 
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) \
        $(RAMPART_SOURCE_DIR)\samples\client\saml_protect\echo.c \
        /Fo$(RAMPART_INTDIR)\samples\client\saml_protect\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\client\saml_protect\echo.obj axutil.lib axiom.lib neethi.lib \
        axis2_parser.lib axis2_engine.lib /LIBPATH:$(RAMPART_DISTDIR)\lib rampart.lib /OUT:$(RAMPART_SAMPLE_BIN_DIR)\saml_protect_echo.exe 
	-@$(_VC_MANIFEST_EMBED_EXE)
			
mod_rampart_samples_saml_protect: $(RAMPART_SAMPLE_BIN_DIR)\saml_protect_echo.exe

$(RAMPART_SAMPLE_LIB_DIR)\cred_provider.dll : $(RAMPART_SOURCE_DIR)\samples\credential_provider\*.c
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) \
        $(RAMPART_SOURCE_DIR)\samples\credential_provider\*.c \
        /Fo$(RAMPART_INTDIR)\samples\credential_provider\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\credential_provider\cred_provider.obj \
        axutil.lib axiom.lib axis2_parser.lib $(LIBS) axis2_engine.lib \
        axis2_http_receiver.lib axis2_http_sender.lib \
        /DLL /OUT:$(RAMPART_SAMPLE_LIB_DIR)\cred_provider.dll
	-@$(_VC_MANIFEST_EMBED_DLL)

mod_rampart_samples_credential_provider: $(RAMPART_SAMPLE_LIB_DIR)\cred_provider.dll

mod_rampart_samples: mod_rampart_samples_sec_echo mod_rampart_services_sec_echo mod_rampart_services_secconv_echo mod_rampart_samples_saml_protect

mod_rampart_copy_include:
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\include $(RAMPART_DISTDIR)\include

mod_rampart_copy_keys:
	if not exist $(RAMPART_SAMPLE_DATA_DIR)\keys mkdir $(RAMPART_SAMPLE_DATA_DIR)\keys
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\keys\* $(RAMPART_SAMPLE_DATA_DIR)\keys

mod_rampart_copy_deploy:
	copy deploy_rampart.bat $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\samples\client\sec_echo\update_n_run.bat $(RAMPART_SAMPLE_BIN_DIR)
	copy $(RAMPART_SOURCE_DIR)\samples\client\saml_echo\update_n_run.bat $(RAMPART_SAMPLE_BIN_DIR)\saml_update_n_run.bat
	copy $(RAMPART_SOURCE_DIR)\samples\data\server_axis2.xml $(RAMPART_SAMPLE_DATA_DIR)\ 

copy_sec_policy:
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\secpolicy $(RAMPART_SAMPLE_POLICY_DIR)\

copy_dist_files:
	copy $(RAMPART_SOURCE_DIR)\README $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\INSTALL $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\AUTHORS $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\COPYING $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\LICENSE $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\NEWS $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\NOTICE $(RAMPART_DISTDIR)
	copy $(RAMPART_SOURCE_DIR)\ChangeLog $(RAMPART_DISTDIR)


#copy make_bin_dist.bat $(RAMPART_DISTDIR)

mod_rampart_all: rampart mod_rampart mod_rampart_authn mod_rampart_rd mod_rampart_sct_provider mod_rampart_sct_provider_hashdb mod_rampart_pwcb mod_rampart_htpwcb mod_rampart_samples mod_rampart_copy_include copy_dist_files

mv_dist:
	move $(RAMPART_DISTDIR) $(RAMPART_DIST_NAME)

del_am:
	chdir $(RAMPART_DISTDIR)
	del /s *.am
	chdir .\..\win32

copy_docs:
	if exist $(RAMPART_SOURCE_DIR)\docs xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\docs $(RAMPART_DISTDIR)\docs 

install: distdir intdirs rampart mod_rampart mod_rahas mod_rampart_pwcb mod_rampart_authn mod_rampart_rd mod_rampart_sct_provider mod_rampart_sct_provider_hashdb mod_rampart_services_sec_echo mod_rampart_services_secconv_echo mod_rampart_services_saml_sts mod_rampart_samples_sec_echo mod_rampart_samples_saml_echo mod_rampart_samples_issued_token mod_rampart_samples_saml_protect mod_rampart_samples_credential_provider mod_rampart_copy_deploy mod_rampart_copy_include copy_dist_files copy_sec_policy mod_rampart_copy_keys del_am mod_rampart_sample_data copy_docs

dist_no_samples: clean distdir intdirs rampart mod_rampart mod_rahas mod_rampart_copy_include copy_dist_files


copy_samples:
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\authn_provider $(RAMPART_SAMPLE_SRC_DIR)\authn_provider
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\callback $(RAMPART_SAMPLE_SRC_DIR)\callback
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\client $(RAMPART_SAMPLE_SRC_DIR)\client
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\credential_provider $(RAMPART_SAMPLE_SRC_DIR)\credential_provider
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\replay_detector $(RAMPART_SAMPLE_SRC_DIR)\replay_detector
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\sct_provider $(RAMPART_SAMPLE_SRC_DIR)\sct_provider
	@xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\samples\server $(RAMPART_SAMPLE_SRC_DIR)\server
	@cd $(RAMPART_SAMPLE_SRC_DIR)
	@del /s /q *.am
	@cd .\..\..\..\..\win32

dist: install copy_samples

deploy: dist
	chdir $(RAMPART_DISTDIR)
	deploy_rampart.bat
	chdir ..\win32

