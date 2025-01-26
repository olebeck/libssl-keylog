#pragma once
// AUTO GENERATED DONT EDIT


// SSLKeylogPatch
int get_SSLKeylogPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// SSLPrintErrorsPatch
int get_SSLPrintErrorsPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// SSLNoVerifyPatch
int get_SSLNoVerifyPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// PsnRedirectPatch
int get_PsnRedirectPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// ShellCACheckPatch
int get_ShellCACheckPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// ShellXMPPRedirect
int get_ShellXMPPRedirect(const char** patch, int* offset, int* patch_size, unsigned int module_nid);


// Matching2TlsPortPatch
int get_Matching2TlsPortPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid);
