// AUTO GENERATED DONT EDIT


// SSLKeylogPatch
const char ssl_keylog_0x81012a6c_0x8104a568[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x37, 0xf0, 0x7a, 0xed};

const char ssl_keylog_0x81012a6c_0x8104a5a8[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x37, 0xf0, 0x9a, 0xed};

const char ssl_keylog_0x81012a6c_0x8104a78c[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x37, 0xf0, 0x8c, 0xee};

const char ssl_keylog_0x81014696_0x8104c8c8[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x38, 0xf0, 0x14, 0xe9};

const char ssl_keylog_0x81014696_0x8104ca78[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x38, 0xf0, 0xec, 0xe9};

const char ssl_keylog_0x81014696_0x8104ca50[] = {0xd4, 0xf8, 0xd0, 0x10, 0x60, 0x6d, 0x38, 0xf0, 0xd8, 0xe9};

int get_SSLKeylogPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x4ade6130: // 361-CEX, 361-DEX, 361-TOOL
	case 0x9cd6ca85: // 360-CEX, 360-DEX, 360-QAF, 360-TOOL
		*patch = ssl_keylog_0x81012a6c_0x8104a568;
		*patch_size = sizeof(ssl_keylog_0x81012a6c_0x8104a568);
		*offset = 0x12a6c;
		break;
	case 0x57fbdef4: // 363-CEX, 363-DEX, 363-QAF, 363-TOOL
		*patch = ssl_keylog_0x81012a6c_0x8104a5a8;
		*patch_size = sizeof(ssl_keylog_0x81012a6c_0x8104a5a8);
		*offset = 0x12a6c;
		break;
	case 0x29273020: // 365-CEX, 365-DEX, 365-TOOL
	case 0x71ab9ffb: // 367-CEX, 367-DEX, 367-TOOL
	case 0xc80f8f57: // 368-CEX, 368-DEX, 368-TOOL
		*patch = ssl_keylog_0x81012a6c_0x8104a78c;
		*patch_size = sizeof(ssl_keylog_0x81012a6c_0x8104a78c);
		*offset = 0x12a6c;
		break;
	case 0x3e75e16b: // 369-CEX
	case 0x4dff96bf: // 370-CEX
		*patch = ssl_keylog_0x81014696_0x8104c8c8;
		*patch_size = sizeof(ssl_keylog_0x81014696_0x8104c8c8);
		*offset = 0x14696;
		break;
	case 0xa0910f30: // 373-CEX, 373-TOOL
	case 0xb1620f91: // lssl
	case 0x3d13b1d4: // 371-CEX, 371-TOOL
	case 0xe0bce065: // 372-CEX, 372-DEX, 372-QAF
		*patch = ssl_keylog_0x81014696_0x8104ca78;
		*patch_size = sizeof(ssl_keylog_0x81014696_0x8104ca78);
		*offset = 0x14696;
		break;
	case 0x13b6a102: // 374-CEX
		*patch = ssl_keylog_0x81014696_0x8104ca50;
		*patch_size = sizeof(ssl_keylog_0x81014696_0x8104ca50);
		*offset = 0x14696;
		break;
	default:
		return -1;
	}
	return 0;
}


// SSLPrintErrorsPatch
const char ssl_print_errors_0x8101b7c0_0x8104a568[] = {0x00, 0xb5, 0x2e, 0xf0, 0xd2, 0xee, 0x5d, 0xf8, 0x04, 0xfb};

const char ssl_print_errors_0x8101b7c0_0x8104a5a8[] = {0x00, 0xb5, 0x2e, 0xf0, 0xf2, 0xee, 0x5d, 0xf8, 0x04, 0xfb};

const char ssl_print_errors_0x8101b7c0_0x8104a78c[] = {0x00, 0xb5, 0x2e, 0xf0, 0xe4, 0xef, 0x5d, 0xf8, 0x04, 0xfb};

const char ssl_print_errors_0x8101d648_0x8104c8c8[] = {0x00, 0xb5, 0x2f, 0xf0, 0x3e, 0xe9, 0x5d, 0xf8, 0x04, 0xfb};

const char ssl_print_errors_0x8101d648_0x8104ca78[] = {0x00, 0xb5, 0x2f, 0xf0, 0x16, 0xea, 0x5d, 0xf8, 0x04, 0xfb};

const char ssl_print_errors_0x8101d648_0x8104ca50[] = {0x00, 0xb5, 0x2f, 0xf0, 0x02, 0xea, 0x5d, 0xf8, 0x04, 0xfb};

int get_SSLPrintErrorsPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x4ade6130: // 361-CEX, 361-DEX, 361-TOOL
	case 0x9cd6ca85: // 360-CEX, 360-DEX, 360-QAF, 360-TOOL
		*patch = ssl_print_errors_0x8101b7c0_0x8104a568;
		*patch_size = sizeof(ssl_print_errors_0x8101b7c0_0x8104a568);
		*offset = 0x1b7c0;
		break;
	case 0x57fbdef4: // 363-CEX, 363-DEX, 363-QAF, 363-TOOL
		*patch = ssl_print_errors_0x8101b7c0_0x8104a5a8;
		*patch_size = sizeof(ssl_print_errors_0x8101b7c0_0x8104a5a8);
		*offset = 0x1b7c0;
		break;
	case 0x29273020: // 365-CEX, 365-DEX, 365-TOOL
	case 0x71ab9ffb: // 367-CEX, 367-DEX, 367-TOOL
	case 0xc80f8f57: // 368-CEX, 368-DEX, 368-TOOL
		*patch = ssl_print_errors_0x8101b7c0_0x8104a78c;
		*patch_size = sizeof(ssl_print_errors_0x8101b7c0_0x8104a78c);
		*offset = 0x1b7c0;
		break;
	case 0x3e75e16b: // 369-CEX
	case 0x4dff96bf: // 370-CEX
		*patch = ssl_print_errors_0x8101d648_0x8104c8c8;
		*patch_size = sizeof(ssl_print_errors_0x8101d648_0x8104c8c8);
		*offset = 0x1d648;
		break;
	case 0xa0910f30: // 373-CEX, 373-TOOL
	case 0xb1620f91: // lssl
	case 0x3d13b1d4: // 371-CEX, 371-TOOL
	case 0xe0bce065: // 372-CEX, 372-DEX, 372-QAF
		*patch = ssl_print_errors_0x8101d648_0x8104ca78;
		*patch_size = sizeof(ssl_print_errors_0x8101d648_0x8104ca78);
		*offset = 0x1d648;
		break;
	case 0x13b6a102: // 374-CEX
		*patch = ssl_print_errors_0x8101d648_0x8104ca50;
		*patch_size = sizeof(ssl_print_errors_0x8101d648_0x8104ca50);
		*offset = 0x1d648;
		break;
	default:
		return -1;
	}
	return 0;
}


// SSLNoVerifyPatch
const char ssl_no_verify[] = {0xc9, 0xf8, 0xd4, 0x50};

int get_SSLNoVerifyPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x29273020: // 365-CEX, 365-DEX, 365-TOOL
	case 0x9cd6ca85: // 360-CEX, 360-DEX, 360-QAF, 360-TOOL
	case 0x4ade6130: // 361-CEX, 361-DEX, 361-TOOL
	case 0x57fbdef4: // 363-CEX, 363-DEX, 363-QAF, 363-TOOL
	case 0xc80f8f57: // 368-CEX, 368-DEX, 368-TOOL
	case 0x71ab9ffb: // 367-CEX, 367-DEX, 367-TOOL
		*patch = ssl_no_verify;
		*patch_size = sizeof(ssl_no_verify);
		*offset = 0xe94e;
		break;
	case 0x13b6a102: // 374-CEX
	case 0xe0bce065: // 372-CEX, 372-DEX, 372-QAF
	case 0x3e75e16b: // 369-CEX
	case 0xa0910f30: // 373-CEX, 373-TOOL
	case 0xb1620f91: // lssl
	case 0x3d13b1d4: // 371-CEX, 371-TOOL
	case 0x4dff96bf: // 370-CEX
		*patch = ssl_no_verify;
		*patch_size = sizeof(ssl_no_verify);
		*offset = 0x102ce;
		break;
	default:
		return -1;
	}
	return 0;
}


// PsnRedirectPatch
const char psn_redirect_0x81002596_0x810182f4[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0x7a, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xa2, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x5b, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0x94, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x66, 0xff, 0x09, 0xe0};

const char psn_redirect_0x81002596_0x81018354[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0xaa, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xd2, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x5b, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xc4, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x66, 0xff, 0x09, 0xe0};

const char psn_redirect_0x81002596_0x81018370[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0xb8, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xe0, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x69, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xd2, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x74, 0xff, 0x09, 0xe0};

int get_PsnRedirectPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x751039e1: // 361-DEX
	case 0xb015b405: // 360-CEX
	case 0x356e041b: // 363-DEX
	case 0xe222489b: // 363-QAF, 363-TOOL
	case 0x548b4754: // 361-CEX
	case 0x72aab836: // 360-DEX
	case 0x545b24b7: // 363-CEX
	case 0xf7c71fbb: // 361-TOOL
	case 0x776f287d: // 360-TOOL
	case 0xbea1205f: // 360-QAF
		*patch = psn_redirect_0x81002596_0x810182f4;
		*patch_size = sizeof(psn_redirect_0x81002596_0x810182f4);
		*offset = 0x2596;
		break;
	case 0x6cc68689: // 367-DEX
	case 0xa4ee4fd0: // 368-TOOL
	case 0x65d8aa31: // 367-CEX
	case 0xd90c9b72: // 368-CEX
	case 0xd172bcd3: // 365-TOOL
	case 0x9ee29c74: // 365-DEX
	case 0x40403cf5: // 368-DEX
	case 0x7b2c16b7: // 367-TOOL
	case 0xf8ac499b: // 365-CEX
		*patch = psn_redirect_0x81002596_0x81018354;
		*patch_size = sizeof(psn_redirect_0x81002596_0x81018354);
		*offset = 0x2596;
		break;
	case 0x0fbd68a0: // 373-TOOL
	case 0xe14bbda1: // 373-CEX
	case 0x8a536365: // 371-CEX
	case 0x963fbaea: // 372-DEX
	case 0x12c12f6c: // 371-TOOL
	case 0x861b880e: // 372-QAF
	case 0xf82fc630: // 370-CEX
	case 0x27de0e91: // 372-CEX
	case 0x02733194: // lhttp
	case 0xda3a5e57: // 369-CEX
	case 0x4deb60db: // 374-CEX
		*patch = psn_redirect_0x81002596_0x81018370;
		*patch_size = sizeof(psn_redirect_0x81002596_0x81018370);
		*offset = 0x2596;
		break;
	default:
		return -1;
	}
	return 0;
}


// ShellCACheckPatch
const char shell_ca_check_patch[] = {0x4f, 0xf0, 0x00, 0x00, 0x70, 0x47};

int get_ShellCACheckPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x0552f692: // 360-CEX
	case 0x532155e5: // 361-CEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x325974;
		break;
	case 0xeab89d5c: // 360-DEX
	case 0x7a5f8457: // 361-DEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x31c3bc;
		break;
	case 0xb96bcfc3: // 360-QAF
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x325bd4;
		break;
	case 0x232d733b: // 361-TOOL
	case 0x6cb01295: // 360-TOOL
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x317ac8;
		break;
	case 0xbb4b0a3e: // 363-CEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x325a10;
		break;
	case 0xe7c5011a: // 363-DEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x31c458;
		break;
	case 0xe541db9b: // 363-QAF, 363-TOOL
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x317b64;
		break;
	case 0x12dac0f3: // 368-CEX
	case 0x34b4d82e: // 367-CEX
	case 0x5549bf1f: // 365-CEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x325db8;
		break;
	case 0x3c652b1a: // 367-DEX
	case 0x587f9ced: // 365-DEX
	case 0x4df04256: // 368-DEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x31c800;
		break;
	case 0xab5c2a00: // 367-TOOL
	case 0x4fe7c671: // 368-TOOL
	case 0xe6a02f2b: // 365-TOOL
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x317f34;
		break;
	case 0x2053b5a5: // 370-CEX
	case 0xf476e785: // 371-CEX
	case 0x51cb6207: // 374-CEX
	case 0x0703c828: // 369-CEX
	case 0x939ffbe9: // 372-CEX
	case 0x734d476a: // 373-CEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x325dc8;
		break;
	case 0x4670a0c8: // 373-TOOL
	case 0xc5b7c871: // 371-TOOL
	case 0xb45216f4: // 372-QAF
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x317f44;
		break;
	case 0xa6509361: // 372-DEX
		*patch = shell_ca_check_patch;
		*patch_size = sizeof(shell_ca_check_patch);
		*offset = 0x31c810;
		break;
	default:
		return -1;
	}
	return 0;
}


// ShellXMPPRedirect
const char shell_xmpp_redirect_patch_0x81310bf6_0x81458000[] = {0x47, 0xf1, 0x04, 0xea};

const char shell_xmpp_redirect_patch_0x8130763e_0x8144e1c8[] = {0x46, 0xf1, 0xc4, 0xed};

const char shell_xmpp_redirect_patch_0x81310e56_0x81458250[] = {0x47, 0xf1, 0xfc, 0xe9};

const char shell_xmpp_redirect_patch_0x81302d4a_0x81449788[] = {0x46, 0xf1, 0x1e, 0xed};

const char shell_xmpp_redirect_patch_0x81310c92_0x814580a0[] = {0x47, 0xf1, 0x06, 0xea};

const char shell_xmpp_redirect_patch_0x813076da_0x8144e260[] = {0x46, 0xf1, 0xc2, 0xed};

const char shell_xmpp_redirect_patch_0x81302de6_0x81449828[] = {0x46, 0xf1, 0x20, 0xed};

const char shell_xmpp_redirect_patch_0x8131103a_0x81458448[] = {0x47, 0xf1, 0x06, 0xea};

const char shell_xmpp_redirect_patch_0x81307a82_0x8144e608[] = {0x46, 0xf1, 0xc2, 0xed};

const char shell_xmpp_redirect_patch_0x813031b6_0x81449bf8[] = {0x46, 0xf1, 0x20, 0xed};

const char shell_xmpp_redirect_patch_0x8131103a_0x81458468[] = {0x47, 0xf1, 0x16, 0xea};

const char shell_xmpp_redirect_patch_0x813031b6_0x81449c20[] = {0x46, 0xf1, 0x34, 0xed};

const char shell_xmpp_redirect_patch_0x81307a82_0x8144e630[] = {0x46, 0xf1, 0xd6, 0xed};

int get_ShellXMPPRedirect(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x0552f692: // 360-CEX
	case 0x532155e5: // 361-CEX
		*patch = shell_xmpp_redirect_patch_0x81310bf6_0x81458000;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81310bf6_0x81458000);
		*offset = 0x310bf6;
		break;
	case 0xeab89d5c: // 360-DEX
	case 0x7a5f8457: // 361-DEX
		*patch = shell_xmpp_redirect_patch_0x8130763e_0x8144e1c8;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x8130763e_0x8144e1c8);
		*offset = 0x30763e;
		break;
	case 0xb96bcfc3: // 360-QAF
		*patch = shell_xmpp_redirect_patch_0x81310e56_0x81458250;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81310e56_0x81458250);
		*offset = 0x310e56;
		break;
	case 0x232d733b: // 361-TOOL
	case 0x6cb01295: // 360-TOOL
		*patch = shell_xmpp_redirect_patch_0x81302d4a_0x81449788;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81302d4a_0x81449788);
		*offset = 0x302d4a;
		break;
	case 0xbb4b0a3e: // 363-CEX
		*patch = shell_xmpp_redirect_patch_0x81310c92_0x814580a0;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81310c92_0x814580a0);
		*offset = 0x310c92;
		break;
	case 0xe7c5011a: // 363-DEX
		*patch = shell_xmpp_redirect_patch_0x813076da_0x8144e260;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x813076da_0x8144e260);
		*offset = 0x3076da;
		break;
	case 0xe541db9b: // 363-QAF, 363-TOOL
		*patch = shell_xmpp_redirect_patch_0x81302de6_0x81449828;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81302de6_0x81449828);
		*offset = 0x302de6;
		break;
	case 0x12dac0f3: // 368-CEX
	case 0x34b4d82e: // 367-CEX
	case 0x5549bf1f: // 365-CEX
		*patch = shell_xmpp_redirect_patch_0x8131103a_0x81458448;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x8131103a_0x81458448);
		*offset = 0x31103a;
		break;
	case 0x3c652b1a: // 367-DEX
	case 0x587f9ced: // 365-DEX
	case 0x4df04256: // 368-DEX
		*patch = shell_xmpp_redirect_patch_0x81307a82_0x8144e608;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81307a82_0x8144e608);
		*offset = 0x307a82;
		break;
	case 0xab5c2a00: // 367-TOOL
	case 0x4fe7c671: // 368-TOOL
	case 0xe6a02f2b: // 365-TOOL
		*patch = shell_xmpp_redirect_patch_0x813031b6_0x81449bf8;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x813031b6_0x81449bf8);
		*offset = 0x3031b6;
		break;
	case 0x2053b5a5: // 370-CEX
	case 0xf476e785: // 371-CEX
	case 0x51cb6207: // 374-CEX
	case 0x0703c828: // 369-CEX
	case 0x939ffbe9: // 372-CEX
	case 0x734d476a: // 373-CEX
		*patch = shell_xmpp_redirect_patch_0x8131103a_0x81458468;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x8131103a_0x81458468);
		*offset = 0x31103a;
		break;
	case 0x4670a0c8: // 373-TOOL
	case 0xc5b7c871: // 371-TOOL
	case 0xb45216f4: // 372-QAF
		*patch = shell_xmpp_redirect_patch_0x813031b6_0x81449c20;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x813031b6_0x81449c20);
		*offset = 0x3031b6;
		break;
	case 0xa6509361: // 372-DEX
		*patch = shell_xmpp_redirect_patch_0x81307a82_0x8144e630;
		*patch_size = sizeof(shell_xmpp_redirect_patch_0x81307a82_0x8144e630);
		*offset = 0x307a82;
		break;
	default:
		return -1;
	}
	return 0;
}


// Matching2TlsPortPatch
const char np_matching2_tls_patch[] = {0x40, 0xf6, 0x98, 0x51};

int get_Matching2TlsPortPatch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x85e47c80: // 368-TOOL
	case 0x34ada081: // 365-TOOL
	case 0x67435d82: // 371-TOOL
	case 0x05db4084: // 371-CEX
	case 0x7ada9407: // 368-DEX
	case 0x0b279888: // 365-DEX
	case 0x04224f89: // 361-DEX
	case 0x2524248b: // 360-TOOL
	case 0x96822b16: // 363-CEX
	case 0x9d187521: // 363-QAF, 363-TOOL
	case 0x4d701ea1: // 368-CEX
	case 0xfeefd5a3: // 361-TOOL
	case 0xa66effab: // 367-TOOL
	case 0x264af8ab: // 373-CEX
	case 0xa9eb5533: // 374-CEX
	case 0x73a34dc0: // 372-CEX
	case 0xe991cb43: // 369-CEX
	case 0x8003114b: // 363-DEX
	case 0x6b92da59: // 365-CEX
	case 0x7c7c6bda: // 370-CEX
	case 0x9b6e9b68: // 372-QAF
	case 0x4892f1eb: // 361-CEX
	case 0xc0a286eb: // 367-DEX
	case 0x515c27f0: // 367-CEX
	case 0x729da3f1: // 360-QAF
	case 0x4bebbdf3: // 360-CEX
	case 0x72ee4373: // 372-DEX
	case 0x5e983677: // 373-TOOL
	case 0x874ddd78: // 360-DEX
		*patch = np_matching2_tls_patch;
		*patch_size = sizeof(np_matching2_tls_patch);
		*offset = 0x20196;
		break;
	default:
		return -1;
	}
	return 0;
}
