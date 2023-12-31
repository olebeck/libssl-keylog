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
