#pragma once

// Local development defaults. Replace these at build time for production.
#ifndef APP_SERVER_HOST
#define APP_SERVER_HOST L"127.0.0.1"
#endif
#ifndef APP_SERVER_PORT
#define APP_SERVER_PORT 5555
#endif
#ifndef APP_SERVER_TLS
#define APP_SERVER_TLS 0
#endif
#ifndef APP_CLIENT_API_KEY
#define APP_CLIENT_API_KEY "clk_6DJSR8fExILbliA-KojmhZMTh4ZbI-WLL1YUGBYWcDNIylo5"
#endif
#ifndef APP_HMAC_SALT
#define APP_HMAC_SALT "hmac_X-n5U4AoteIJd3f3oyuhfaxpcuIb1gyFtVtx1vMgKz8tTlw9RTswPfsroNEn2Nbi"
#endif

#ifndef FEATURE_SERVER_HOST
#define FEATURE_SERVER_HOST L"127.0.0.1"
#endif
#ifndef FEATURE_SERVER_PORT
#define FEATURE_SERVER_PORT 80
#endif
#ifndef FEATURE_SERVER_TLS
#define FEATURE_SERVER_TLS 0
#endif
#ifndef FEATURE_API_PATH
#define FEATURE_API_PATH L"/php-panel/public/?page=api-features"
#endif
#ifndef FEATURE_API_KEY
#define FEATURE_API_KEY L"feat_BpfnPJuUG1NxD1opDGY66llauIpNhko0uS2HuvUOoiJwqcYV"
#endif
