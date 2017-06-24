/*
    Anti-XSS c-icap service
    cix_http.cpp
    Copyright (C) 2013  SYA-KE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "cix_http.h"
#include <string.h>

#include <c_icap/simple_api.h>
#include <c_icap/util.h>

#include "cix_debug.h"

namespace http {

#define MAX_URL_SIZE 4096    //4096はCookieの値の最大値と一致する。

/*
 * return : "METHOD" or NULL. Don't free it.
 */
const char * get_method(ci_request_t * req) {
#define NUM_OF_HTTP_METHODS 8
    static const char * HTTP_METHODS[] = {"GET", "POST", "CONNECT", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"};
    //全8メソッド。HTTP1.1でhttpdに標準搭載が推奨されているもの
    //多分、この順番に到着メソッドが多い。
    //SquidにSSL-Bumpを導入しているため、CONNECTメソッドに関しても考慮。
    //GET,POSTは普通のHTTP利用。CONNECTはSSLに。HEADはURI validationとか。PUT,DELETEはREST APIに使われるくらい。

    //本研究ではプロキシを介すため、absoluteURI形式のみが受け渡される。
    // ref => http://www.studyinghttp.net/cgi-bin/rfc.cgi?2616#Sec5
    //(GET / HTTP/1.0みたいなリクエストは飛んでこない。飛んできてもsquidがはじく。)
    const char * request_ptr = ci_http_request(req);//<Method> <URL> <HTTP/1.x>
    for (int i = 0; i < NUM_OF_HTTP_METHODS; ++i) {
        if (strstr(request_ptr, HTTP_METHODS[i]) != NULL) {
            //ci_strnstrを使わない理由はc-icapがソースコードで長さチェックを行っている為。
            return HTTP_METHODS[i];
            //start_pos += strlen(HTTP_METHODS[i]) + 1;//+1 of " "
        }
    }
    return NULL;//UNKNOWN!
}

/*
 * method: a "GET","POST",.....
 * buf: a pointer of char *. this will be start_pos of URL.
 * return: a length of URL.0 for error.
 * この関数はURL始点とそのURLの幅を計算します。
 * printf(buf)とかしないでね。HTTP1.xもひっつくから。
 */
const int get_url(ci_request_t * req, const char * method,const char ** buf) {
    const char * start_pos = ci_http_request(req);//<Method> <URL> <HTTP/1.x>
    if (method) {
        start_pos += strlen(method) + 1;//+1 of " "
        const char * end_pos;
        if(start_pos) {
            //start_pos = "<METHOD> <URL> <HTTP/1.x>" の<URL>の直前のポインタ。
            end_pos = strstr(start_pos," HTTP/1.");
            if (end_pos) {
                //end_pos = "<URL> <HTTP/1.x>" の<URL>の直後のポインタ。
                *buf = start_pos;
                return end_pos - start_pos;
            }
        }
    }
    return 0;
}

/*
 * http://www.google.co.jp/ -> www.google.co.jp
 * char buf[4096];
 * hostlen = get_host(req, _&buf);
 */
const int get_host(ci_request_t * req, const char ** buf) {
    const char * start_pos = ci_http_request(req);//<Method> <URL> <HTTP/1.x>
    const char * method = get_method(req);
    if (method) {
        start_pos += strlen(method) + 1;//+1 of " "
        //start_posはURLの先頭
        const char * protocol_pos = strstr(start_pos,"://");
        if(protocol_pos) {
            protocol_pos += 3;
            const char * end_pos = strstr(protocol_pos, "/");
            if (end_pos) {
                //end_pos = "<URL> <HTTP/1.x>" の<URL>の直後のポインタ。
                *buf = protocol_pos;
                return end_pos - protocol_pos;
            }
        }
    }
    return 0;
}

//==========================canaria_cookie

#define CANARIA_COOKIE_NAME "piyopiyopiyo"
#define MAX_COOKIE_SIZE MAX_URL_SIZE
#define MAX_CANARIA_HEADER_SIZE 12+13+hostlen+38+1
#define CANARIA_HEADER "Set-Cookie: "CANARIA_COOKIE_NAME"=%s; expires=Mon, 25-Nov-2071 23:59:59 GMT;"

//only work in REQMOD = HTTP GET,POST
const char * has_canaria_cookie(ci_request_t * req) {
    const char * cookie_header = ci_http_request_get_header(req, "Cookie");
    if (cookie_header) {
        return strstr(cookie_header, CANARIA_COOKIE_NAME"=");// piyopiyopiyo=
    }
    return NULL;
}

//only work in REQMOD = HTTP GET,POST
const char * is_valid_canaria_cookie(ci_request_t * req) {
    const char * canaria_cookie = has_canaria_cookie(req);
    if (canaria_cookie) {
        const char * buf;
        const int buflen = get_host(req, &buf);
        if (buflen) {
            canaria_cookie = ci_strnstr(canaria_cookie, "=", MAX_COOKIE_SIZE);
            if (canaria_cookie) {
                return ci_strnstr(canaria_cookie + 1, buf, buflen);
            }
        }
    }
    return NULL;
}

void add_canaria_cookie(ci_request_t * req) {
    //Set-Cookie: NAME=VALUE; expires=DATE; path=PATH; domain=DOMAIN_NAME; secure
    //"Set-Cookie: " = 12,"piyopiyopiyo=" = 13, "<host>; " = hostlen, "expires=Mon, 25-Nov-2071 23:59:59 GMT;" = 38,""=1
    const char * host;
    const int hostlen = get_host(req, &host);
    char real_host[hostlen +1];
    strncpy(real_host, host, hostlen);
    real_host[hostlen] = '\0';
    char canaria_header[MAX_CANARIA_HEADER_SIZE];
    snprintf(canaria_header, MAX_CANARIA_HEADER_SIZE, CANARIA_HEADER, real_host);
    ci_http_response_add_header(req, canaria_header);//カナリアCookieのセット。
}

/*
 * req: request.
 * buf: this function will set a pointer at cookie value to this buffer
 */
const int get_canaria_cookie(ci_request_t * req, const char * buf[]) {
    const char * canaria_cookie = has_canaria_cookie(req);
    if (canaria_cookie) {
        canaria_cookie += 13;//strlen("piyopiyopiyo=")
        int end_pos = 0;
        while (end_pos < MAX_URL_SIZE) {
            char c = canaria_cookie[end_pos];
            if (c == ' ' || c == ';' || (c == '\r' && canaria_cookie[end_pos+1] == '\n')) {
                break;
            }
            ++end_pos;
        }
        *buf = canaria_cookie;
        return end_pos;
        /*
        const char * end_pos = ci_strnstr(canaria_cookie, ";", MAX_COOKIE_SIZE);
        if (end_pos) {
            *buf = canaria_cookie;
            return end_pos - canaria_cookie;
        } else {
            end_pos = ci_strnstr(canaria_cookie, "\r\n", MAX_COOKIE_SIZE);
            if (end_pos) {
                *buf = canaria_cookie;
                return end_pos - canaria_cookie;
            } else {
                end_pos = ci_strnstr(canaria_cookie, " ", MAX_COOKIE_SIZE);
                if (end_pos) {
                    *buf = canaria_cookie;
                    return end_pos - canaria_cookie;
                }
            }
        }
        */
    }
    return 0;
}
/*
const int is_valid_canaria_cookie(ci_request_t * req) {
    const char * canary;
    const int canarylen = get_canaria_cookie(req, &canary);
    if (canarylen > 0) {
        const char * host;
        const int hostlen = get_host(req, &host);
        if (hostlen > 0) {
            if(ci_strnstr(host, canary, canarylen)) {
                return canarylen;
            }
        }
        return -1;
    }
    return 0;
}*/

} /* namespace http */
