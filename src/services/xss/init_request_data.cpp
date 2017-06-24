/*
    Anti-XSS c-icap service
    init_request_data.h

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

#include "c_icap/c-icap.h"
#include <c_icap/request.h>
#include <c_icap/simple_api.h>

#include "re2/re2.h"

#include <string>

#include "utils/cix_debug.h"
#include "utils/cix_http.h"
#include "body/MemBuf.h"
#include "body/utils/Url.h"

/*
 * ICAPリクエストが到着する度に呼び出される。
 * 一つのICAPトランザクションで共有するインスタンスを作成する。
 */
void *cix_init_request_data(ci_request_t *req) {
    cix_debug_printf(CIX_INFO_LEVEL,"starts");
    const int REQ_TYPE = ci_req_type(req);
    const char * METHOD_TYPE = ci_method_string(REQ_TYPE);//Don't free!

    cix_debug_printf(CIX_MESSAGE_LEVEL,"request %s has come", METHOD_TYPE);

    if (REQ_TYPE != ICAP_REQMOD && REQ_TYPE != ICAP_RESPMOD){
        return NULL;//OPTIONSリクエストとかはスルー。
    }

    body::MemBuf * instance = new body::MemBuf();
    const char * method = http::get_method(req);
    if (method) {
        instance->method = method;
        const char * buf = NULL;
        const int urllen = http::get_url(req, method, &buf);
        if (urllen > 0) {
            instance->url = new http::Url(buf, buf + urllen);
        }
        return (void *)instance;
    }
    return NULL;
}
