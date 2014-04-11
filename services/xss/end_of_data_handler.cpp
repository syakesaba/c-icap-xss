/*
    Anti-XSS c-icap service
    end_of_data_handler.cpp
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

#include <c_icap/service.h>
#include <c_icap/request.h>
#include <c_icap/simple_api.h>

#include "utils/cix_debug.h"
#include "utils/cix_xss_regex.h"
#include "utils/cix_page.h"
#include "utils/cix_http.h"
#include "body/MemBuf.h"

#include <re2/re2.h>
#include <string>


#define MAX_URL_SIZE 4096
/*
 * この関数に届くreqは
 * check_preview_handlerでAllow204されなかったものです。
 */
int cix_end_of_data_handler(ci_request_t *req) {
    cix_debug_printf(CIX_INFO_LEVEL, "starts");
    body::MemBuf * instance = (body::MemBuf *)ci_service_data(req);
    bool already_denied =  false;
    if (ci_req_type(req) == ICAP_REQMOD && req->data_locked) {
          if (ci_req_hasbody(req)) {
            const char * body = instance->getBuffer();
            //bodyには全てのPOSTデータが入っている

            //XSSがPOSTデータに入っているか調査
            if(RE2::PartialMatch(body, ms1) ) {
                cix_debug_printf(CIX_INFO_LEVEL, "MS1 MATCHED!");
                if (RE2::PartialMatch(body, ms2)) {
                    cix_debug_printf(CIX_INFO_LEVEL, "MS2 MATCHED!!");
                    rewriteResponse403(req);
                    instance->setBuffer("<body>DENIED! XSS in POST!</body>");
                    cix_debug_printf(CIX_MESSAGE_LEVEL,"XSS found in POST!");
                    already_denied = true;
                }
            }

            //カナリアCookieがPOSTデータに入っているか調査
            if (!already_denied) {
                if (strstr(body, "piyopiyopiyo%3D") ) {
                    rewriteResponse403(req);
                    instance->setBuffer("<body>canaria in POST!</body>");
                    cix_debug_printf(CIX_MESSAGE_LEVEL, "CANARIA found in POST!");
                }
            }
        }
    }/*
    cix_debug_printf(CIX_INFO_LEVEL, "-------------------------query!!");
    const http::Url * u = (instance->url);
    u->getQuery();
    const std::map<char *,char *> * q = (instance->url)->getQuery();
    std::map<char *,char *>::const_iterator it = q->begin();
    while( it != q->end() ) {
        cix_debug_printf(CIX_INFO_LEVEL, "%s=%s", (*it).first, (*it).second);
	    it++;
    }*/
    return CI_MOD_DONE;
}
