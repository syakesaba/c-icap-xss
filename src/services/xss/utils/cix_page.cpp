/*
    Anti-XSS c-icap service
    cix_generrorpage.cpp
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

#include "cix_page.h"
#include <c_icap/request.h>
#include <c_icap/simple_api.h>
/*
 * srv_url_checkからいんよう
 */
void rewriteResponse403(ci_request_t * req) {
    ci_http_response_create(req,1,1);
    ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden"); /*Send an 403 Forbidden http responce to web client */
    ci_http_response_add_header(req, "Server: c-icap-xss");
    ci_http_response_add_header(req, "Content-Type: text/html");
    ci_http_response_add_header(req, "Connection: close");
    ci_http_response_add_header(req, "Content-Language: en");
}
