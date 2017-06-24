/*
    Anti-XSS c-icap service
    cix_http.h
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

#ifndef CIX_HTTP_H_
#define CIX_HTTP_H_

#include <c_icap/request.h>

#define MAX_URL_SIZE 4096

namespace http {

const char * get_method(ci_request_t * req);
const int get_url(ci_request_t * req, const char * method, const char ** buf);
const char * has_canaria_cookie(ci_request_t * req);
void add_canaria_cookie(ci_request_t * req);
const int get_canaria_cookie(ci_request_t * req, const char ** buf);
const int get_host(ci_request_t * req, const char ** buf);
const char * is_valid_canaria_cookie(ci_request_t * req);

}
#endif /* CIX_HTTP_H_ */
