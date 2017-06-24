/*
    Anti-XSS c-icap service
    check_preview_handler.h
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

#ifndef CHECK_PREVIEW_HANDLER_H_
#define CHECK_PREVIEW_HANDLER_H_

#include <c_icap/request.h>

int cix_check_preview_handler(char *preview_data, int preview_data_len,
        ci_request_t *);

#endif /* CHECK_PREVIEW_HANDLER_H_ */
