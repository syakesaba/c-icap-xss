/*
    Anti-XSS c-icap service
    end_of_data_handler.h
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

#ifndef END_OF_DATA_HANDLER_H_
#define END_OF_DATA_HANDLER_H_

#include <c_icap/request.h>

int cix_end_of_data_handler(ci_request_t * req);

#endif /* END_OF_DATA_HANDLER_H_ */
