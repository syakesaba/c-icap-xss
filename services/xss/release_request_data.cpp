/*
    Anti-XSS c-icap service
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

#include "utils/cix_debug.h"
#include "body/MemBuf.h"

void cix_release_request_data(void *data) {
    cix_debug_printf(CIX_INFO_LEVEL,"starts");
    body::MemBuf * instance = (body::MemBuf *)data;
    delete instance;
}
