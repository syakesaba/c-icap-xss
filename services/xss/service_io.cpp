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

#include <c_icap/request.h>

#include "string.h"
#include "malloc.h"

#include "utils/cix_debug.h"
#include "body/MemBuf.h"


//rlen,wlenもポインタになっていることに注意！
int cix_service_io(char * wbuf, int * wlen, char * rbuf, int * rlen, int iseof, ci_request_t * req) {
    cix_debug_printf(CIX_INFO_LEVEL,"starts iseof=%5s", (iseof)?"True":"False");

    body::MemBuf * instance = (body::MemBuf *)ci_service_data(req);

    int ret = CI_OK;

    if (rlen && rbuf) { // io = IN MODE
        cix_debug_printf(CIX_INFO_LEVEL,"io = READ MODE! rlen=%d", *rlen);
        if (*rlen < 0) {
            cix_debug_printf(CIX_ERROR_LEVEL, "FAIL at (*rlen < 0) : rlen = %d", *rlen);
            ret = CI_ERROR;
        } else {
            instance->write(rbuf, *rlen, iseof);
        }
    }
    /*read some data from the echo_data->body and put them to the write buffer to be send
     to the ICAP client*/

    if (wlen && wbuf) { // io = OUT MODE
        cix_debug_printf(CIX_INFO_LEVEL,"io = WRITE MODE! wlen=%d", *wlen);
        char * data = (char *)malloc(sizeof(char) * *wlen);
        int datalen = 0;

        datalen = instance->read(data, *wlen);  // datelenは、-2=CI_EOFが入ることがある。

        if (datalen > *wlen) {
            ret = CI_ERROR;
            cix_debug_printf(CIX_ERROR_LEVEL, "Error: write_data() returned more than requested: %d for %d", datalen, *wlen);
            return CI_ERROR;
        }
        if (datalen > 0) {
            memcpy(wbuf, data, datalen);
            cix_debug_printf(CIX_INFO_LEVEL, "WRITE/WROTE = %d/%d", datalen, *wlen)
        }//else, datalen == CI_EOF
        free(data);
        *wlen = datalen;
    }

    return ret;
}
