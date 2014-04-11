/*
 Anti-XSS c-icap service
 MemBuf.h
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

#ifndef MEMBUF_H_
#define MEMBUF_H_

#include <c_icap/body.h>
#include <c_icap/filetype.h>

#include "utils/Url.h"

namespace body {

class MemBuf {
    ci_membuf_t * buffer;
public:
    MemBuf();
    MemBuf(int size);
    ~MemBuf();
    int write(const char * buf,int len, int iseof);
    int read(char * buf, int len);
    const char * getBuffer();
    void setBuffer(const char * buf);
    void setBuffer(const char * buf, int bufsize);
    const int getBufferLen();
	const char * method;
    const http::Url * url;
    /*
    const int isGraphic();
    const int isStream();
    const int isText();
    const int isData();
    const int isExecutable();
    const int isArchive();
    const int isDocument();
    */
    //z_stream z;
    //コンストラクタでzをinit
    //デコンストラクタでzをclose
};

} /* namespace body */
#endif /* MEMBUF_H_ */
