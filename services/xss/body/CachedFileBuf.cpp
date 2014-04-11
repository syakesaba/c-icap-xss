/*
 Anti-XSS c-icap service
 CachedFileBuf.cpp
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
#include "CachedFileBuf.h"
#include <c_icap/body.h>

namespace body {

CachedFileBuf::CachedFileBuf(int size, bool willDeleteFile) {
    buffer = ci_cached_file_new(size);
    willDelete = willDeleteFile;
}

CachedFileBuf::~CachedFileBuf() {
    if(willDelete) {
        destroy();
    } else {
        release();
    }
}

int CachedFileBuf::write(const char * buf, int len, int iseof) {
    return ci_cached_file_write(buffer, buf, len, iseof);
}

int CachedFileBuf::read(char * buf, int len) {
    return ci_cached_file_read(buffer, buf, len);
}

void CachedFileBuf::reset(int size) {
    ci_cached_file_reset(buffer, size);
}

void CachedFileBuf::release() {
    ci_cached_file_release(buffer);
}

void CachedFileBuf::destroy() {
    ci_cached_file_destroy(buffer);
}

} /* namespace body */
