/*
 Anti-XSS c-icap service
 MemBuf.cpp
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

#include <string.h>

#include "MemBuf.h"
#include <c_icap/body.h>
#include <c_icap/filetype.h>

namespace body {
/*
static const int GROUP_GRAPHICS = ci_magic_group_id("GRAPHICS");
static const int GROUP_STREAM = ci_magic_group_id("STREAM");
static const int GROUP_TEXT = ci_magic_group_id("TEXT");
static const int GROUP_DATA = ci_magic_group_id("DATA");
static const int GROUP_EXECUTABLE = ci_magic_group_id("EXECUTABLE");
static const int GROUP_ARCHIVE = ci_magic_group_id("ARCHIVE");
static const int GROUP_DOCUMENT = ci_magic_group_id("DOCUMENT");
*/
//エラー処理無視や！
MemBuf::MemBuf() {
	method = NULL;
	url = NULL;
    buffer = ci_membuf_new();
}

MemBuf::MemBuf(int size) {
	method = NULL;
	url = NULL;
    buffer = ci_membuf_new_sized(size);
}

MemBuf::~MemBuf() {
	method = NULL;
	url = NULL;
    ci_membuf_free(buffer);
}

int MemBuf::read(char * buf, int len) {
    return ci_membuf_read(buffer, buf, len);
}

int MemBuf::write(const char * buf, int len, int iseof) {
    return ci_membuf_write(buffer, buf, len, iseof);
}
/*
 * Don't free it.
 */
const char * MemBuf::getBuffer() {
    return buffer->buf;
}
/*
 * Don't free it.
 */
const int MemBuf::getBufferLen() {
    return buffer->len;
}

void MemBuf::setBuffer(const char * buf) {
    ci_membuf_free(buffer);
    int bufsize = strlen(buf);//NULLあったら終わるなあ。バイナリ無理だなあ。Byteref？
    buffer = ci_membuf_new_sized(bufsize);
    write(buf, bufsize, 1);
}

void MemBuf::setBuffer(const char * buf, int bufsize) {
    ci_membuf_free(buffer);
    buffer = ci_membuf_new_sized(bufsize);
    write(buf, bufsize, 1);
}

} /* namespace body */
