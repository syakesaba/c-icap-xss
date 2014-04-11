/*
 Anti-XSS c-icap service
 CachedFileBuf.h
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

#ifndef CACHEDFILEBUF_H_
#define CACHEDFILEBUF_H_

#include <c_icap/body.h>

namespace body {

class CachedFileBuf {
    ci_cached_file_t * buffer;
    bool willDelete;
public:
    CachedFileBuf(int size, bool willDeleteFile=true);
    ~CachedFileBuf();
    inline int write(const char *buf,int len, int iseof);
    inline int read(char * buf, int len);
    inline void reset(int size);
    inline void release();
    inline void destroy();
    inline void lock_all();
    inline void unlock(int len);
    inline void unlock_all();
    inline int size();
    inline bool ismem();
    inline int read_pos();
    inline bool haseof();
    inline void setWillDelete(bool willDeleteFile);
};

} /* namespace body */
#endif /* CACHEDFILEBUF_H_ */
