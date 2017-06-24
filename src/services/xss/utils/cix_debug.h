/*
    Anti-XSS c-icap service
    cix_debug.h
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

#ifndef CIX_DEBUG_H_
#define CIX_DEBUG_H_

#include <c_icap/debug.h>
#include <sys/types.h>
#include <unistd.h> //for getpid()

#ifndef DEBUG
#define DEBUG 1 /* TODO: 最終的に削除*/
#endif

#define CIX_ERROR_LEVEL 1
#define CIX_WARN_LEVEL 3
#define CIX_MESSAGE_LEVEL 5
#define CIX_INFO_LEVEL 7
#define CIX_DEBUG_LEVEL 9

/*
 * ci_debug_printf関数に "(プロセスID):関数名:行番号: " を付与します。
 */

#ifdef DEBUG
#define cix_debug_printf(lev,msg, ...)  \
        ci_debug_printf(1, "(%d):%s():L%04d: "msg"\n", getpid(), __func__, __LINE__, ## __VA_ARGS__)
#endif
// レベル1 = 絶対ログ表示

#ifndef DEBUG
#define cix_debug_printf(lev,msg, ...)  \
        ci_debug_printf(lev, "%s():L%04d: "msg"\n", __func__, __LINE__, ## __VA_ARGS__)
#endif
//レベル > levなら表示

#endif /* CIX_DEBUG_H_ */
