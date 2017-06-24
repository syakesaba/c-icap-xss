/*
 Anti-XSS c-icap service
 Url.h
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

#ifndef URL_H_
#define URL_H_

#include "uriparser/Uri.h"
#include <string>
#include <vector>
#include <map>

namespace http {

class Url
{
private:
    //一つもpublic変数無いので，アンダースコアを末尾に入れない．
    UriParserStateA state;//毎回生成する方が良い
    UriUriA uri;//毎回生成する方が良い
    //getが呼ばれたらその時にアロケートする。
    //アロケートしたオブジェクトはデストラクタでfreeする。
    char * scheme;
    char * userInfo;
    char * hostText;
    char * hostData;
    char * portText;
    std::vector<char *> * path;
    std::map<char * ,char *> * query;
    char * fragment;
    void initializer();
    inline char * dupUriTextRangeA(const UriTextRangeA range) const;
    bool parsed;
public:
    Url(const std::string _uri);
    Url(const char * _uri);
    Url(const char * _uriStringStart,const char * _uriStringEnd);
    ~Url();
    const bool couldParsed() const;
    const char * getScheme() const;
    const char * getUserInfo() const;
    const char * getHostText() const;
    const char * getHostData() const;
    const char * getPortText() const;
    const std::vector<char *> * getPath() const;
    const std::map<char *,char *> * getQuery() const;
    const char * getFragment() const;
    const bool isAbsolutePath() const;
    const bool isOwner() const;
};

} /* namespace http */
#endif /* URL_H_ */
