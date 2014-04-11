/*
 Anti-XSS c-icap service
 Url.cpp
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
#include "Url.h"

#include <uriparser/Uri.h>
#include <string>
#include <vector>
#include <map>

namespace http {

Url::Url(const std::string _uri) {
    state.uri = &uri;
    parsed = true;
    if(uriParseUriA(&state, _uri.c_str()) != URI_SUCCESS) {
        parsed = false;
    }
    initializer();
}

Url::Url(const char * _uri) {
    state.uri = &uri;
    parsed = true;
    if(uriParseUriA(&state, _uri) != URI_SUCCESS) {
        parsed = false;
    }
    initializer();
}

Url::Url(const char * _uriStringStart,const char * _uriStringEnd) {
    state.uri = &uri;
    parsed = true;
    if(uriParseUriExA(&state, _uriStringStart, _uriStringEnd) != URI_SUCCESS) {
    	parsed = false;
    }
    initializer();
}

/*
 * All the resource should be free'ed in this destructor.
 */
Url::~Url() {
    //delete state;
    uriFreeUriMembersA(&uri);
    //free(char *)はNULLでも問題ない。
    free(scheme);
    free(userInfo);
    free(hostText);
    free(hostData);
    free(portText);
    //TODO:path free each char*
	if (path != NULL) {
		std::vector<char*>::const_iterator it = path->begin();
		while( it != path->end() ) {
			free(*it);
			++it;
		}
		delete path;
	}
    if (query != NULL) {
        std::map<char *,char *>::const_iterator it = query->begin();
        while( it != query->end() ) {
        	free((*it).first);
        	free((*it).second);//freeはNULLでもOK
            ++it;
        }
        delete query;
    }
    free(fragment);
}

void Url::initializer() {
    scheme = dupUriTextRangeA(uri.scheme);
    userInfo = dupUriTextRangeA(uri.userInfo);
    hostText = dupUriTextRangeA(uri.hostText);
    hostData = NULL;//TODO:
    portText = dupUriTextRangeA(uri.portText);
    path = new std::vector<char *>;
    UriPathSegmentA * node = (UriPathSegmentA *)uri.pathHead;
	while (node != NULL) {
		path->push_back(dupUriTextRangeA(node->text));
		node = (UriPathSegmentA *)node->next;
	}
    query = new std::map<char *,char *>;
	UriQueryListA * queryList = NULL;
	int itemCount;
	if (uriDissectQueryMallocA(&queryList, &itemCount, uri.query.first,
					uri.query.afterLast) != URI_SUCCESS) {
		//TODO:
	}
	while (queryList != NULL) {
		if (queryList->key != NULL && queryList->value != NULL)
			query->insert( std::map<char *,char *>::value_type( strdup(queryList->key), strdup(queryList->value) ) );
		else if (queryList->key != NULL)
			query->insert( std::map<char *,char *>::value_type( strdup(queryList->key), NULL) );
		queryList = queryList->next;
	}
	uriFreeQueryListA(queryList);
    fragment = dupUriTextRangeA(uri.fragment);
}

const bool Url::couldParsed() const {
	return parsed;
}


/*
 *  http://www.google.com/search/text?q=word;data#framgment
 *  -> http
 */
const char * Url::getScheme() const {
	return scheme;
}

/*
 *  ftp://anon@anon:ftp.jaist.ac.jp/public/squeeze/package.deb
 *  -> anon
 */
const char * Url::getUserInfo() const {
	return userInfo;
}
/*
 *  http://www.google.com/search/text?q=word;data#framgment
 *  -> www.google.com
 */
const char * Url::getHostText() const {
	return hostText;
}

/*
 * IPアドレス情報・・・DNSラウンドロビンもあるし、使わない方が吉カモ。
 */
const char * Url::getHostData() const{
	//TODO:
	if (hostData==NULL) {
		return NULL;
	}
	return NULL;
}
/*
 *  http://www.google.com:8080/search/text?q=word;data#framgment
 *  -> 8080
 */
const char * Url::getPortText() const {
	return portText;
}

/*
 *  const std::vector<char *> * path = url->getPath();
 *  if (path != NULL && !path->empty()) {
 *      std::vector<char *>::const_iterator it = path->begin();
 *      while( it != path->end() ) {
 *          puts(*it);
 *          ++it;
 *      }
 *  }
 *
 */
const std::vector<char *> * Url::getPath() const{
	return path;
}

/*
 *   const std::map<char *,char *> * m = unko.getQuery();
 *   if (m != NULL) {
 *       std::map<char *,char *>::const_iterator it = m->begin();
 *       while( it != m->end() ) {
 *           std::cout << (*it).first << ":" << (*it).second << std::endl;
 *           ++it;
 *       }
 *	}
 *
 *  returns: pointer to map. DO NOT free or delete it!
 */
const std::map<char *,char *> * Url::getQuery() const{
	return query;
}

/*
 *  http://www.google.com:8080/search/text?q=word&a=b#framgment
 *  -> fragment
 */
const char * Url::getFragment() const{
	return fragment;
}
/*
 * GET / HTTP/1.0 -> True
 * GET http://www.google.co.jp HTTP/1.0 -> False
 */
const bool Url::isAbsolutePath() const {
	return (uri.absolutePath)?true:false;
}

/*
 * ??
 */
const bool Url::isOwner() const {
	return (uri.owner)?true:false;
}

/*	0x00000000 <- "0123456789"
 *
 *  dupUriTextRangeA(0x00000003,0x0000005)
 *  -> allocated "345"
 */
inline char * Url::dupUriTextRangeA(const UriTextRangeA range) const {
	if (range.first) {
		return strndup(range.first, range.afterLast - range.first);
	}
	return NULL;
}

} /* namespace http */
