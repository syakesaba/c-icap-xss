/*
    Anti-XSS c-icap service
    cix_magic.h
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

#ifndef CIX_MAGIC_H_
#define CIX_MAGIC_H_

//CURRENT GROUPS: TEXT DATA EXECUTABLE ARCHIVE GRAPHICS STREAM DOCUMENT
//マクロでやりたかったなあ。

inline const int isGraphic(int data_type) {
    static const int GROUP_GRAPHICS = ci_magic_group_id("GRAPHICS");
    return ci_magic_group_check(data_type, GROUP_GRAPHICS);
}

inline const int isStream(int data_type) {
    static const int GROUP_STREAM = ci_magic_group_id("STREAM");
    return ci_magic_group_check(data_type, GROUP_STREAM);
}

inline const int isText(int data_type) {
    static const int GROUP_TEXT = ci_magic_group_id("TEXT");
    return ci_magic_group_check(data_type, GROUP_TEXT);
}

inline const int isData(int data_type) {
    static const int GROUP_DATA = ci_magic_group_id("DATA");
    return ci_magic_group_check(data_type, GROUP_DATA);
}

inline const int isExecutable(int data_type) {
    static const int GROUP_EXECUTABLE = ci_magic_group_id("EXECUTABLE");
    return ci_magic_group_check(data_type, GROUP_EXECUTABLE);
}

inline const int isArchive(int data_type) {
    static const int GROUP_ARCHIVE = ci_magic_group_id("ARCHIVE");
    return ci_magic_group_check(data_type, GROUP_ARCHIVE);
}

inline const int isDocument(int data_type) {
    static const int GROUP_DOCUMENT = ci_magic_group_id("DOCUMENT");
    return ci_magic_group_check(data_type, GROUP_DOCUMENT);
}


#endif /* CIX_MAGIC_H_ */
