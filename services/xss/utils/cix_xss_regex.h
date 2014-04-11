/*
    Anti-XSS c-icap service
    cix_xss_regex.h
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

#ifndef CIX_XSS_REGEX_H_
#define CIX_XSS_REGEX_H_

#include <re2/re2.h>

static const RE2 ms1("(?:jscript|onsubmit|copyparentfolder|javascript|meta|onmove|onkeydown|onchange|onkeyup|activexobject|expression|onmouseup|ecmascript|onmouseover|vbscript:|(?:%3[Cc])!\\[cdata\\[|http:|settimeout|onabort|shell:|\\.innerhtml|onmousedown|onkeypress|asfunction:|onclick|\\.fromcharcode|background-image:|\\.cookie|ondragdrop|onblur|x-javascript|mocha:|onfocus|javascript:|getparentfolder|lowsrc|onresize|@import|alert|onselect|script|onmouseout|onmousemove|background|application|\\.execscript|livescript:|getspecialfolder|vbscript|iframe|\\.addimport|onunload|createtextrange|onload|(?:%3[Cc])input)");
static const RE2 ms2("(?:\\b(?:(?:type\\b\\W*?\\b(?:text\\b\\W*?\\b(?:j(?:ava)?|ecma|vb)|application\\b\\W*?\\bx-(?:java|vb))script|c(?:opyparentfolder|reatetextrange)|get(?:special|parent)folder|iframe\\b.{0,100}?\\bsrc)\\b|on(?:e(?:rror(?:update)?|nd)|c(?:o(?:nt(?:extmenu|rolselect)|py)|ut|lick|(?:ellc)?hange)|m(?:o(?:ve(?:end|start)?|use(?:o(?:ut|ver)|up|(?:mo|lea)ve|down|wheel|enter))|essage)|lo(?:ad|secapture)|d(?:r(?:ag(?:en(?:d|ter)|drop|over|leave|start)?|op)|ata(?:setc(?:hanged|omplete)|available)|blclick|eactivate)|s(?:t(?:op|art)|elect(?:start)?|croll|ubmit)|b(?:e(?:for(?:e(?:c(?:ut|opy)|p(?:aste|rint)|u(?:pdate|nload)|activate|editfocus)|deactivate)|gin)|lur|ounce)|p(?:ast|ropertychang)e|key(?:up|down|press)|f(?:o(?:cus(?:in|out)?|rm(?:input|change))|i(?:nish|lterchange))|in(?:put|valid)|a(?:fter(?:print|update)|bort|ctivate)|r(?:e(?:s(?:et|ize)|peat|adystatechange)|ow(?:e(?:xit|nter)|s(?:delete|inserted)))|zoom|help|unload)\\b\\W*?=\\b)|(?:l(?:owsrc\\b\\W*?\\b(?:(?:java|vb)script|shell|http)|ivescript)|(?:href|url)\\b\\W*?\\b(?:(?:java|vb)script|shell)|background-image|mocha):|s(?:(?:tyle\\b\\W*=.*\\bexpression\\b\\W*|ettimeout\\b\\W*?)(\\\\|rc\\b\\W*?\\b(?:(?:java|vb)script|shell|http):)|a(?:ctivexobject\\b|lert\\b\\W*?\\(|sfunction:))|(?:%3[Cc])(?:(?:body\\b.*?\\b(?:backgroun|onloa)d|input\\b.*?\\btype\\b\\W*?\\bima?ge?)\\b| ?(?:(?:script|meta)\\b|iframe)|!\\[cdata\\[)|(?:\\.(?:(?:execscrip|addimpor)t|(?:fromcharcod|cooki)e|innerhtml)|\\@import)\\b)");

#endif /* CIX_XSS_REGEX_H_ */
