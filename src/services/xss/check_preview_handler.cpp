/*
    Anti-XSS module for C-ICAP server
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

#include <string>
#include <malloc.h>
#include <c_icap/request.h>
#include <c_icap/simple_api.h>
#include <c_icap/filetype.h>
#include <c_icap/util.h>

#include "utils/cix_debug.h"
#include "utils/cix_page.h"
#include "utils/cix_http.h"
#include "utils/cix_xss_regex.h"
#include "utils/cix_magic.h"
#include "body/MemBuf.h"

/*
 * REQMODでは・・・GETパラメタの調査及びHTTPボディのMagic判定
 * RESPMODでは・・・カナリアCookieのセットのみ
 */
int cix_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *req) {

    cix_debug_printf(CIX_INFO_LEVEL,"starts. len=%d/%d ,hasbody=%5s, hasalldata=%5s ",
                    preview_data_len,
                    ci_req_preview_size(req),
                    (ci_req_hasbody(req))? "True":"False",
                    (ci_req_hasalldata(req))? "True":"False");

    body::MemBuf * instance = (body::MemBuf *)ci_service_data(req);
    //ci_headers_list_t * req_headers = ci_http_request_headers(req);
    //REQMOD ( HTTPリクエスト )
    ci_headers_list_t * resp_headers = ci_http_response_headers(req);
    //REQMOD ( HTTPリクエスト )

    bool denied = false;//このフラグが立ったらAllow204しません。

    //ここからRESPMOD

    const char * method = instance->method;

    if (ci_req_type(req) == ICAP_RESPMOD) {
        const char * http_ok = NULL;
        if (resp_headers && resp_headers->headers[0]) {
            http_ok = ci_strnstr(resp_headers->headers[0], " 200 ", MAX_URL_SIZE);
        }

        //RESPMODの場合、すぐさま応答させるため、REQMODよりも上の方にコードを書く
        if (method && (strcmp(method, "GET") || strcmp(method, "POST"))) {
            if (!http::has_canaria_cookie(req)) {
                if (http_ok) {
                    http::add_canaria_cookie(req);//カナリアのセット
                }
            }
        } else {
            return CI_MOD_ALLOW204;
        }
        ci_req_unlock_data(req);
        //HTTPレスポンス「ボディ」の編集はしないので、後続データを待たずに応答。
        instance->write(preview_data, preview_data_len, ci_req_hasalldata(req));
        //previewの読み込み。previewが全て含んでいるならiseofはtrue。
        cix_debug_printf(CIX_INFO_LEVEL, "RESPMOD! unlocking data!");
        //return CI_MOD_ALLOW204;//ここでAllow204を応答するとHTTTPヘッダの編集が無効になる
        return CI_MOD_CONTINUE;//ボディ入ってないの？でもHTTPヘッダの編集はさせてもらうよ。
    }

    //ここまでRESPMOD

    //ここからはREQMOD

    //URLデータの中にXSSが無いか調査。
    const char * url;
    const int urllen = http::get_url(req, method, &url);
    const char * request_location = NULL;
    if (urllen != 0) {
        request_location = ci_strnstr(url, "://", urllen);
        if (request_location) {//NULLなんてあり得ないが。。
            request_location = request_location + 3;//len("://")
            cix_debug_printf(CIX_INFO_LEVEL, "going to match [%s]", request_location);//HTTP1.xも検査しちゃえ！
            if (RE2::PartialMatch(request_location, ms1)) {
                cix_debug_printf(CIX_INFO_LEVEL, "MS1 MATCHED!");
                if (RE2::PartialMatch(request_location, ms2)) {
                    cix_debug_printf(CIX_INFO_LEVEL, "MS2 MATCHED!");
                    rewriteResponse403(req);
                    instance->setBuffer("<body><h4>DENIED (XSS in URL) </h4></body>");
                    denied = true;
                }
            }
        }
    } else {
        cix_debug_printf(CIX_INFO_LEVEL,"Not a HTTP request.")
    }

    //URLデータ内にカナリアCookieが無いか調査
    if (urllen > 0 && !denied) {
        if (ci_strnstr(url, "piyopiyopiyo%3D", urllen)){
            //カナリアCookieをあらぬ場所に発見した！！
            rewriteResponse403(req);
            instance->setBuffer("<body>canaria in GET!!</body>");
            cix_debug_printf(CIX_MESSAGE_LEVEL,
                    "CANARIA found in GET! %s", request_location);
            denied = true;
        }
    }
    //=============ここまでHTTPヘッダのチェック

    //=============ここからHTTPボディのチェック
    int iscompressed = 0;
    int PREVIEW_DATA_TYPE = -1;//magicデータの関数に必要な準備
    if (resp_headers != NULL) { //HTTPヘッダ、previewデータのmagicからファイルのタイプを決定
        PREVIEW_DATA_TYPE = ci_magic_data_type_ext(resp_headers, preview_data, preview_data_len, &iscompressed);
       } else { //ヘッダが無いのにボディがあるなんて事は無いが一応。magicのみからタイプを決定。
           PREVIEW_DATA_TYPE = ci_magic_data_type(preview_data, preview_data_len);
       }
    cix_debug_printf(CIX_INFO_LEVEL, "MAGIC_TYPE %d = %s(%s)", PREVIEW_DATA_TYPE,
            ci_magic_type_name(PREVIEW_DATA_TYPE), (iscompressed)?"compressed":"raw" );

    if (PREVIEW_DATA_TYPE && !isText(PREVIEW_DATA_TYPE)) {
        //ボディがあるが、テキストデータでなければAllow204
        //ここに来るのはHTTPリクエストでボディがテキスト以外のもの(画像うpとかZIPうpとか)。
        //ボディが「空」の場合はDATAとして扱われ、ここに飛ぶ
        //if (ci_allow204(req)) {
        return CI_MOD_ALLOW204;
        //}
    }

    if(!ci_req_hasbody(req) && !denied) {
        //ボディが無い&怪しい所が見られない
        cix_debug_printf(CIX_INFO_LEVEL, "No body! Allowing 204!");
        ci_req_unlock_data(req);//このデータ、返信待たずにservice_io(wモード)しちゃってOK。
        //return CI_MOD_CONTINUE;//ボディ入ってないの？でもHTTPヘッダの編集はさせてもらうよ！
        return CI_MOD_ALLOW204;//ボディ入ってないの？もういいわお前。RESPMODこい。
        //return CI_MOD_ALLOW206;//SquidちゃんがRFCを無視しているので利用できません。
    }
    if (! denied) {//ヘッダとpreviewだけじゃ判断できませんでした。
        ci_req_lock_data(req);//ボディあるし、テキストデータ！全体調査するロック！
        instance->write(preview_data, preview_data_len, ci_req_hasalldata(req));//previewの読み込み
    } else {//遮断済みなので、もはやボディを受けとる必要もない。
        cix_debug_printf(CIX_MESSAGE_LEVEL,
                "This request has body but already denied!");
        ci_req_unlock_data(req);
    }
        //cix_service_io(NULL, NULL, preview_data, &preview_data_len, ci_req_hasalldata(req),req);//previewの読み込み
    //if (ci_req_hasalldata(req)) {
        // preview(データ先頭10124バイト)で全てのボディを読み込んだ！結構あるケース。
        //return CI_MOD_CONTINUE;
        //RFCには「送信元に残ってるデータ空ならCONTINUE返すな！」って書いてあるけど、c-icapの場合はMOD_CONTINUEでいい。
        //ヘッダの編集だけならいちいちサービスIOしなくてもいいし
        //CI_MOD_DONEをやりたいなあ。RFCではOKなんだけどc-icapでは駄目なんだなあ。
        //最低1回はservice_ioが呼ばれるなあ。速度的にどうなんだろうなあ。
        //Allow206でどうにかなんないかなあ。squidとc-icapのAllow204+Allow206連携はやくー！
    //}

    //(1024 ASCII文字以上あるテキストなPOSTデータって何だ？アヤシすぎる・・・)

    return CI_MOD_CONTINUE;//まだデータのこってんのか次のデータよこせやあ
}
