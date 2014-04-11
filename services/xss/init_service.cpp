/*
    Anti-XSS c-icap service
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


#include <c_icap/service.h>
#include <c_icap/request.h>

#include "utils/cix_debug.h"


/*
 * ================================================================
 * Next is -> post_init_service.c
 * ================================================================
 */

/*
 * ICAPが起動した直後一度だけ動作する関数
 * ここではスクリプトが示したsrv_xdataに関係する情報をSquidに送りたい。
 * return CI_OK on success, CI_ERROR on any error
 */
int cix_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf) {
    cix_debug_printf(CIX_INFO_LEVEL,"starts");
    ci_service_set_istag(srv_xdata, "CIX-v20131004");// ISTAG_SIZE

    //TODO: 全部送っちゃったら多少データ量が多くなる。必要に応じてadd_xoptsを追加する。
    //色々な識別子
    ci_service_set_xopts(srv_xdata,
            CI_XCLIENTIP | CI_XSERVERIP | CI_XSUBSCRIBERID|
            CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS);

    //TODO: 全部（略
    //ICAPに送ってきてもいいけど、previewするわ、っていう拡張子
    ci_service_set_transfer_preview(srv_xdata, "*");
    //ci_service_set_transfer_preview(srv_xdata,"html,js,php,cgi,");

    //TODO: 全部（略
    //ICAPに送ってこないで　っていう拡張子
    ci_service_set_transfer_ignore(srv_xdata,"");
    //ci_service_set_transfer_ignore(srv_xdata,"zip, tar");

    //TODO: 全（略
    //previewせず、全部もらう拡張子
    ci_service_set_transfer_complete(srv_xdata,"");

    //TODO: スクリプトの平均実行時間によってTTLを設定し、タイムアウトを実装する
    ci_service_set_options_ttl(srv_xdata, 3600);

    //TODO: スクリプトからとってくる
    //自分のXINCLUDEを追加できる！イイネ！！
    ci_service_add_xincludes(srv_xdata, NULL);

    /* previwサイズ。そのまんま。*/
    /* 1024という数字は、どうなのだろう */
    ci_service_set_preview(srv_xdata, 1024);

    /*Tell to the icap clients that we support 204 responses*/
    /* そのまんま */
    ci_service_enable_204(srv_xdata);

    /*Tell to the icap clients that we support 204 responses*/
    /* そのまんま */
    ci_service_enable_206(srv_xdata);

    return CI_OK;
}
