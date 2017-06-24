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

/*
 * ================================================================
 * Prev is <- init_service.c
 * Next is -> (run!) => ICAP request coming] => init_request_data
 * ================================================================
 */

#include <c_icap/service.h> //cfg_param.h
#include <c_icap/request.h> //CI_OK

#include "utils/cix_debug.h"

/**
   \brief Pointer to the function which called after the c-icap initialized, but before
 * the c-icap start serves requests.
 *
 * This function can be used to initialize the service. Unlike to the
 * ci_service_module::mod_init_service when this function called the c-icap has initialized
 * and it is known other system parameters like the services and modules which are loaded,
 * network ports and addresses c-icap is listening etc.
 \param srv_xdata Pointer to the ci_service_xadata_t object of this service
 \param server_conf Pointer to the struct holds the main c-icap server configuration
 \return CI_OK on success, CI_ERROR on errors.
 ここの*xdataはstatic変数にストアすることでグローバルに使用できる。
 OPTIONSレスポンスを編集したい場合はxdataにlockをかけるらしいが、まだAPIが正式なもの
 になっていないらしい 201301101

 */
int cix_post_init_service(ci_service_xdata_t *srv_xdata,struct ci_server_conf *server_conf) {
    cix_debug_printf(CIX_INFO_LEVEL,"starts");
    return CI_OK;
}
