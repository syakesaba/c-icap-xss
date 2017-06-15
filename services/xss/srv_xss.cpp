/*
    Anti-XSS c-icap service
    srv_xss.cpp
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

#include <c_icap/c-icap.h>
#include <c_icap/service.h>

#include "init_service.h"
#include "post_init_service.h"
#include "close_service.h"
#include "init_request_data.h"
#include "check_preview_handler.h"
#include "service_io.h"
#include "end_of_data_handler.h"
#include "release_request_data.h"

CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "xss",                       /* mod_name, The module name */
     "Anti-XSS service",          /* mod_short_descr,  Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,  /* mod_type, The service type is responce or request modification */
     cix_init_service,            /* mod_init_service. Service initialization */
     cix_post_init_service,       /* post_init_service. Service initialization after c-icap configured. */
     cix_close_service,           /* mod_close_service. Called when service shutdowns. */
     cix_init_request_data,       /* mod_init_request_data */
     cix_release_request_data,    /* mod_release_request_data */
     cix_check_preview_handler,   /* mod_check_preview_handler */
     cix_end_of_data_handler,     /* mod_end_of_data_handler */
     cix_service_io,              /* mod_service_io */
     NULL,                          /* mod_conf_table, c-icap.conf - c-icap.confファイルから値を持ってこれる。 */
     NULL                          /* mod_data, NULL. */
};
