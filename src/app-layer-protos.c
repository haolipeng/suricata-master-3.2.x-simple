/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "app-layer-protos.h"

#define CASE_CODE(E)  case E: return #E

const char *AppProtoToString(AppProto alproto)
{
    const char *proto_name = NULL;
    enum AppProtoEnum proto = alproto;

    switch (proto) {
        case ALPROTO_HTTP:
            proto_name = "http";
            break;
        case ALPROTO_TLS:
            proto_name = "tls";
            break;
        case ALPROTO_DNS:
            proto_name = "dns";
            break;
        case ALPROTO_TEMPLATE:
            proto_name = "template";
            break;
        case ALPROTO_FAILED:
            proto_name = "failed";
            break;
#ifdef UNITTESTS
        case ALPROTO_TEST:
#endif
        case ALPROTO_MAX:
        case ALPROTO_UNKNOWN:
            break;
    }

    return proto_name;
}
