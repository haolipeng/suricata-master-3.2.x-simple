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

#ifndef __TM_THREADS_COMMON_H__
#define __TM_THREADS_COMMON_H__

/** \brief Thread Model Module id's.
 *
 *  \note anything added here should also be added to TmModuleTmmIdToString
 *        in tm-modules.c
 */
typedef enum {
    TMM_FLOWWORKER,
    TMM_RECEIVEPCAP,        //receive pcap
    TMM_RECEIVEPCAPFILE,    //receive pcap file
    TMM_DECODEPCAP,         //decode pcap
    TMM_DECODEPCAPFILE,     //decode pcap file

    TMM_RECEIVEPFRING,      //receive pfring
    TMM_DECODEPFRING,       //decode pfring

    TMM_RESPONDREJECT,

    TMM_RECEIVEAFP,         //receive AF_PACKET
    TMM_DECODEAFP,          //decode AF_PACKET

    TMM_ALERTPCAPINFO,

    TMM_STATSLOGGER,

    TMM_FLOWMANAGER,
    TMM_FLOWRECYCLER,
    TMM_DETECTLOADER,

    TMM_UNIXMANAGER,

    TMM_SIZE,
} TmmId;

/*Error codes for the thread modules*/
typedef enum {
    TM_ECODE_OK = 0,    /**< Thread module exits OK*/
    TM_ECODE_FAILED,    /**< Thread module exits due to failure*/
    TM_ECODE_DONE,    /**< Thread module task is finished*/
} TmEcode;

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_CMD,
    TVT_MAX,
};

#endif /* __TM_THREADS_COMMON_H__ */

