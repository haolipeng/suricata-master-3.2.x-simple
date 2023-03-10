/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 */

#ifndef __TM_QUEUES_H__
#define __TM_QUEUES_H__

//实现对队列的管理
typedef struct Tmq_ {
    char *name;//队列名称
    uint16_t id;//对应的队列存储在trans_q中的索引
    uint16_t reader_cnt;//读队列中数据的线程数
    uint16_t writer_cnt;//向队列写数据的线程数
    /* 0 for packet-queue and 1 for data-queue */
    uint8_t q_type;//队列类型， 0为数据包队列，1为数据队列
} Tmq;

Tmq* TmqCreateQueue(char *name);
Tmq* TmqGetQueueByName(char *name);

void TmqDebugList(void);
void TmqResetQueues(void);
void TmValidateQueueState(void);

#endif /* __TM_QUEUES_H__ */

