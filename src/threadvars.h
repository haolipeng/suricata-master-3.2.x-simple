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
 */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

#include "util-affinity.h"
#include "tm-queues.h"
#include "counters.h"
#include "threads.h"

struct TmSlot_;

/** Thread flags set and read by threads to control the threads */
#define THV_USE       1 /** thread is in use */
#define THV_INIT_DONE (1 << 1) /** thread initialization done */
#define THV_PAUSE     (1 << 2) /** signal thread to pause itself */
#define THV_PAUSED    (1 << 3) /** the thread is paused atm */
#define THV_KILL      (1 << 4) /** thread has been asked to cleanup and exit */
#define THV_FAILED    (1 << 5) /** thread has encountered an error and failed */
#define THV_CLOSED    (1 << 6) /** thread done, should be joinable */
/* used to indicate the thread is going through de-init.  Introduced as more
 * of a hack for solving stream-timeout-shutdown.  Is set by the main thread. */
#define THV_DEINIT    (1 << 7)
#define THV_RUNNING_DONE (1 << 8) /** thread has completed running and is entering
                                   * the de-init phase */
#define THV_KILL_PKTACQ (1 << 9)    /**< flag thread to stop packet acq */
#define THV_FLOW_LOOP (1 << 10)   /**< thread is in flow shutdown loop */

/** signal thread's capture method to create a fake packet to force through
 *  the engine. This is to force timely handling of maintenance taks like
 *  rule reloads even if no packets are read by the capture method. */
#define THV_CAPTURE_INJECT_PKT (1<<11)

/** \brief Per thread variable structure */
typedef struct ThreadVars_ {
    pthread_t t;				//线程句柄
    char name[16];				//线程名称
    char *thread_group_name;

    SC_ATOMIC_DECLARE(unsigned int, flags);//标记线程当前状态

    /** TmModule::flags for each module part of this thread */
    uint8_t tmm_flags;

    /** local id */
    int id;

    /** queue's */
    Tmq *inq;					//输入数据包的队列
    Tmq *outq;					//输出数据包的队列
    void *outctx;				//autofp模式下，每个捕获线程需要保存所有worker线程的PacketQueue，采用此成员存储
    char *outqh_name;			//输出数据包队列处理程序的名称

    /** queue handlers */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);//输入数据包的队列处理程序中的InHandler
    void (*InShutdownHandler)(struct ThreadVars_ *);//tmqh_in所属的队列处理程序中的InShutdownHandler
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);//输出数据包的队列处理程序中的OutHandler

    /** slot functions */
	//线程的入口函数，有以下几种选择：
	//参数”varslot”，TmThreadsSlotVar
	//参数”pktacqloop”，TmThreadsSlotPktAcqLoop(默认)
	//参数”command”，TmThreadsManagement
	//以上都是在TmThreadSetSlots函数进行设置的
    void *(*tm_func)(void *);
    struct TmSlot_ *tm_slots;//线程下挂在的TmSlot链表，每个TmSlot下有多个模块

    /** stream packet queue for flow time out injection */
    struct PacketQueue_ *stream_pq;//这玩意是干啥的

    uint8_t thread_setup_flags;//线程启动时的优先级和cpu亲和性

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
	//线程类型，共三种
	//TVT_PPT 数据包处理线程
	//TVT_MGMT 管理线程
	//TVT_CMD 指令接收线程
    uint8_t type;

    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    uint16_t rank;
    int thread_priority; /** priority (real time) for this thread. Look at threads.h */

    /* counters */

    /** public counter store: counter syncs update this */
    StatsPublicThreadContext perf_public_ctx;

    /** private counter store: counter updates modify this */
    StatsPrivateThreadContext perf_private_ctx;

    SCCtrlMutex *ctrl_mutex;
    SCCtrlCondT *ctrl_cond;

    uint8_t cap_flags; /**< Flags to indicate the capabilities of all the
                            TmModules resgitered under this thread */
	//将同类型线程存放到全局变量数组tv_root下，使用pre和next进行连接
    struct ThreadVars_ *next;
    struct ThreadVars_ *prev;
} ThreadVars;

/** Thread setup flags: */
#define THREAD_SET_AFFINITY     0x01 /** CPU/Core affinity */
#define THREAD_SET_PRIORITY     0x02 /** Real time priority */
#define THREAD_SET_AFFTYPE      0x04 /** Priority and affinity */

#endif /* __THREADVARS_H__ */

