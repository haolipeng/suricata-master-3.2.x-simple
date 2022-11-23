/* Copyright (C) 2014 Open Information Security Foundation
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
* \ingroup netmap
*
* @{
*/

/**
* \file
*
* \author Aleksey Katargin <gureedo@gmail.com>
*
* Netmap runmode
*
*/

#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-netmap.h"
#include "log-httplog.h"
#include "output.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"

#include "source-netmap.h"

extern int max_pending_packets;

static const char *default_mode_workers = NULL;

const char *RunModeNetmapGetDefaultMode(void)
{
    return default_mode_workers;
}

void RunModeIdsNetmapRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "single",
            "Single threaded netmap mode",
            RunModeIdsNetmapSingle);
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "workers",
            "Workers netmap mode, each thread does all"
                    " tasks from acquisition to logging",
            RunModeIdsNetmapWorkers);
    default_mode_workers = "workers";
    RunModeRegisterNewRunMode(RUNMODE_NETMAP, "autofp",
            "Multi threaded netmap mode.  Packets from "
                    "each flow are assigned to a single detect "
                    "thread.",
            RunModeIdsNetmapAutoFp);
    return;
}

int RunModeIdsNetmapAutoFp(void)
{
    SCEnter();

    SCReturnInt(0);
}

/**
* \brief Single thread version of the netmap processing.
*/
int RunModeIdsNetmapSingle(void)
{
    SCEnter();

    SCReturnInt(0);
}

/**
* \brief Workers version of the netmap processing.
*
* Start N threads with each thread doing all the work.
*
*/
int RunModeIdsNetmapWorkers(void)
{
    SCEnter();

    SCReturnInt(0);
}

/**
* @}
*/
