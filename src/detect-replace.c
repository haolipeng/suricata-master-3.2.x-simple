/* Copyright (C) 2011-2014 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Replace part of the detection engine.
 *
 * If previous filter is of content type, replace can be used to change
 * the matched part to a new value.
 */

#include "suricata-common.h"

#include "runmodes.h"

extern int run_mode;

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-byte-extract.h"
#include "detect-replace.h"
#include "app-layer.h"

#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "detect-engine-state.h"

#include "util-checksum.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "flow-var.h"

#include "util-debug.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

static int DetectReplaceSetup(DetectEngineCtx *, Signature *, char *);
void DetectReplaceRegisterTests(void);

void DetectReplaceRegister (void)
{
    sigmatch_table[DETECT_REPLACE].name = "replace";
    sigmatch_table[DETECT_REPLACE].Match = NULL;
    sigmatch_table[DETECT_REPLACE].Setup = DetectReplaceSetup;
    sigmatch_table[DETECT_REPLACE].Free  = NULL;
    sigmatch_table[DETECT_REPLACE].RegisterTests = DetectReplaceRegisterTests;

    sigmatch_table[DETECT_REPLACE].flags |= SIGMATCH_PAYLOAD;
}

int DetectReplaceSetup(DetectEngineCtx *de_ctx, Signature *s, char *replacestr)
{
    uint8_t *content = NULL;
    uint16_t len = 0;
    uint32_t flags = 0;
    SigMatch *pm = NULL;
    DetectContentData *ud = NULL;

    int ret = DetectContentDataParse("replace", replacestr, &content, &len, &flags);
    if (ret == -1)
        goto error;

    if (flags & DETECT_CONTENT_NEGATED) {
        SCLogError(SC_ERR_INVALID_VALUE, "Can't negate replacement string: %s",
                   replacestr);
        goto error;
    }

    switch (run_mode) {
        default:
            SCLogWarning(SC_ERR_RUNMODE,
                         "Can't use 'replace' keyword in non IPS mode: %s",
                         s->sig_str);
            /* this is a success, having the alert is interesting */
            return 0;
    }

    /* add to the latest "content" keyword from either dmatch or pmatch */
    pm =  SigMatchGetLastSMFromLists(s, 2,
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
    if (pm == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "replace needs"
                "preceding content option for raw sig");
        SCFree(content);
        return -1;
    }

    /* we can remove this switch now with the unified structure */
    ud = (DetectContentData *)pm->ctx;
    if (ud == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
        SCFree(content);
        return -1;
    }
    if (ud->flags & DETECT_CONTENT_NEGATED) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                "negated keyword set along with a replacement");
        goto error;
    }
    if (ud->content_len != len) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a content "
                "length different from replace length");
        goto error;
    }

    ud->replace = SCMalloc(len);
    if (ud->replace == NULL) {
        goto error;
    }
    memcpy(ud->replace, content, len);
    ud->replace_len = len;
    ud->flags |= DETECT_CONTENT_REPLACE;
    /* want packet matching only won't be able to replace data with
     * a flow.
     */
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    SCFree(content);

    return 0;

error:
    SCFree(content);
    return -1;
}

/* Add to the head of the replace-list.
 *
 * The first to add to the replace-list has the highest priority. So,
 * adding the the head of the list results in the newest modifications
 * of content being applied first, so later changes can over ride
 * earlier changes. Thus the highest priority modifications should be
 * applied last.
 */
DetectReplaceList *DetectReplaceAddToList(DetectReplaceList *replist,
                                          uint8_t *found,
                                          DetectContentData *cd)
{
    DetectReplaceList *newlist;

    if (cd->content_len != cd->replace_len)
        return NULL;
    SCLogDebug("replace: Adding match");

    newlist = SCMalloc(sizeof(DetectReplaceList));
    if (unlikely(newlist == NULL))
        return replist;
    newlist->found = found;
    newlist->cd = cd;
    /* Push new value onto the front of the list. */
    newlist->next = replist;

    return newlist;
}


void DetectReplaceExecuteInternal(Packet *p, DetectReplaceList *replist)
{
    DetectReplaceList *tlist = NULL;

    SCLogDebug("replace: Executing match");
    while (replist) {
        memcpy(replist->found, replist->cd->replace, replist->cd->replace_len);
        SCLogDebug("replace: injecting '%s'", replist->cd->replace);
        p->flags |= PKT_STREAM_MODIFIED;
        ReCalculateChecksum(p);
        tlist = replist;
        replist = replist->next;
        SCFree(tlist);
    }
}


void DetectReplaceFreeInternal(DetectReplaceList *replist)
{
    DetectReplaceList *tlist = NULL;
    while (replist) {
        SCLogDebug("replace: Freeing match");
        tlist = replist;
        replist = replist->next;
        SCFree(tlist);
    }
}
/**
 * \brief this function registers unit tests for DetectContent
 */
void DetectReplaceRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    //delete by haolipeng at 2023-02-15s
#endif /* UNITTESTS */
}
