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
 *
 * Implements the msg keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "util-classification-config.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

static int DetectMsgSetup (DetectEngineCtx *, Signature *, char *);
void DetectMsgRegisterTests(void);

void DetectMsgRegister (void)
{
    sigmatch_table[DETECT_MSG].name = "msg";
    sigmatch_table[DETECT_MSG].desc = "information about the rule and the possible alert";
    sigmatch_table[DETECT_MSG].url = DOC_URL DOC_VERSION "/rules/meta.html#msg-message";
    sigmatch_table[DETECT_MSG].Match = NULL;
    sigmatch_table[DETECT_MSG].Setup = DetectMsgSetup;
    sigmatch_table[DETECT_MSG].Free = NULL;
    sigmatch_table[DETECT_MSG].RegisterTests = DetectMsgRegisterTests;
}

static int DetectMsgSetup (DetectEngineCtx *de_ctx, Signature *s, char *msgstr)
{
    char *str = NULL;
    uint16_t len;
    uint16_t pos = 0;
    uint16_t slen = 0;

    slen = strlen(msgstr);
    if (slen == 0)
        goto error;

    /* skip the first spaces */
    while (pos < slen && isspace((unsigned char)msgstr[pos]))
        pos++;

    /* Strip leading and trailing "s. */
    if (msgstr[pos] == '\"') {
        str = SCStrdup(msgstr + pos + 1);
        if (unlikely(str == NULL))
            goto error;
        if (strlen(str) && str[strlen(str) - 1] == '\"') {
            str[strlen(str)-1] = '\0';
        }
    } else {
        SCLogError(SC_ERR_INVALID_VALUE, "format error \'%s\'", msgstr);
        goto error;
    }

    len = strlen(str);
    if (len == 0)
        goto error;

    char converted = 0;

    {
        uint16_t i, x;
        uint8_t escape = 0;

        /* it doesn't matter if we need to escape or not we remove the extra "\" to mimic snort */
        for (i = 0, x = 0; i < len; i++) {
            //printf("str[%02u]: %c\n", i, str[i]);
            if(!escape && str[i] == '\\') {
                escape = 1;
            } else if (escape) {
                if (str[i] != ':' &&
                        str[i] != ';' &&
                        str[i] != '\\' &&
                        str[i] != '\"')
                {
                    SCLogDebug("character \"%c\" does not need to be escaped but is" ,str[i]);
                }
                escape = 0;
                converted = 1;

                str[x] = str[i];
                x++;
            }else{
                str[x] = str[i];
                x++;
            }

        }
#if 0 //def DEBUG
        if (SCLogDebugEnabled()) {
            for (i = 0; i < x; i++) {
                printf("%c", str[i]);
            }
            printf("\n");
        }
#endif

        if (converted) {
            len = x;
            str[len] = '\0';
        }
    }

    if (s->msg != NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "duplicated 'msg' keyword detected");
        goto error;
    }

    s->msg = SCMalloc(len + 1);
    if (s->msg == NULL)
        goto error;

    strlcpy(s->msg, str, len + 1);

    SCFree(str);
    return 0;

error:
    SCFree(str);
    return -1;
}

/* -------------------------------------Unittests-----------------------------*/

#ifdef UNITTESTS
static int DetectMsgParseTest01(void)
{
    int result = 0;
    Signature *sig = NULL;
    char *teststringparsed = "flow stateless to_server";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"flow stateless to_server\"; flow:stateless,to_server; content:\"flowstatelesscheck\"; classtype:bad-unknown; sid: 40000002; rev: 1;)");
    if(sig == NULL)
        goto end;

    if (strcmp(sig->msg, teststringparsed) != 0) {
        printf("got \"%s\", expected: \"%s\": ", sig->msg, teststringparsed);
        goto end;
    }

    result = 1;
end:
    if (sig != NULL)
        SigFree(sig);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectMsgParseTest02(void)
{
    int result = 0;
    Signature *sig = NULL;
    char *teststringparsed = "msg escape tests wxy'\"\\;:";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"msg escape tests \\w\\x\\y\\'\\\"\\\\;\\:\"; flow:to_server,established; content:\"blah\"; uricontent:\"/blah/\"; sid: 100;)");
    if(sig == NULL)
        goto end;

    if (strcmp(sig->msg, teststringparsed) != 0) {
        printf("got \"%s\", expected: \"%s\": ",sig->msg, teststringparsed);
        goto end;
    }

    result = 1;
end:
    if (sig != NULL)
        SigFree(sig);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectMsgParseTest03(void)
{
    int result = 0;
    Signature *sig = NULL;
    char *teststringparsed = "flow stateless to_server";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg: \"flow stateless to_server\"; flow:stateless,to_server; content:\"flowstatelesscheck\"; classtype:bad-unknown; sid: 40000002; rev: 1;)");
    if(sig == NULL)
        goto end;

    if (strcmp(sig->msg, teststringparsed) != 0) {
        printf("got \"%s\", expected: \"%s\": ", sig->msg, teststringparsed);
        goto end;
    }

    result = 1;
end:
    if (sig != NULL)
        SigFree(sig);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectMsg
 */
void DetectMsgRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectMsgParseTest01", DetectMsgParseTest01);
    UtRegisterTest("DetectMsgParseTest02", DetectMsgParseTest02);
    UtRegisterTest("DetectMsgParseTest03", DetectMsgParseTest03);
#endif /* UNITTESTS */
}

