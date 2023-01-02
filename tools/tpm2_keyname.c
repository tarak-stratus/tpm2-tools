/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;


    /*
     * Outputs
     */
    char *output_file_path;
    FILE *foutput;
    TPM2B_NAME *name;
};

static tpm_rsadecrypt_ctx ctx = {
    .name = NULL,
};

static tool_rc key_name(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_key_name(ectx, &ctx.key.object, &ctx.name);
    return rc;
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    is_file_op_success = files_write_bytes(ctx.foutput, (UINT8*)ctx.name->name,
        ctx.name->size);
    if (ctx.foutput != stdout) {
        fclose(ctx.foutput);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;


    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
        ctx.key.auth_str, &ctx.key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        goto out;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    ctx.foutput = ctx.output_file_path ?
        fopen(ctx.output_file_path, "wb+") : stdout;
    if (!ctx.foutput) {
        return tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */

out:
    Esys_Free(ctx.name);
    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.key.ctx_path) {
        LOG_ERR("Expected argument -c.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'o': {
        ctx.output_file_path = value;
        break;
    }
    }
    return true;
}

static bool on_args(int argc, char **argv) {
    UNUSED(argv);
    UNUSED(argc);
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "output",      required_argument, 0, 'o' },
      { "key-context", required_argument, 0, 'c' },
    };

    *opts = tpm2_options_new("o:c:", ARRAY_LEN(topts), topts, on_option,
        on_args, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = key_name(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    Esys_Free(ctx.name);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("keyname", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
