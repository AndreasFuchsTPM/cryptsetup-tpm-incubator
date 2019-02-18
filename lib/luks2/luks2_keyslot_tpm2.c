/*
 * LUKS - Linux Unified Key Setup v2, TPM type keyslot handler
 *
 * Copyright (C) 2018, Fraunhofer SIT sponsorred by Infineon Technologies AG
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <tss2/tss2_esys.h>

#include "luks2_internal.h"

/* Initialize the TPM including a potentially necessary TPM2_Startup command,
   which is needed for simulators and RPi TPM hats. */
static TSS2_RC tpm_init(struct crypt_device *cd,
    ESYS_CONTEXT **ctx)
{
    TSS2_RC r;
    log_dbg("Initializing ESYS connection");

    r = Esys_Initialize(ctx, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error initializing ESYS: %08x", r);
        return r;
    }
    r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
    if (r == TPM2_RC_INITIALIZE) {
        log_dbg("TPM already started up. Not an error !");
        r = TSS2_RC_SUCCESS;
    }
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "TPM StartUp command failed: %08x", r);
        Esys_Finalize(ctx);
    }
    return r;
}

/* This function constructs the TPML_PCR_SELECTION for the active PCR banks.
   It checks for SHA384, SHA256 and SHA1. If none is supported an error is
   returned. */
static TSS2_RC tpm_getPcrBanks(struct crypt_device *cd,
    uint32_t *pcrbanks)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;

    r = tpm_init(cd, &ctx);
    if (r != TSS2_RC_SUCCESS)
        return r;

    TPML_PCR_SELECTION readPCRs = { .count = 3, .pcrSelections = {
        { .hash = TPM2_ALG_SHA1, .sizeofSelect = 3,
          .pcrSelect = { 1, 0, 0 }},
        { .hash = TPM2_ALG_SHA256, .sizeofSelect = 3,
          .pcrSelect = { 1, 0, 0 }},
        { .hash = TPM2_ALG_SHA384, .sizeofSelect = 3,
          .pcrSelect = { 1, 0, 0 }}
    }};
    TPML_PCR_SELECTION *pcrs;

    r = Esys_PCR_Read(ctx,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      &readPCRs, NULL, &pcrs, NULL);
    Esys_Finalize(&ctx);
    if (r) {
        log_dbg("TPM returned 0x%08x.", r);
        return r;
    }

    if (pcrs->count == 0) {
        log_dbg("TPM does not support SHA256 nor SHA384 nor SHA1.");
        return -1;
    }

    *pcrbanks = 0;
    for (int i = 0; i < pcrs->count; i++) {
        switch(pcrs->pcrSelections[i].hash) {
        case TPM2_ALG_SHA1:
            *pcrbanks |= CRYPT_TPM_PCRBANK_SHA1;
            break;
        case TPM2_ALG_SHA256:
            *pcrbanks |= CRYPT_TPM_PCRBANK_SHA1;
            break;
        case TPM2_ALG_SHA384:
            *pcrbanks |= CRYPT_TPM_PCRBANK_SHA1;
            break;
        default:
            return -1;
        }
    }

    log_dbg("The TPM supports the following %i banks: 0x%08x.",
            pcrs->count, *pcrbanks);

    return 0;
}

static TSS2_RC tpm_getPcrDigest(struct crypt_device *cd,
    ESYS_CONTEXT *ctx,
    const TPML_PCR_SELECTION *pcrs,
    TPM2_ALG_ID hashAlg,
    TPM2B_DIGEST *pcrDigest)
{
    TSS2_RC r;
    TPM2B_AUTH auth = {0};
    ESYS_TR hash;
    TPML_DIGEST *value;
    TPML_PCR_SELECTION readPCRs = { .count = 1, .pcrSelections = {} };
    TPM2B_DIGEST *returnPcrDigest;

    r = Esys_HashSequenceStart(ctx,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &auth, hashAlg, &hash);
    if (r)
        return r;

    for (int i = 0; i < pcrs->count; i++) {

        readPCRs.pcrSelections[0].hash = pcrs->pcrSelections[i].hash;
        readPCRs.pcrSelections[0].sizeofSelect = 3;
        for (int j = 0; j < 24; j++) {
            if (!(pcrs->pcrSelections[i].pcrSelect[j / 8] & (1 << (j % 8))))
                continue;
            
            readPCRs.pcrSelections[0].pcrSelect[0] = 0;
            readPCRs.pcrSelections[0].pcrSelect[1] = 0;
            readPCRs.pcrSelections[0].pcrSelect[2] = 0;

            readPCRs.pcrSelections[0].pcrSelect[j / 8] = (1 << (j % 8));

            r = Esys_PCR_Read(ctx,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &readPCRs, NULL, NULL, &value);
//TODO:            if (r == 0x984) continue;
            if (r) {
                log_err(cd, "PCR Read failed with 0x%08x.", r);
                return r;
            }
            if (!value->count) {
                free(value);
                continue;
            }

            TPM2B_MAX_BUFFER digest = { .size = value->digests[0].size };
            memcpy(&digest.buffer[0], &value->digests[0].buffer, digest.size);

            r = Esys_SequenceUpdate(ctx, hash,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &digest);
            free(value);
            if (r) return r;
        }
    }
    r = Esys_SequenceComplete(ctx, hash,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL, TPM2_RH_NULL,
                              &returnPcrDigest, NULL);
    if (r) return r;
    *pcrDigest = *returnPcrDigest;
    free(returnPcrDigest);

    return 0;
}

static TSS2_RC tpm_policy_Read(struct crypt_device *cd,
    ESYS_CONTEXT *ctx,
    int tpm_pcr,
    uint32_t pcrbanks,
    ESYS_TR *authSession,
    TPM2B_DIGEST *authPolicy)
{
    (void)(cd);
    TSS2_RC r;
    ESYS_TR session;
    TPM2B_DIGEST *policyDigest;

    TPM2B_DIGEST pcrDigest = { .size = 0, .buffer = {} };
    TPML_PCR_SELECTION pcrs = { .count = 0 };

    TPMT_SYM_DEF sym = {.algorithm = TPM2_ALG_AES,
                        .keyBits = {.aes = 128},
                        .mode = {.aes = TPM2_ALG_CFB}
    };

    if (pcrbanks == 0) {
        log_err(cd, "No banks selected.");
        return -1;
    }

    if ((pcrbanks & CRYPT_TPM_PCRBANK_SHA1)) {
        pcrs.pcrSelections[pcrs.count].hash = TPM2_ALG_SHA1;
        pcrs.count++;
    }
    if ((pcrbanks & CRYPT_TPM_PCRBANK_SHA256)) {
        pcrs.pcrSelections[pcrs.count].hash = TPM2_ALG_SHA256;
        pcrs.count++;
    }
    if ((pcrbanks & CRYPT_TPM_PCRBANK_SHA384)) {
        pcrs.pcrSelections[pcrs.count].hash = TPM2_ALG_SHA384;
        pcrs.count++;
    }

    for (int i = 0; i < pcrs.count; i++) {
        pcrs.pcrSelections[i].sizeofSelect = 3;
        pcrs.pcrSelections[i].pcrSelect[0] = tpm_pcr & 0xff;
        pcrs.pcrSelections[i].pcrSelect[1] = tpm_pcr >>8 & 0xff;
        pcrs.pcrSelections[i].pcrSelect[2] = tpm_pcr >>16 & 0xff;
    }

    r = tpm_getPcrDigest(cd, ctx, &pcrs, TPM2_ALG_SHA256, &pcrDigest);
    if (r != TSS2_RC_SUCCESS) {
        return r;
    }

    r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                    &session);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "TPM returned error %08x", r);
        return r;
    }

    r = Esys_PolicyPCR(ctx, session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &pcrDigest, &pcrs);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "TPM returned error %08x", r);
        Esys_FlushContext(ctx, session);
        return r;
    }

    r = Esys_PolicyPassword(ctx, session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (r != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, session);
        log_err(cd, "TPM returned error %08x", r);
        return r;
    }

    r = Esys_PolicyCommandCode(ctx, session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    TPM2_CC_NV_Read);
    if (r != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, session);
        log_err(cd, "TPM returned error %08x", r);
        return r;
    }

    r = Esys_PolicyGetDigest(ctx, session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &policyDigest);
    if (r != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, session);
        log_err(cd, "TPM returned error %08x", r);
        return r;
    }

    if (authSession)
        *authSession = session;
    else
        Esys_FlushContext(ctx, session);

    if (authPolicy)
        *authPolicy = *policyDigest;
    free(policyDigest);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC tpm_nv_prep(struct crypt_device *cd,
    long int tpm_nv,
    const char *passphrase,
    size_t passphrase_size,
    ESYS_CONTEXT **ctx,
    ESYS_TR *nvIndex)
{
    (void)(cd); /* Only needed for log_err */
    TSS2_RC r;

    TPM2B_AUTH tpm_passphrase = { .size = passphrase_size, .buffer={} };
    if (passphrase_size > sizeof(tpm_passphrase.buffer))
        return -1;
    if (passphrase_size > 0)
        memcpy(&tpm_passphrase.buffer[0], passphrase, tpm_passphrase.size);

    if (tpm_nv < 0x01800000 || tpm_nv > 0x01BFFFFF) {
        log_err(cd, "NV index handle %08lx out of range", tpm_nv);
        return -1;
    }

    r = tpm_init(cd, ctx);
    if (r != TSS2_RC_SUCCESS)
        return r;

    r = Esys_TR_FromTPMPublic(*ctx, tpm_nv,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              nvIndex);
    if (r != TSS2_RC_SUCCESS) {
        Esys_Finalize(ctx);
        return r;
    }

    r = Esys_TR_SetAuth(*ctx, *nvIndex, &tpm_passphrase);
    if (r != TSS2_RC_SUCCESS) {
        Esys_Finalize(ctx);
        return r;
    }

    return r;
}

static TSS2_RC tpm_nv_read(struct crypt_device *cd,
    long int tpm_nv,
    int tpm_pcr,
    uint32_t pcrbanks,
    const char *passphrase,
    size_t passphrase_size,
    char *volume_key,
    size_t volume_key_len)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvIndex, session;
    TPM2B_MAX_NV_BUFFER *nv_pass;

    r = tpm_nv_prep(cd, tpm_nv, passphrase, passphrase_size, &ctx,
                    &nvIndex);
    if (r != TSS2_RC_SUCCESS)
        return r;

    r = tpm_policy_Read(cd, ctx, tpm_pcr, pcrbanks, &session, NULL);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "TPM returned error %08x", r);
        Esys_Finalize(&ctx);
        return r;
    }
    Esys_TRSess_SetAttributes(ctx, session, 0, TPMA_SESSION_CONTINUESESSION);

    r = Esys_NV_Read(ctx, nvIndex, nvIndex,
                     session, ESYS_TR_NONE, ESYS_TR_NONE,
                     volume_key_len, 0, &nv_pass);
    if (r != TSS2_RC_SUCCESS) {
        /* We are silent about auth failures since they can appear intentionally
           if multiple TPM keyslots are present */
        if (r != 0x9a2)
            log_err(cd, "TPM returned error %08x", r);
        r = Esys_FlushContext(ctx, session);
        Esys_Finalize(&ctx);
        return r;
    }

    if (volume_key_len != nv_pass->size) {
        log_err(cd, "VK lengths differ");
        Esys_Finalize(&ctx);
        return -1;
    }

    memcpy(volume_key, &nv_pass->buffer[0], volume_key_len);
    free(nv_pass);

    Esys_Finalize(&ctx);
    return 0;
}

static TSS2_RC tpm_nv_write(struct crypt_device *cd,
    long int tpm_nv,
    int tpm_pcr,
    const char *passphrase,
    size_t passphrase_size,
    const char *buffer,
    size_t buffer_size)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvIndex;

    TPM2B_MAX_NV_BUFFER nv_pass = { .size = buffer_size, .buffer = {} };
    if (buffer_size > sizeof(nv_pass.buffer)) {
        log_err(cd, "volumekey too large");
        return -EINVAL;
    }
    memcpy(&nv_pass.buffer[0], buffer, buffer_size);

    r = tpm_nv_prep(cd, tpm_nv, passphrase, passphrase_size, &ctx,
                    &nvIndex);
    if (r != TSS2_RC_SUCCESS)
        return r;

    r = Esys_NV_Write(ctx, nvIndex, nvIndex,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &nv_pass, 0);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error on NV_Write: %08x", r);
    }

    Esys_Finalize(&ctx);

    return r;
}

static TSS2_RC tpm_nv_define(struct crypt_device *cd,
    const char *passphrase,
    size_t passphrase_size,
    uint32_t tpm_nv,
    uint32_t tpm_pcr,
    uint32_t pcrbanks,
    bool noda,
    const char *ownerpw,
    size_t ownerpw_size)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvIndex;

    TPM2B_AUTH tpm_passphrase = { .size = passphrase_size, .buffer={} };
    if (passphrase_size > sizeof(tpm_passphrase.buffer))
        return -1;
    if (passphrase_size > 0)
        memcpy(&tpm_passphrase.buffer[0], passphrase, tpm_passphrase.size);

    TPM2B_NV_PUBLIC nvInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = tpm_nv,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = TPMA_NV_AUTHWRITE |
                          TPMA_NV_POLICYREAD |
                          TPMA_NV_WRITEALL,
            .authPolicy = {
                     .size = 0,
                     .buffer = {},
                 },
            .dataSize = 32
        }
    };

    if (noda)
        nvInfo.nvPublic.attributes |= TPMA_NV_NO_DA;

    if (tpm_nv < 0x01800000 || tpm_nv > 0x01BFFFFF) {
        log_err(cd, "NV index handle %08x out of range", tpm_nv);
        return -1;
    }

    r = tpm_init(cd, &ctx);
    if (r != TSS2_RC_SUCCESS)
        return r;

    if (ownerpw != NULL) {
        TPM2B_AUTH ownerauth = { .size = ownerpw_size, .buffer={} };
        if (ownerpw_size > sizeof(ownerauth.buffer))
            return -1;
        memcpy(&ownerauth.buffer[0], ownerpw, ownerauth.size);

        r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &ownerauth);
        if (r != TSS2_RC_SUCCESS) {
            Esys_Finalize(&ctx);
            return r;
        }
    }

    r = tpm_policy_Read(cd, ctx, tpm_pcr, pcrbanks, NULL, &nvInfo.nvPublic.authPolicy);
    if (r != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        return r;
    }

    log_dbg("Defining TPM handle 0x%08x.", tpm_nv);

    r = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &tpm_passphrase, &nvInfo,
                            &nvIndex);
    Esys_Finalize(&ctx);
    if (r != TSS2_RC_SUCCESS) {
        return r;
    }

    return r;
}

static int tpm_nv_undefine(struct crypt_device *cd,
    uint32_t tpm_nv,
    const char *ownerpw,
    size_t ownerpw_size)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvIndex;

    r = tpm_nv_prep(cd, tpm_nv, NULL, 0, &ctx, &nvIndex);
    if (r != TSS2_RC_SUCCESS)
        return r;

    log_dbg("Deleting TPM handle 0x%08x.", tpm_nv);

    r = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvIndex,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    Esys_Finalize(&ctx);
    if (r != TSS2_RC_SUCCESS)
        return r;

    return 0;
}

static TSS2_RC tpm_nv_find(struct crypt_device *cd,
    uint32_t *tpm_nv)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    ESYS_TR nvIndex;
    TPMS_CAPABILITY_DATA *capabilityData;

    r = tpm_init(cd, &ctx);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error connecting to TPM.");
        return r;
    }

    r = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_HANDLES, 0x01000000, 0xffff,
                           NULL, &capabilityData);
    Esys_Finalize(&ctx);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error retrieving TPM capabilities.");
        return r;
    }

    int i;
    for (nvIndex = 0x01BF0000; nvIndex < 0x01BF00FF; nvIndex++) {
        for (i = capabilityData->data.handles.count-1; i >= 0; i--) {
            if (nvIndex == capabilityData->data.handles.handle[i])
                break;
        }

        if (i < 0) {
            *tpm_nv = nvIndex;
            return 0;
        } else {
            log_dbg("NV-Index 0x%08x already in use.", nvIndex);
        }
    }

    log_err(cd, "Error no free slot found.");
    return -1;
}

static TSS2_RC tpm_nv_exists(struct crypt_device *cd,
    uint32_t tpm_nv)
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;
    TPMS_CAPABILITY_DATA *capabilityData;

    r = tpm_init(cd, &ctx);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error connecting to TPM.");
        return r;
    }

    r = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_HANDLES, 0x01000000, 0xffff,
                           NULL, &capabilityData);
    Esys_Finalize(&ctx);
    if (r != TSS2_RC_SUCCESS) {
        log_err(cd, "Error retrieving TPM capabilities.");
        return r;
    }

    int i;
    for (i = capabilityData->data.handles.count-1; i >= 0; i--) {
        if (tpm_nv == capabilityData->data.handles.handle[i])
            log_dbg("TPM-NV-Handle 0x%08x does exist.", tpm_nv);
            return 0xffffffff;
    }

    log_dbg("TPM-NV-Handle 0x%08x does not exist.", tpm_nv);
    return 0;
}

extern const keyslot_handler luks2_keyslot;

static int tpm_keyslot_alloc(struct crypt_device *cd,
    int keyslot,
    size_t volume_key_len,
    const struct luks2_keyslot_params *params)
{
    struct luks2_hdr *hdr;
    char num[16];
    uint32_t nvindex, pcrbanks;
    json_object *jobj_keyslots, *jobj_keyslot, *jobj_area;
    TSS2_RC trc;

    log_dbg("Trying to allocate TPM keyslot %d.", keyslot);

    if (!params || params->area_type != LUKS2_KEYSLOT_AREA_TPM) {
        log_dbg("Invalid LUKS2 keyslot parameters.");
        return -EINVAL;
    }

    if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
        return -EINVAL;

    if (keyslot == CRYPT_ANY_SLOT)
        keyslot = LUKS2_keyslot_find_empty(hdr, "tpm2");

    if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX)
        return -ENOMEM;

    if (LUKS2_get_keyslot_jobj(hdr, keyslot)) {
        log_dbg("Cannot modify already active keyslot %d.", keyslot);
        return -EINVAL;
    }

    nvindex = params->area.tpm.nvindex;

    if (nvindex == 0) {
        trc = tpm_nv_find(cd, &nvindex);
        if (trc) {
            log_err(cd, "NV finding failed.");
            return -EACCES;
        }
    }

    pcrbanks = params->area.tpm.pcrbanks;

    if (!pcrbanks) {
        log_dbg("No PCR banks selected, autodetecting.");
        trc = tpm_getPcrBanks(cd, &pcrbanks);
        if (trc) {
            log_err(cd, "Bank detection failed.");
            return -EACCES;
        }
    }

    trc = tpm_nv_define(cd, NULL, 0, 
                                nvindex,
                                params->area.tpm.pcrselection,
                                pcrbanks,
                                params->area.tpm.noda,
                                NULL, 0);
    if (trc) {
        log_err(cd, "NV allocation failed.");
        return -EACCES;
    }

    if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
        return -EINVAL;

    jobj_keyslot = json_object_new_object();
    json_object_object_add(jobj_keyslot, "type", json_object_new_string("tpm2"));
    json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(volume_key_len));

    /* Area object */
    jobj_area = json_object_new_object();
    json_object_object_add(jobj_area, "type", json_object_new_string("tpm2nv"));
    json_object_object_add(jobj_area, "nvindex", json_object_new_int64(nvindex));
    json_object_object_add(jobj_area, "pcrselection", json_object_new_int64(params->area.tpm.pcrselection));
    json_object_object_add(jobj_area, "pcrbanks", json_object_new_int64(pcrbanks));
    json_object_object_add(jobj_area, "noda", json_object_new_boolean(params->area.tpm.noda));
    json_object_object_add(jobj_keyslot, "area", jobj_area);

    snprintf(num, sizeof(num), "%d", keyslot);

    json_object_object_add(jobj_keyslots, num, jobj_keyslot);

    if (LUKS2_check_json_size(hdr)) {
        log_dbg("Not enough space in header json area for new keyslot.");
        json_object_object_del(jobj_keyslots, num);
        return -ENOSPC;
    }

    return 0;
}

/* We currently do not support updates of keyslot parameters */
static int tpm_keyslot_update(struct crypt_device *cd,
    int keyslot,
    const struct luks2_keyslot_params *params)
{
    log_err(cd, "Keyslot parameter update not supported for TPM keyslots.");
    return -EINVAL;
}

static int tpm_keyslot_open(struct crypt_device *cd,
    int keyslot,
    const char *password,
    size_t password_len,
    char *volume_key,
    size_t volume_key_len)
{

    struct luks2_hdr *hdr;
    json_object *jobj_keyslot, *jobj_area, *jobj1;
    uint32_t nvindex, pcrselection, pcrbanks;

    log_dbg("Trying to open LUKS2 TPM keyslot %d.", keyslot);

    if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
        return -EINVAL;

    jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
    if (!jobj_keyslot)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_area, "nvindex", &jobj1))
        return -EINVAL;
    nvindex = (uint32_t)json_object_get_uint64(jobj1);

    if (!json_object_object_get_ex(jobj_area, "type", &jobj1))
        return -EINVAL;
    if (strcmp(json_object_get_string(jobj1), "tpm2nv") != 0)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_area, "pcrselection", &jobj1))
        return -EINVAL;
    pcrselection = (uint32_t)json_object_get_uint64(jobj1);

    if (!json_object_object_get_ex(jobj_area, "pcrbanks", &jobj1))
        return -EINVAL;
    pcrbanks = (uint32_t)json_object_get_uint64(jobj1);

    TSS2_RC r = tpm_nv_read(cd, nvindex, pcrselection, pcrbanks,
                        password, password_len,
                        volume_key, volume_key_len);

    if (r == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_BAD_AUTH) ||
        r == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_AUTH_FAIL))
        return -EPERM;
    if (r) {
        log_err(cd, "TPM NV Read failed with %08x", r);
        return -EINVAL;
    }

    return 0;
}

static int tpm_keyslot_store(struct crypt_device *cd,
    int keyslot,
    const char *password,
    size_t password_len,
    const char *volume_key,
    size_t volume_key_len)
{
    struct luks2_hdr *hdr;
    json_object *jobj_keyslot, *jobj_area, *jobj1;
    uint32_t nvindex, pcrselection, pcrbanks;
    bool noda;
    TSS2_RC trc;
    int r;

    log_dbg("Calculating attributes for LUKS2 TPM keyslot %d.", keyslot);

    if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
        return -EINVAL;

    jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
    if (!jobj_keyslot)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
        return -EINVAL;

    json_object_object_get_ex(jobj_area, "nvindex", &jobj1);
    nvindex = (uint32_t)json_object_get_uint64(jobj1);

    json_object_object_get_ex(jobj_area, "pcrselection", &jobj1);
    pcrselection = (uint32_t)json_object_get_uint64(jobj1);

    json_object_object_get_ex(jobj_area, "pcrbanks", &jobj1);
    pcrbanks = (uint32_t)json_object_get_uint64(jobj1);
    
    json_object_object_get_ex(jobj_area, "noda", &jobj1);
    noda = (uint32_t)json_object_get_boolean(jobj1);

    char keystr[volume_key_len*2+1];
    keystr[volume_key_len*2] = '\0';
    for (int i = 0; i < volume_key_len; i++)
        sprintf(&keystr[i*2], "%02x", (uint8_t)volume_key[i]);
    json_object *jobj_key = json_object_new_string(keystr);
    json_object_object_add(jobj_keyslot, "key", jobj_key);

    /* Though it may appear intuitive to just call changeauth here after the
       alloc, we don't.
       The reason is that the LUKS_changeauth will call wipe (which does a
       tpm_nv_undefine) followed by a store (this function). Thus we have to
       call for a tpm_nv_define anyways. */
    trc = tpm_nv_exists(cd, nvindex);
    if (trc != 0 && trc != 0xffffffff) {
        log_err(cd, "TPM NV exists error.");
        return -EINVAL;
    }

    if (trc == 0xffffffff) {
        /* This branch is only entered on store after alloc, but not on store
           after wipe (LUKS_changeauth case). */
        trc = tpm_nv_undefine(cd, nvindex, NULL, 0);
        if (trc) {
            log_err(cd, "TPM NV Undefine error.");
            return -EINVAL;
        }
    }

    trc = tpm_nv_define(cd, password, password_len, nvindex,
                                pcrselection, pcrbanks, noda, NULL, 0);
    if (trc) {
        log_err(cd, "TPM NV Define error.");
        return -EINVAL;
    }

    trc = tpm_nv_write(cd, nvindex, pcrselection,
                               password, password_len,
                               volume_key, volume_key_len);
    if (trc) {
        log_err(cd, "TPM NV Write error.");
        return -EINVAL;
    }

    r = LUKS2_hdr_write(cd, hdr);
    if (r < 0)
        return r;

    return keyslot;
}

static int tpm_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
    struct luks2_hdr *hdr;
    json_object *jobj_keyslot, *jobj_area, *jobj1;
    uint32_t nvindex;

    log_dbg("Wiping TPM keyslot %i", keyslot);

    if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
        return -EINVAL;

    jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
    if (!jobj_keyslot)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
        return -EINVAL;

    json_object_object_get_ex(jobj_area, "nvindex", &jobj1);
    nvindex = (uint32_t)json_object_get_uint64(jobj1);

    TSS2_RC
    trc = tpm_nv_undefine(cd, nvindex, NULL, 0);
    if (trc) {
        log_err(cd, "TPM NV Undefine error. Please remove NV 0x%08x manually",
                nvindex);
        return -EINVAL;
    }

    /* Remove any reference of deleted keyslot from digests and tokens */
    LUKS2_digest_assign(cd, hdr, keyslot, CRYPT_ANY_DIGEST, 0, 0);
    LUKS2_token_assign(cd, hdr, keyslot, CRYPT_ANY_TOKEN, 0, 0);

    return 0;
}

static int tpm_keyslot_dump(struct crypt_device *cd, int keyslot)
{
    json_object *jobj_keyslot, *jobj1, *jobj_area;

    jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
    if (!jobj_keyslot)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
        return -EINVAL;

    json_object_object_get_ex(jobj_area, "key_size", &jobj1);
    log_std(cd, "\tkey_size:   %s [bytes]\n", json_object_get_string(jobj1));

    json_object_object_get_ex(jobj_area, "nvindex", &jobj1);
    log_std(cd, "\tnvindex:    0x%08" PRIx32 "\n",
            (uint32_t) json_object_get_uint64(jobj1));

    json_object_object_get_ex(jobj_area, "pcrselection", &jobj1);
    log_std(cd, "\tpcrsel:     0x%08" PRIx32 " [bits]\n",
            (uint32_t) json_object_get_uint64(jobj1));

    json_object_object_get_ex(jobj_area, "pcrbanks", &jobj1);
    log_std(cd, "\tpcrbanks:   0x%08" PRIx32 " [bits]\n",
            (uint32_t) json_object_get_uint64(jobj1));

    json_object_object_get_ex(jobj_area, "noda", &jobj1);
    log_std(cd, "\tnoda:           %" PRIx32 " [bool]\n",
            (uint32_t) json_object_get_boolean(jobj1));

    return 0;
}

static int tpm_keyslot_validate(struct crypt_device *cd, json_object *jobj_keyslot)
{
    json_object *jobj_area, *jobj1;

    if (!jobj_keyslot)
        return -EINVAL;

    if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
        return -EINVAL;

    // FIXME check numbered
    if (!json_object_object_get_ex(jobj_area, "type", &jobj1))
        return -EINVAL;
    if (!strcmp(json_object_get_string(jobj1), "tpm2nv")) {
        if (!json_contains(jobj_area, "area", "tpm2nv type", "nvindex", json_type_int) ||
            !json_contains(jobj_area, "area", "tpm2nv type", "pcrselection", json_type_int) ||
            !json_contains(jobj_area, "area", "tpm2nv type", "pcrbanks", json_type_int) ||
            !json_contains(jobj_area, "area", "tpm2nv type", "noda", json_type_boolean)) {
            log_err(cd, "JSON is malformed.");
            return -EINVAL;
        }
    } else {
        return -EINVAL;
    }
    return 0;
}

static void tpm_keyslot_repair(struct crypt_device *cd, json_object *jobj_keyslot)
{
    log_err(cd, "Keyslot repair not supported for TPM keyslots.");
    (void)(jobj_keyslot);
}

const keyslot_handler tpm_keyslot = {
    .name  = "tpm2",
    .alloc  = tpm_keyslot_alloc,
    .update = tpm_keyslot_update,
    .open  = tpm_keyslot_open,
    .store = tpm_keyslot_store,
    .wipe  = tpm_keyslot_wipe,
    .dump  = tpm_keyslot_dump,
    .validate = tpm_keyslot_validate,
    .repair = tpm_keyslot_repair
};
