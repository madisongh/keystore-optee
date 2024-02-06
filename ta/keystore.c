/* SPDX-License-Identifier: MIT */
/*
 * Keystore TA for OP-TEE
 *
 * Stores or etrieves a passphrase for use with
 * LUKS or other device storage encryption method.
 *
 * Copyright (c) 2023, M. Madison
 */

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "keystore.h"

static uint32_t disabled_ids;

struct session_context {
	uint8_t ppbuf[KEYSTORE_PP_MAXSIZE];
	char objname[16];
};

TEE_Result
TA_CreateEntryPoint (void)
{
	disabled_ids = 0;
	return TEE_SUCCESS;

} /* TA_CreateEntryPoint */

void
TA_DestroyEntryPoint (void)
{
	return;

} /* TA_DestroyEntryPoint */

static TEE_Result
retrieve_passphrase (struct session_context *ctx, uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle ppobj;
	TEE_ObjectInfo pp_info;
	TEE_Result result;
	uint32_t bytecount;
	int objnamelen;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.a > KEYSTORE_MAX_ID) {
		EMSG("Invalid passphrase ID: %u", params[0].value.a);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (disabled_ids & (1U << params[0].value.a)) {
		EMSG("Attempt to retrieve disabled passphrase ID: %u", params[0].value.a);
		return TEE_ERROR_ACCESS_DENIED;
	}

	objnamelen = snprintf(ctx->objname, sizeof(ctx->objname),
			      "keystore.pp.%u", params[0].value.a);
	if (objnamelen < 0) {
		EMSG("Failed to format object name");
		return TEE_ERROR_GENERIC;
	}

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_RPMB,
					  ctx->objname, (uint32_t) objnamelen,
					  TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
					  &ppobj);
	if (result != TEE_SUCCESS)
		return result;

	result = TEE_GetObjectInfo1(ppobj, &pp_info);
	if (result == TEE_SUCCESS) {
		if (pp_info.dataSize > params[2].memref.size || pp_info.dataSize > sizeof(ctx->ppbuf))
			result = TEE_ERROR_SHORT_BUFFER;
		else {
			result = TEE_ReadObjectData(ppobj, ctx->ppbuf, pp_info.dataSize, &bytecount);
			if (result == TEE_SUCCESS) {
				TEE_MemMove(params[2].memref.buffer, ctx->ppbuf, bytecount);
				params[2].memref.size = bytecount;
				if ((params[1].value.a & KEYSTORE_RETRIEVE_NODISABLE) == 0)
					disabled_ids |= (1U << params[0].value.a);
			}
		}
	}
	TEE_CloseObject(ppobj);
	return result;

} /* retrieve_passphrase */

static TEE_Result
store_passphrase (struct session_context *ctx, uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle ppobj;
	TEE_Result result;
	uint32_t objectflags;
	int objnamelen;
	int tries_remaining;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].value.a > KEYSTORE_MAX_ID) {
		EMSG("Invalid passphrase ID: %u", params[0].value.a);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (params[2].memref.size > sizeof(ctx->ppbuf))
		return TEE_ERROR_EXCESS_DATA;
	TEE_MemMove(ctx->ppbuf, params[2].memref.buffer, params[2].memref.size);
	objnamelen = snprintf(ctx->objname, sizeof(ctx->objname), "keystore.pp.%u", params[0].value.a);
	if (objnamelen < 0) {
		EMSG("Failed to format object name");
		return TEE_ERROR_GENERIC;
	}
	objectflags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META;
	if ((params[1].value.a & KEYSTORE_STORE_OVERWRITE) != 0)
		objectflags |= TEE_DATA_FLAG_OVERWRITE;
	for (tries_remaining = 2; tries_remaining > 0; tries_remaining -= 1) {
		result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_RPMB,
						    ctx->objname, (uint32_t) objnamelen,
						    objectflags,
						    TEE_HANDLE_NULL,
						    ctx->ppbuf, params[2].memref.size,
						    &ppobj);
		if (result == TEE_SUCCESS)
			break;
		EMSG("TEE_CreatePersistentOjbect returned 0x%x, tries remaining: %d", result, tries_remaining - 1);
	}
	if (result == TEE_SUCCESS) {
		TEE_CloseObject(ppobj);
		disabled_ids &= ~(1U << params[0].value.a);
	}
	return result;

} /* store_passphrase */

static TEE_Result
disable_passphrase (struct session_context *ctx __unused, uint32_t param_types, TEE_Param params[4])
{
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.a > KEYSTORE_MAX_ID) {
		EMSG("Invalid passphrase ID: %u", params[0].value.a);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	disabled_ids |= (1U << params[0].value.a);
	return TEE_SUCCESS;

} /* disable_passphrase */

TEE_Result
TA_OpenSessionEntryPoint (uint32_t param_types __unused,
			  TEE_Param params[4] __unused,
			  void **session_context)
{
	*session_context = TEE_Malloc(sizeof(struct session_context), TEE_MALLOC_FILL_ZERO);
	return (*session_context == NULL ? TEE_ERROR_OUT_OF_MEMORY: TEE_SUCCESS);

} /* TA_OpenSessionEntryPoint */

TEE_Result
TA_InvokeCommandEntryPoint (void *session_context,
			    uint32_t cmd, uint32_t param_types,
			    TEE_Param params[4])
{
	TEE_Result result;
	struct session_context *ctx = session_context;

	if (ctx == NULL)
		return TEE_ERROR_GENERIC;

	switch (cmd) {
	case KEYSTORE_CMD_RETRIEVE:
		result = retrieve_passphrase(ctx, param_types, params);
		break;
	case KEYSTORE_CMD_STORE:
		result = store_passphrase(ctx, param_types, params);
		break;
	case KEYSTORE_CMD_DISABLE:
		result = disable_passphrase(ctx, param_types, params);
		break;
	default:
		result = TEE_ERROR_NOT_SUPPORTED;
	}

	return result;

} /* TA_InvokeCommandEntryPoint */

void
TA_CloseSessionEntryPoint (void *session_context __unused)
{
	if (session_context)
		TEE_Free(session_context);
	return;

} /* TA_CloseSessionEntryPoint */
