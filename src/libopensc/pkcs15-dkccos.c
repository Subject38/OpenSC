/*
 * PKCS#15 emulation for DKCCOS token objects.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Objects contain little-endian attribute records: uint32 type, uint16 length,
 * followed by the value. Vendor attribute 0x80000008 associates a certificate
 * with its key objects; 0x80000001 references private-key storage.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "internal.h"
#include "pkcs15.h"
#include "pkcs15-syn.h"
#include "common/compat_strlcpy.h"

#define DK_MAX_ATTRS 64
#define DK_MAX_OBJECT_SIZE 16384
#define DK_ATTR_CLASS 0x00000000U
#define DK_ATTR_LABEL 0x00000003U
#define DK_ATTR_VALUE 0x00000011U
#define DK_ATTR_KEY_TYPE 0x00000100U
#define DK_ATTR_ID 0x00000102U
#define DK_ATTR_MODULUS 0x00000120U
#define DK_ATTR_PRIVATE_FILE 0x80000001U
#define DK_ATTR_OBJECT_ID 0x80000008U

struct dk_attr {
	uint32_t type;
	const u8 *value;
	size_t length, offset;
};
struct dk_attrs {
	struct dk_attr items[DK_MAX_ATTRS];
	size_t count;
};

static uint32_t dk_le32(const u8 *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
		(uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int dk_parse(const u8 *buf, size_t len, struct dk_attrs *attrs)
{
	size_t off = 0, i;
	attrs->count = 0;
	while (off < len) {
		struct dk_attr *a;
		if (len - off < 6 || attrs->count == DK_MAX_ATTRS)
			return SC_ERROR_INVALID_DATA;
		a = &attrs->items[attrs->count];
		a->type = dk_le32(buf + off);
		a->length = buf[off + 4] | (size_t)buf[off + 5] << 8;
		off += 6;
		if (a->length > len - off)
			return SC_ERROR_INVALID_DATA;
		for (i = 0; i < attrs->count; i++)
			if (attrs->items[i].type == a->type)
				return SC_ERROR_INVALID_DATA;
		a->value = buf + off;
		a->offset = off;
		off += a->length;
		attrs->count++;
	}
	return SC_SUCCESS;
}

static const struct dk_attr *dk_find(const struct dk_attrs *attrs, uint32_t type)
{
	size_t i;
	for (i = 0; i < attrs->count; i++)
		if (attrs->items[i].type == type)
			return &attrs->items[i];
	return NULL;
}

static int dk_bool(const struct dk_attrs *attrs, uint32_t type)
{
	const struct dk_attr *a = dk_find(attrs, type);
	return a && a->length == 1 && a->value[0] != 0;
}

static void dk_path(unsigned int fid, struct sc_path *path)
{
	char text[9];
	snprintf(text, sizeof(text), "3F00%04X", fid);
	sc_format_path(text, path);
}

static int dk_read(sc_card_t *card, const struct sc_path *path, u8 *buf, size_t cap)
{
	sc_file_t *file = NULL;
	size_t size, done = 0;
	int r = sc_select_file(card, path, &file);
	if (r < 0)
		return r;
	size = file->size;
	sc_file_free(file);
	if (size > cap)
		return SC_ERROR_BUFFER_TOO_SMALL;
	while (done < size) {
		r = sc_read_binary(card, (unsigned int)done, buf + done, size - done, 0);
		if (r < 0)
			return r;
		if (r == 0)
			break; /* Some token EFs report a size one byte beyond their data. */
		if ((size_t)r > size - done)
			return SC_ERROR_INVALID_DATA;
		done += r;
	}
	return (int)done;
}

static int dk_identity(const struct dk_attrs *attrs, struct sc_pkcs15_object *obj,
		struct sc_pkcs15_id *id)
{
	const struct dk_attr *a = dk_find(attrs, DK_ATTR_OBJECT_ID);
	const struct dk_attr *label = dk_find(attrs, DK_ATTR_LABEL);
	if (!a)
		a = dk_find(attrs, DK_ATTR_ID);
	if (!a || !a->length || a->length > sizeof(id->value))
		return SC_ERROR_INVALID_DATA;
	memcpy(id->value, a->value, a->length);
	id->len = a->length;
	if (!label)
		label = a;
	size_t n = MIN(label->length, sizeof(obj->label) - 1);
	memcpy(obj->label, label->value, n);
	obj->label[n] = '\0';
	return SC_SUCCESS;
}

static int dk_have_private(sc_pkcs15_card_t *p15card, const struct sc_pkcs15_id *id)
{
	struct sc_pkcs15_object *obj;
	for (obj = p15card->obj_list; obj; obj = obj->next) {
		if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA &&
				sc_pkcs15_compare_id(id, &((struct sc_pkcs15_prkey_info *)obj->data)->id))
			return 1;
	}
	return 0;
}

static int dk_private(sc_pkcs15_card_t *p15card, const struct dk_attrs *attrs)
{
	struct sc_pkcs15_prkey_info info = {0};
	struct sc_pkcs15_object obj = {0};
	const struct dk_attr *keytype = dk_find(attrs, DK_ATTR_KEY_TYPE);
	const struct dk_attr *modulus = dk_find(attrs, DK_ATTR_MODULUS);
	const struct dk_attr *file = dk_find(attrs, DK_ATTR_PRIVATE_FILE);
	int r;
	if (!keytype || keytype->length != 4 || dk_le32(keytype->value) != 0)
		return SC_ERROR_NOT_SUPPORTED;
	if (!modulus || !modulus->length || !file || file->length != 2)
		return SC_ERROR_INVALID_DATA;
	r = dk_identity(attrs, &obj, &info.id);
	if (r < 0 || dk_have_private(p15card, &info.id))
		return r;
	/* These flags are actual PKCS#11 attributes in the token metadata. */
	if (dk_bool(attrs, 0x105)) info.usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
	if (dk_bool(attrs, 0x108)) info.usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
	if (dk_bool(attrs, 0x109)) info.usage |= SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	if (dk_bool(attrs, 0x107)) info.usage |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
	info.modulus_length = modulus->length * 8;
	info.native = 1;
	info.key_reference = -1;
	dk_path(file->value[0] | (unsigned int)file->value[1] << 8, &info.path);
	obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	sc_pkcs15_format_id("01", &obj.auth_id);
	return sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
}

static int dk_certificate(sc_pkcs15_card_t *p15card, const struct dk_attrs *attrs,
		const struct sc_path *path)
{
	struct sc_pkcs15_cert_info info = {0};
	struct sc_pkcs15_pubkey_info pubinfo = {0};
	struct sc_pkcs15_object obj = {0};
	struct sc_pkcs15_cert *cert = NULL;
	const struct dk_attr *value = dk_find(attrs, DK_ATTR_VALUE);
	int r;
	if (!value || !value->length)
		return SC_ERROR_INVALID_DATA;
	r = dk_identity(attrs, &obj, &info.id);
	if (r < 0)
		return r;
	info.path = *path;
	info.path.index = (int)value->offset;
	info.path.count = (int)value->length;
	/* The object scan already read the complete certificate attribute. */
	info.value.value = malloc(value->length);
	if (!info.value.value)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(info.value.value, value->value, value->length);
	info.value.len = value->length;
	r = sc_pkcs15_read_certificate(p15card, &info, 0, &cert);
	if (r < 0) {
		free(info.value.value);
		return r;
	}
	r = sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
	if (r < 0) {
		free(info.value.value);
		goto done;
	}
	if (!cert->key || cert->key->algorithm != SC_ALGORITHM_RSA)
		goto done;
	pubinfo.id = info.id;
	pubinfo.modulus_length = cert->key->u.rsa.modulus.len * 8;
	pubinfo.usage = SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_ENCRYPT;
	r = sc_pkcs15_encode_pubkey_as_spki(p15card->card->ctx, cert->key,
			&pubinfo.direct.spki.value, &pubinfo.direct.spki.len);
	if (r < 0)
		goto done;
	r = sc_pkcs15emu_add_rsa_pubkey(p15card, &obj, &pubinfo);
	if (r < 0)
		free(pubinfo.direct.spki.value);
done:
	sc_pkcs15_free_certificate(cert);
	return r;
}

static int dk_scan(sc_pkcs15_card_t *p15card)
{
	u8 ids[1024], buf[DK_MAX_OBJECT_SIZE];
	struct sc_path root, path;
	int count, i, r;
	sc_format_path("3F00", &root);
	r = sc_select_file(p15card->card, &root, NULL);
	if (r < 0)
		return r;
	count = sc_list_files(p15card->card, ids, sizeof(ids));
	if (count < 0)
		return count;
	if (count > (int)sizeof(ids) || (count & 1))
		return SC_ERROR_INVALID_DATA;
	for (i = 0; i < count; i += 2) {
		sc_file_t *file = NULL;
		struct dk_attrs attrs;
		const struct dk_attr *class;
		dk_path(ids[i] << 8 | ids[i + 1], &path);
		r = sc_select_file(p15card->card, &path, &file);
		if (r < 0)
			continue; /* Special PIN/system files cannot be selected this way. */
		int metadata = file->type == SC_FILE_TYPE_WORKING_EF &&
			file->ef_structure == SC_FILE_EF_TRANSPARENT && file->size <= sizeof(buf);
		sc_file_free(file);
		if (!metadata)
			continue;
		sc_log(p15card->card->ctx, "DKCCOS scanning object %s", sc_print_path(&path));
		r = dk_read(p15card->card, &path, buf, sizeof(buf));
		if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
			r = sc_pkcs15_add_df(p15card, SC_PKCS15_PRKDF, &path);
			if (r < 0)
				return r;
			continue;
		}
		if (r < 0)
			return r;
		if (dk_parse(buf, (size_t)r, &attrs) < 0) {
			sc_log(p15card->card->ctx, "DKCCOS object is not attribute metadata (%d bytes)", r);
			continue;
		} /* Working EFs also contain ordinary token data. */
		class = dk_find(&attrs, DK_ATTR_CLASS);
		if (!class || class->length != 4)
			continue;
		sc_log(p15card->card->ctx, "DKCCOS object class %lu", (unsigned long)dk_le32(class->value));
		if (dk_le32(class->value) == 1)
			r = dk_certificate(p15card, &attrs, &path);
		else if (dk_le32(class->value) == 3)
			r = dk_private(p15card, &attrs);
		else
			continue;
		if (r < 0)
			return r;
	}
	return SC_SUCCESS;
}

static int dk_parse_df(sc_pkcs15_card_t *p15card, struct sc_pkcs15_df *df)
{
	u8 buf[DK_MAX_OBJECT_SIZE];
	struct dk_attrs attrs;
	const struct dk_attr *class;
	int r;
	if (df->enumerated)
		return SC_SUCCESS;
	if (df->type != SC_PKCS15_PRKDF)
		return SC_ERROR_NOT_SUPPORTED;
	r = dk_read(p15card->card, &df->path, buf, sizeof(buf));
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		return SC_SUCCESS; /* Retry this EF after a successful login. */
	if (r < 0)
		return r;
	r = dk_parse(buf, (size_t)r, &attrs);
	if (r < 0)
		return r;
	class = dk_find(&attrs, DK_ATTR_CLASS);
	if (class && class->length == 4 && dk_le32(class->value) == 3) {
		r = dk_private(p15card, &attrs);
		if (r < 0)
			return r;
	}
	df->enumerated = 1;
	return SC_SUCCESS;
}

int sc_pkcs15emu_dkccos_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	struct sc_path path;
	struct sc_pkcs15_auth_info pin = {0};
	struct sc_pkcs15_object obj = {0};
	u8 buf[128];
	char serial[9], label[33];
	int r;
	(void)aid;
	if (p15card->card->type != SC_CARD_TYPE_DKCCOS_V6_0)
		return SC_ERROR_WRONG_CARD;
	dk_path(6, &path);
	r = dk_read(p15card->card, &path, buf, sizeof(buf));
	if (r < 8)
		return r < 0 ? r : SC_ERROR_INVALID_DATA;
	memcpy(serial, buf, 8);
	serial[8] = '\0'; /* PKCS#11 pads this with spaces to sixteen bytes. */
	dk_path(0x0a, &path);
	r = dk_read(p15card->card, &path, buf, sizeof(buf));
	if (r < 0)
		return r;
	size_t n = MIN((size_t)r, sizeof(label) - 1);
	memcpy(label, buf, n);
	label[n] = '\0';
	set_string(&p15card->tokeninfo->label, label);
	set_string(&p15card->tokeninfo->serial_number, serial);
	set_string(&p15card->tokeninfo->manufacturer_id, "Rainbow Technologies");
	if (!p15card->tokeninfo->label || !p15card->tokeninfo->serial_number ||
			!p15card->tokeninfo->manufacturer_id)
		return SC_ERROR_OUT_OF_MEMORY;
	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY | SC_PKCS15_TOKEN_PRN_GENERATION;

	strlcpy(obj.label, "User PIN", sizeof(obj.label));
	sc_pkcs15_format_id("01", &pin.auth_id);
	pin.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin.attrs.pin.reference = 1; /* Successful Windows VERIFY: 00 20 01 00 14. */
	pin.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin.attrs.pin.min_length = 16;
	pin.attrs.pin.max_length = pin.attrs.pin.stored_length = 20;
	pin.attrs.pin.pad_char = ' ';
	pin.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
	pin.tries_left = -1;
	pin.logged_in = SC_PIN_STATE_UNKNOWN;
	sc_format_path("3F00", &pin.path);
	r = sc_pkcs15emu_add_pin_obj(p15card, &obj, &pin);
	if (r < 0)
		goto fail;
	p15card->ops.parse_df = dk_parse_df;
	r = dk_scan(p15card);
	if (r < 0)
		goto fail;
	return SC_SUCCESS;
fail:
	sc_pkcs15_card_clear(p15card);
	return r;
}
