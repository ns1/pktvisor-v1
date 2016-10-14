/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <maxminddb.h>
#include <netinet/in.h>

#include "built_in.h"
#include "die.h"
#include "ioops.h"
#include "str.h"
#include "xmalloc.h"

#define LOC_BUF_LEN 80
#define GEO_OK(r) ((r) == MMDB_SUCCESS)
#define GEO_ERROR(r) ((r) != MMDB_SUCCESS)

static MMDB_s mmdb_city;
static bool has_city = false;

static MMDB_s mmdb_isp;
static bool has_isp = false;

int geoip_working(void)
{
	return (has_city && has_isp);
}

/**
 * Lookup data and fill the given result struct.
 */
static int lookup_entry_data_va(MMDB_s *db, struct sockaddr *sa, MMDB_entry_data_s *result, va_list path) 
{
	int mmdb_error;
	MMDB_lookup_result_s lookup_result = MMDB_lookup_sockaddr(db, sa, &mmdb_error);

	if (GEO_ERROR(mmdb_error)) {
		return mmdb_error;
	} else if (!lookup_result.found_entry) {
		return MMDB_INVALID_LOOKUP_PATH_ERROR;
	}

	mmdb_error = MMDB_vget_value(&lookup_result.entry, result, path);
	if (GEO_ERROR(mmdb_error)) {
		return mmdb_error;
	} else {
		return MMDB_SUCCESS;
	}
}

/**
 * Variadic version of data lookup.
 */
static int lookup_entry_data(MMDB_s *db, struct sockaddr *sa, MMDB_entry_data_s *result, ...)
{
	va_list path;
	va_start(path, result);
	return lookup_entry_data_va(db, sa, result, path);
}

/**
 * Lookup a single string from the given path, returning NULL if not found (or errors).
 */
static char *lookup_string(MMDB_s *db, struct sockaddr *sa, ...)
{
	va_list path;
	va_start(path, sa);

	MMDB_entry_data_s entry_data;
	int status = lookup_entry_data_va(db, sa, &entry_data, path);
	if (GEO_OK(status) && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
		return strndup(entry_data.utf8_string, entry_data.data_size);
	} else {
		return NULL;
	}
}

/**
 * Lookup an ASN + Organization label.  This must be synthesized because GeoIP2 stores the AS num
 * and the org string separately.
 */
static char *lookup_as_label(struct sockaddr *sa)
{

	MMDB_entry_data_s entry_data;
	int status = lookup_entry_data(&mmdb_isp, sa, &entry_data, "autonomous_system_number", NULL);
	if (GEO_ERROR(status) || !entry_data.has_data) {
		entry_data.type = UINT32_MAX;
	}

	char *actual_org_name = lookup_string(&mmdb_isp, sa, "autonomous_system_organization", NULL);
	char *name = actual_org_name ? actual_org_name : "Unknown";

	char *buf = malloc(LOC_BUF_LEN);
	switch (entry_data.type) {
		case MMDB_DATA_TYPE_UINT16:
			snprintf(buf, LOC_BUF_LEN, "AS%d %s", entry_data.uint16, name);
		break;
		case MMDB_DATA_TYPE_UINT32:
			snprintf(buf, LOC_BUF_LEN, "AS%d %s", entry_data.uint32, name);
		break;
		case MMDB_DATA_TYPE_UINT64:
			snprintf(buf, LOC_BUF_LEN, "AS%lu %s", entry_data.uint64, name);
		break;
		case MMDB_DATA_TYPE_INT32:
			snprintf(buf, LOC_BUF_LEN, "AS%d %s", entry_data.int32, name);
		break;
		default:
			snprintf(buf, LOC_BUF_LEN, "AS0 %s", name);
		break;
    }

	if (actual_org_name) {
		free(actual_org_name);
	}

	return buf;
}

const char *geoip4_as_name_by_ip(uint32_t ip)
{
	bug_on(!has_isp);

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = 1;
	sa.sin_addr.s_addr = ip;  // calling conventions assume this is already in network form.

	return lookup_as_label((struct sockaddr *) &sa);
}

const char *geoip4_as_name(struct sockaddr_in *sa)
{
	bug_on(!has_isp);

	return lookup_as_label((struct sockaddr *) sa);
}

const char *geoip6_as_name(struct sockaddr_in6 *sa)
{
	bug_on(!has_isp);

	return lookup_as_label((struct sockaddr *) sa);
}

static float lookup_lat_or_lon(struct sockaddr *sa, char *lat_or_lon)
{
	MMDB_entry_data_s entry_data;
	int status = lookup_entry_data(&mmdb_city, (struct sockaddr *) sa, &entry_data, "location", lat_or_lon, NULL);
	if (GEO_ERROR(status) || !entry_data.has_data) {
		return .0f;
	} else {
		switch (entry_data.type) {
			case MMDB_DATA_TYPE_FLOAT:
				return entry_data.float_value;
			case MMDB_DATA_TYPE_DOUBLE:
				// Cast away double-ness because the existing geoip API can't handle it anyway.
				return (float) entry_data.double_value;
			default:
				return .0f;
		}
	}
}

float geoip4_longitude(struct sockaddr_in *sa)
{
	return lookup_lat_or_lon((struct sockaddr *) sa, "longitude");
}

float geoip4_latitude(struct sockaddr_in *sa)
{
	return lookup_lat_or_lon((struct sockaddr *) sa, "latitude");
}

float geoip6_longitude(struct sockaddr_in6 *sa)
{
	return lookup_lat_or_lon((struct sockaddr *) sa, "longitude");
}

float geoip6_latitude(struct sockaddr_in6 *sa)
{
	return lookup_lat_or_lon((struct sockaddr *) sa, "latitude");
}

const char *geoip4_city_name(struct sockaddr_in *sa)
{
	return lookup_string(&mmdb_city, (struct sockaddr *) sa, "city", "names", "en", NULL);
}

const char *geoip6_city_name(struct sockaddr_in6 *sa)
{
	return lookup_string(&mmdb_city, (struct sockaddr *) sa, "city", "names", "en", NULL);
}

const char *geoip4_region_name(struct sockaddr_in *sa)
{
	// This will return an ISO code like the previous version did.  Alternative would be:
	// "continent", "names", "en" or "continent", "code".
	return lookup_string(&mmdb_city, (struct sockaddr *) sa, "subdivisions", "0", "iso_code", NULL);
}

const char *geoip6_region_name(struct sockaddr_in6 *sa)
{
	return lookup_string(&mmdb_city, (struct sockaddr *) sa, "subdivisions", "0", "iso_code", NULL);
}

const char *geoip4_country_name(struct sockaddr_in *sa)
{
	char *name = lookup_string(&mmdb_city, (struct sockaddr *) sa, "country", "names", "en", NULL);
	if (!name) {
		name = lookup_string(&mmdb_city, (struct sockaddr *) sa, "country", "iso_code", NULL);
	}

	return name;
}

const char *geoip6_country_name(struct sockaddr_in6 *sa)
{
	char *name = lookup_string(&mmdb_city, (struct sockaddr *) sa, "country", "names", "en", NULL);
	if (!name) {
		name = lookup_string(&mmdb_city, (struct sockaddr *) sa, "country", "iso_code", NULL);
	}

	return name;
}

char *geoip4_loc_by_ip(uint32_t ip)
{
	bug_on(!has_city);

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = 1;
	sa.sin_addr.s_addr = ip;

	char *country = lookup_string(&mmdb_city, (struct sockaddr *) &sa, "country", "iso_code", NULL);
	const char *region = geoip4_region_name(&sa);

	char *buf = malloc(LOC_BUF_LEN);
	snprintf(buf, LOC_BUF_LEN, "%s/%s",
		(country ? country : "Unknown"),
		(region ? region : "Unknown"));

	if (country) {
		free(country);
	}

	if (region) {
		free((char *)region);
	}

	return buf;
}

void init_geoip(const char *citydb, const char *asndb)
{
	int result;

	if (citydb) {
		result = MMDB_open(citydb, MMDB_MODE_MMAP, &mmdb_city);
		bug_on(result != MMDB_SUCCESS);
		has_city = true;
	}

	if (asndb) {
		result = MMDB_open(asndb, MMDB_MODE_MMAP, &mmdb_isp);
		bug_on(result != MMDB_SUCCESS);
		has_isp = true;
	}
}

void destroy_geoip(void)
{
	if (has_city) {
		MMDB_close(&mmdb_city);
		has_city = false;
	}

	if (has_isp) {
		MMDB_close(&mmdb_isp);
		has_isp = false;
	}
}

