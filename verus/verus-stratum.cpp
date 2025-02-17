/**
 * verushash specific stratum protocol
 * tpruvot@github - 2017 - Part under GPLv3 Licence
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <cmath>
extern "C" {
#include <miner.h>
}

#define EQNONCE_OFFSET 30 /* 27:34 */

extern struct stratum_ctx stratum;
extern "C" {
//FIXME: is g_work_lock the same as stratum_work_lock?
extern pthread_mutex_t g_work_lock;
}

double target_to_diff_verus(uint32_t target){
    const unsigned exponent_diff = 8 * (0x20 - ((target >> 24) & 0xFF));
    const double significand = target & 0xFFFFFF;
    return std::ldexp(0x0f0f0f / significand, exponent_diff);
}

void diff_to_target_verus(uint32_t *target, double diff)
{
	uint64_t m;
	int k;

	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = (uint64_t)(4294901760.0 / diff);
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k + 1] = (uint32_t)(m >> 8);
		target[k + 2] = (uint32_t)(m >> 40);
		//memset(target, 0xff, 6*sizeof(uint32_t));
		for (k = 0; k < 28 && ((uint8_t*)target)[k] == 0; k++)
			((uint8_t*)target)[k] = 0xff;
	}
}
double verus_network_diff(struct work *work)
{
    uint32_t nbits = work->data[26];
    double d = target_to_diff_verus(nbits);
    // applog(LOG_BLUE, "target nbits: %08x", nbits);
    // applog(LOG_BLUE, "target diff: %f", d);
    return d;
}

void verus_work_set_target(struct work* work, double diff)
{
	// target is given as data by the equihash stratum
	// memcpy(work->target, stratum.job.claim, 32); // claim field is only used for lbry
	// diff_to_target_equi(work->target, diff); // we already set the target
	work->targetdiff = diff;
	// applog(LOG_BLUE, "diff %f to target :", diff);
	// applog_hex(work->target, 32);
}

bool verus_stratum_set_target(struct stratum_ctx *sctx, json_t *params)
{
	uint8_t target_bin[32], target_be[32];

	const char *target_hex = json_string_value(json_array_get(params, 0));
	if (!target_hex || strlen(target_hex) == 0)
		return false;

	hex2bin(target_bin, target_hex, 32);
	memset(target_be, 0x00, 32);

	uint8_t *bits_start = nullptr;
	int filled = 0;
	for (int i = 0; i < 32; i++)
	{
		if (filled == 8) break;
		target_be[31 - i] = target_bin[i];
		if (target_bin[i])
		{
			filled++;
			if(bits_start == nullptr)
				bits_start = &target_bin[i];
		}
	}

	int padding = &target_bin[31] - bits_start;

	uint32_t target_bits;
	uint8_t exponent = ((padding * 8 + 1) + 7) / 8;

	memcpy(&target_bits, &target_be[exponent - 3], 3);  // coefficient
	target_bits |= (exponent << 24);     				// exponent

	// applog_hex(target_bin, 32);
	// applog_hex(target_be, 32);
	// applog(LOG_BLUE, "target_bits %08x", target_bits);

	memcpy(sctx->job.extra, target_be, 32);

	pthread_mutex_lock(&g_work_lock);
	// sctx->next_diff = target_to_diff_equi((uint32_t*) &target_be);
	sctx->next_diff = target_to_diff_verus(target_bits);
	pthread_mutex_unlock(&g_work_lock);

	//applog(LOG_BLUE, "low diff %f", sctx->next_diff);
	//applog_hex(target_be, 32);

	return true;
}

bool verus_stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *version, *prevhash, *coinb1, *coinb2, *nbits, *stime, *solution = NULL;
	size_t coinb1_size, coinb2_size;
	bool clean, ret = false;
	int ntime, i, p=0;
	job_id = json_string_value(json_array_get(params, p++));
	version = json_string_value(json_array_get(params, p++));
	prevhash = json_string_value(json_array_get(params, p++));
	coinb1 = json_string_value(json_array_get(params, p++)); //merkle
	coinb2 = json_string_value(json_array_get(params, p++)); //blank (reserved)
	stime = json_string_value(json_array_get(params, p++));
	nbits = json_string_value(json_array_get(params, p++));
	clean = json_is_true(json_array_get(params, p)); p++;
	solution = json_string_value(json_array_get(params, p++));

	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime ||
	    strlen(prevhash) != 64 || strlen(version) != 8 ||
	    strlen(coinb1) != 64 || strlen(coinb2) != 64 ||
	    strlen(nbits) != 8 || strlen(stime) != 8) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}

	/* store stratum server time diff */
	hex2bin((uchar *)&ntime, stime, 4);
	ntime = ntime - (int) time(0);
	if (ntime > sctx->srvtime_diff) {
		sctx->srvtime_diff = ntime;
		if (opt_protocol && ntime > 20)
			applog(LOG_DEBUG, "stratum time is at least %ds in the future", ntime);
	}

	pthread_mutex_lock(&g_work_lock);
	hex2bin(sctx->job.version, version, 4);
	hex2bin(sctx->job.prevhash, prevhash, 32);

	coinb1_size = strlen(coinb1) / 2;
	coinb2_size = strlen(coinb2) / 2;
	sctx->job.coinbase_size = coinb1_size + coinb2_size + // merkle + reserved
		sctx->xnonce1_size + sctx->xnonce2_size; // extranonce and...

	sctx->job.coinbase = (uchar*) realloc(sctx->job.coinbase, sctx->job.coinbase_size);
	hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
	hex2bin(sctx->job.coinbase + coinb1_size, coinb2, coinb2_size);

	sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + coinb2_size + sctx->xnonce1_size;
	if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
		memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
	memcpy(sctx->job.coinbase + coinb1_size + coinb2_size, sctx->xnonce1, sctx->xnonce1_size);

	for (i = 0; i < sctx->job.merkle_count; i++)
		free(sctx->job.merkle[i]);
	free(sctx->job.merkle);
	sctx->job.merkle = NULL;
	sctx->job.merkle_count = 0;

	free(sctx->job.job_id);
	//applog(LOG_WARNING, "stratum time is at least %ss in the future", job_id);

	sctx->job.job_id = strdup(job_id);

	hex2bin(sctx->job.nbits, nbits, 4);
	hex2bin(sctx->job.ntime, stime, 4);
	hex2bin(sctx->job.solution, solution, 1344);

	sctx->job.clean = clean;

	sctx->job.diff = sctx->next_diff;
	pthread_mutex_unlock(&g_work_lock);

	ret = true;

out:
	return ret;
}

// verushash stratum protocol is not standard, use client.show_message to pass block height
bool verus_stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	val = json_array_get(params, 0);
	if (val) {
		const char* data = json_string_value(val);
		if (data && strlen(data)) {
			char symbol[32] = { 0 };
			uint32_t height = 0;
			int ss = sscanf(data, "verushash %s block %u", symbol, &height);
			//TODO: Fixme?
			//if (height && ss > 1) sctx->job.height = height;
		}
	}

	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

#define JSON_SUBMIT_BUF_LEN (20*1024)
// called by submit_upstream_work()
bool verus_stratum_submit(const char * rpc_user, struct work *work)
{
	char _ALIGN(64) s[JSON_SUBMIT_BUF_LEN];
	char _ALIGN(64) timehex[16] = { 0 };
	char *jobid, *noncestr, *solhex;
	//TODO: Fixme?
	//int idnonce = work->submit_nonce_id;

	// scanned nonce
	//TODO: Fixme?
	//work->data[EQNONCE_OFFSET] = work->nonces[idnonce];
	//work->data[EQNONCE_OFFSET] = work->nonces;
	unsigned char * nonce = (unsigned char*) (&work->data[27]);
	size_t nonce_len = 32 - stratum.xnonce1_size;
	// long nonce without pool prefix (extranonce)
	noncestr = (char*)malloc((nonce_len * 2) + 1);
	solhex = (char*) calloc(1, 1344*2 + 64);
	char* solHexRestore = (char*) calloc(128, 1);
	if (!solhex || !noncestr) {
		applog(LOG_ERR, "unable to alloc share memory");
		return false;
	}
	bin2hex(noncestr, &nonce[stratum.xnonce1_size], nonce_len);
	bin2hex(solhex, work->extra, 1347);

	bin2hex(solHexRestore, &work->solution[8], 64);
	memcpy(&solhex[6+16], solHexRestore, 128);

	//TODO: Fixme?
	jobid = work->job_id;
	//jobid = work->job_id + 8;

	sprintf(timehex, "%08x", swab32(work->data[25]));

	snprintf(s, sizeof(s), "{\"method\":\"mining.submit\",\"params\":"
		"[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"], \"id\":%u}",
		rpc_user, jobid, timehex, noncestr, solhex,
		stratum.job.shares_count + 10);

	free(solhex);
	free(noncestr);
	free(solHexRestore);

	//TODO: Fixme?
	//gettimeofday(&stratum.tv_submit, NULL);

	if(!stratum_send_line(&stratum, s)) {
		applog(LOG_ERR, "%s stratum_send_line failed", __func__);
		return false;
	}

	//TODO: Fixme?
	//stratum.sharediff = work->sharediff[idnonce];
	stratum.sharediff = work->sharediff;
	stratum.job.shares_count++;

	return true;
}
