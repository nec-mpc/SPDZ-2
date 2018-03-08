
#include "spdz_nec_ext.h"
#include <gmp.h>
#include <memory.h>
#include <string.h>

static const int v_port_order = -1;
static const size_t v_port_size = 8;
static const int v_port_endian = 0;
static const size_t v_port_nails = 0;

void increment_value(const size_t v_size, const u_int8_t * v_in, u_int8_t * v_out)
{
	mpz_t v;
	mpz_init(v);

	mpz_import(v, v_size / 8, v_port_order, v_port_size, v_port_endian, v_port_nails, v_in);
	mpz_add_ui(v, v, 1);
	memset(v_out, 0, v_size);
	mpz_export(v_out, NULL, v_port_order, v_port_size, v_port_endian, v_port_nails, v);

	mpz_clear(v);
}

static const u_int32_t token_key = 0xCAFECAFE;

typedef struct
{
	u_int32_t token;
	int party_id, num_of_parties;
}context_t;

#define VALIDATE_CONTEXT(ctx) if(token_key != ((context_t *)ctx->handle)->token) return -1;

int init(MPC_CTX *ctx, const int party_id, const int num_of_parties,
		 const char * field, const int open_count, const int mult_count,
		 const int bits_count)
{
	context_t * pctx = new context_t;
	pctx->token = token_key;
	pctx->party_id = party_id;
	pctx->num_of_parties = num_of_parties;
	ctx->handle = (u_int64_t)(pctx);
	return 0;
}

int term(MPC_CTX * ctx)
{
	VALIDATE_CONTEXT(ctx);
	context_t * pctx = (context_t *)ctx->handle;
	delete pctx;
	return 0;
}


int skew_bit_decomp(MPC_CTX * ctx, const share_t * rings_in, share_t * bits_out)
{
	VALIDATE_CONTEXT(ctx);

	if(rings_in->count != bits_out->count || rings_in->size != bits_out->size)
		return -1;

	for(size_t i = 0; i < rings_in->count; i++)
		increment_value(rings_in->size, rings_in->data + (i * rings_in->size), bits_out->data + (i * bits_out->size));

	return 0;
}

int skew_ring_comp(MPC_CTX * ctx, const share_t * bits_in, share_t * rings_out)
{
	VALIDATE_CONTEXT(ctx);

	if(bits_in->count != rings_out->count || bits_in->size != rings_out->size)
		return -1;

	for(size_t i = 0; i < bits_in->count; i++)
		increment_value(bits_in->size, bits_in->data + (i * bits_in->size), rings_out->data + (i * rings_out->size));

	return 0;
}

int input_party(MPC_CTX * ctx, int sharing_party_id, clear_t * rings_in, share_t * rings_out)
{
	VALIDATE_CONTEXT(ctx);

	if(rings_in->count != rings_out->count || rings_in->size != rings_out->size)
		return -1;

	for(size_t i = 0; i < rings_in->count; i++)
		increment_value(rings_in->size, rings_in->data + (i * rings_in->size), rings_out->data + (i * rings_out->size));

	return 0;
}

int input_share(MPC_CTX * ctx, clear_t * rings_in, share_t *rings_out)
{
	VALIDATE_CONTEXT(ctx);

	if(rings_in->count != rings_out->count || rings_in->size != rings_out->size)
		return -1;

	for(size_t i = 0; i < rings_in->count; i++)
		increment_value(rings_in->size, rings_in->data + (i * rings_in->size), rings_out->data + (i * rings_out->size));

	return 0;
}

int make_input_from_integer(MPC_CTX * ctx, u_int64_t * integers, int integers_count, clear_t * rings_out)
{
	VALIDATE_CONTEXT(ctx);

	if((int)rings_out->count < integers_count || rings_out->size < sizeof(u_int64_t))
		return -1;

	mpz_t v;
	mpz_init(v);

	for(int i = 0; i < integers_count; i++)
	{
		mpz_set_ui(v, integers[i]);
		memset(rings_out->data + (i * rings_out->size), 0, rings_out->size);
		mpz_export(rings_out->data + (i * rings_out->size), NULL, v_port_order, v_port_size, v_port_endian, v_port_nails, v);
	}

	mpz_clear(v);
	return 0;
}

int make_input_from_fixed(MPC_CTX * ctx, const char * fix_strs[], int fix_count, clear_t * rings_out)
{
	int result = -1;
	u_int64_t * pints = new u_int64_t[fix_count];

	for(int i = 0; i < fix_count; i++)
		pints[i] = (u_int64_t)strtod(fix_strs[i], NULL);

	result = make_input_from_integer(ctx, pints, fix_count, rings_out);

	delete pints;
	return result;
}

int start_open(MPC_CTX * ctx, const share_t * rings_in, clear_t * rings_out)
{
	VALIDATE_CONTEXT(ctx);

	if(rings_in->count != rings_out->count || rings_in->size != rings_out->size)
		return -1;

	for(size_t i = 0; i < rings_in->count; i++)
		increment_value(rings_in->size, rings_in->data + (i * rings_in->size), rings_out->data + (i * rings_out->size));

	return 0;
}

int stop_open(MPC_CTX * ctx)
{
	VALIDATE_CONTEXT(ctx);
	return 0;
}

int make_integer_output(MPC_CTX * ctx, const share_t * rings_in, u_int64_t * integers, int * integers_count)
{
	VALIDATE_CONTEXT(ctx);

	if((int)rings_in->count != *integers_count || rings_in->size > sizeof(u_int64_t))
		return -1;

	mpz_t v;
	mpz_init(v);

	for(size_t i = 0; i < rings_in->count; i++)
	{
		mpz_import(v, rings_in->size / 8, v_port_order, v_port_size, v_port_endian, v_port_nails, rings_in->data + (i * rings_in->size));
		integers[i] = mpz_get_ui(v);
	}

	mpz_clear(v);
	return 0;
}

int make_fixed_output(MPC_CTX * ctx, const share_t * rings_in, char * fix_strs[], int * fixed_count)
{
	int result = -1;
	u_int64_t * pints = new u_int64_t[*fixed_count];

	result = make_integer_output(ctx, rings_in, pints, fixed_count);

	for(int i = 0; i < *fixed_count; i++)
		snprintf(fix_strs[i], 128, "%lu", pints[i]);

	delete pints;
	return result;
}

int verify_optional_suggest(MPC_CTX * ctx, int * error)
{
	VALIDATE_CONTEXT(ctx);
	*error = 1;
	return 0;
}

int verify_final(MPC_CTX * ctx, int * error)
{
	VALIDATE_CONTEXT(ctx);
	*error = 1;
	return 0;
}

int start_mult(MPC_CTX * ctx, const share_t * factor1, const share_t * factor2, share_t * product)
{
	VALIDATE_CONTEXT(ctx);

	if(factor1->count != factor2->count || factor1->count != product->count)
		return -1;
	if(factor1->size != factor2->size || factor1->size != product->size)
		return -1;

	mpz_t v1, v2, p;
	mpz_init(v1);
	mpz_init(v2);
	mpz_init(p);

	for(size_t i = 0; i < factor1->count; i++)
	{
		mpz_import(v1, factor1->size / 8, v_port_order, v_port_size, v_port_endian, v_port_nails, factor1->data + (i * factor1->size));
		mpz_import(v2, factor2->size / 8, v_port_order, v_port_size, v_port_endian, v_port_nails, factor2->data + (i * factor2->size));
		mpz_mul (p, v1, v2);
		memset(product->data + (i * product->size), 0, product->size);
		mpz_export(product->data + (i * product->size), NULL, v_port_order, v_port_size, v_port_endian, v_port_nails, p);
	}

	mpz_clear(v1);
	mpz_clear(v2);
	mpz_clear(p);

	return 0;
}

int stop_mult(MPC_CTX * ctx)
{
	VALIDATE_CONTEXT(ctx);
	return 0;
}
