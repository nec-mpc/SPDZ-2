
#ifndef SPDZ_NEC_EXT_H_
#define SPDZ_NEC_EXT_H_

#include <stdlib.h>

extern "C"
{
	typedef struct
	{
		u_int64_t handle;
		// may hold other data
	} MPC_CTX;

	typedef struct{
		u_int8_t * data;
		size_t size, count, md_ring_size;
	}share_t;

	typedef share_t clear_t;

	int init(MPC_CTX *ctx, const int party_id, const int num_of_parties,
			 const char * field, const int open_count, const int mult_count,
			 const int bits_count);
    int term(MPC_CTX *ctx);

    int skew_bit_decomp(MPC_CTX * ctx, const share_t * rings_in, share_t * bits_out);
    int skew_ring_comp(MPC_CTX * ctx, const share_t * bits_in, share_t * rings_out);
    int input_party(MPC_CTX * ctx, int sharing_party_id, clear_t * rings_in, share_t * rings_out);
    int input_share(MPC_CTX * ctx, clear_t * rings_in, share_t *rings_out);
    int make_input_from_integer(MPC_CTX * ctx, u_int64_t * integers, int integers_count, clear_t * rings_out);
    int make_input_from_fixed(MPC_CTX * ctx, const char * fix_strs[], int fix_count, clear_t * rings_out);
    int start_open(MPC_CTX * ctx, const share_t * rings_in, clear_t * rings_out);
    int stop_open(MPC_CTX * ctx);
    int make_integer_output(MPC_CTX * ctx, const share_t * rings_in, u_int64_t * integers, int * integers_count);
    int make_fixed_output(MPC_CTX * ctx, const share_t * rings_in, char * fix_strs[], int * fixed_count);
    int verify_optional_suggest(MPC_CTX * ctx, int * error);
    int verify_final(MPC_CTX * ctx, int * error);
    int start_mult(MPC_CTX * ctx, const share_t * factor1, const share_t * factor2, share_t * product);
    int stop_mult(MPC_CTX * ctx);

}

#endif /* SPDZ_NEC_EXT_H_ */
