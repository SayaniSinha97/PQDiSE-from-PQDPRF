#include <dEnc/Defines.h>
#include "cryptoTools/Crypto/RandomOracle.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/SmartPtr.h>
#include <map>

namespace dEnc{

	/* calculates combinatorial value nCr */
	u64 ncr(u64 n, u64 r);

	/* This function calculates x modulo q */
	inline u64 moduloL(u64 x, u64 q){
		if(x >= 0){
			return x%q;
		}
		else{
			x = (-x)%q;
			return (x ? (q-x) : x);
		}
	};

	/* This function rounds an integer in modulo q to an integer in modulo p. Basically for x in Z_q the function maps
	it to the nearest integer of (x*p/q) */
	inline u64 round_toL(u64 x, u64 q, u64 p){
		x >>= (int)(log2(q) - log2(p) - 1);
		int flag = (x & 1) ? 1 : 0;
		x >>= 1;
		return (x + flag);
	};

	/* This function calculates multiplication (a * b) modulo q */
	u64 moduloMultiplication(u64 a, u64 b, u64 q);

	/* This function performs vector dot product modulo q */
	u64 modular_dot_productL(u64 a[], u64 b[], u64 n, u64 q);

	/* Given a group_id, find the party_ids present in (group_id)^th combination out of TCt combinations */
	void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T);

	/* Given a t-sized list of party-ids compute its rank among total TCt combinations */
	u64 findGroupId(std::vector<u64> parties, u64 t, u64 T);

	block decimal_array_to_single_block(std::vector<u16> arr);
	void convert_block_to_extended_lwr_input(block x, std::vector<NTL::vec_ZZ_p>* y);

	/* the partial evaluation function of LWR-based DPRF */
	void part_eval(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1);
	void part_eval_single(std::vector<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1);

	/* the direct evaluation function of LWR-based PRF */
	void direct_eval(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, u64 q, u64 p);
	void direct_eval_single(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, u64 q, u64 p);
}