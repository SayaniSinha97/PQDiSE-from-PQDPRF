#include "LWR_helper.h"
#include <cryptoTools/Common/Timer.h>
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/block.h"
#include <string>
#include <map>
#include <omp.h>

namespace dEnc{
	using RandomOracle = oc::RandomOracle;
	// RandomOracle H_tmp(64);
	typedef struct bytes64{
		u32 arr[16];
	}bytes64;

	std::map<std::pair<u64, u64>, u64> ncr_cache;

	u64 ncr(u64 n, u64 r){
	    if (ncr_cache.find({n, r}) == ncr_cache.end()){
	        if (r > n || n < 0 || r < 0)
	            return 0;
	        else{
	            if (r == 0 || r == n){
	                ncr_cache[{n, r}] = 1;
	            }
	            else if (r == 1 || r == n - 1){
	                ncr_cache[{n, r}] = n;
	            }
	            else{
	                ncr_cache[{n, r}] = ncr(n - 1, r) + ncr(n - 1, r - 1);
	            }
	        }
	    }

	    return ncr_cache[{n, r}];
	}


	u64 moduloMultiplication(u64 a, u64 b, u64 q){
	    u64 res = 0;
	    a %= q;
	    while (b) {
	        if (b & 1)
	            res = (res + a) % q;
	        a = (2 * a) % q;
	        b >>= 1;
	    }
	    res = moduloL(res, q);
	    return res;
	}


	void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T){
		u64 mem = 0, tmp;
		pt.clear();
		for(u64 i = 1; i < T; i++){
			tmp = ncr(T - i, t - mem -1);
			if(gid > tmp){
				gid -= tmp;
			}
			else{
				pt.push_back(i);
				mem += 1;
			}
			if(mem + (T-i) == t){
				for(u64 j = i + 1; j <= T; j++){
					pt.push_back(j);
				}
				break;
			}
		}
	}


	u64 findGroupId(std::vector<u64> parties, u64 t, u64 T){
		u64 mem = 0;
		u64 group_count = 1;
		for(u64 i = 1; i <= T; i++){
			if(std::find(parties.begin(), parties.end(), i) != parties.end()){
				mem += 1;
			}
			else{
				group_count += ncr(T - i, t - mem - 1);
			}
			if(mem == t){
				break;
			}
		}
		return group_count;
	}


	void convert_block_to_extended_lwr_input(block x, std::vector<NTL::vec_ZZ_p>* y){
		using namespace NTL;
		std::vector<bytes64> hash_outputs;
		hash_outputs.resize(13 * 32);
		int section_length = 32;
		int sectionid, offset;
		
		// #pragma omp parallel for num_threads(4) private(sectionid, offset)
		for(int i = 0; i < 13 * section_length; i++){
			// std::cout << omp_get_thread_num() << " " << i << "\n";
			RandomOracle Hash(64);
			Hash.Update(x);
			Hash.Update(i+1);
			sectionid = i/section_length;
			offset = i % section_length;
			Hash.Final(hash_outputs[i]);
			for(int j = 0; j < 16; j++){
				(*y)[sectionid][(offset * 16) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
			}
			// Hash.Reset();
		}
	}


	block decimal_array_to_single_block(std::vector<u16> arr){
		block b;
		oc::BitIterator iter((u8*)&b, 0);
		for(int i = 0; i < 128; i++){
			*(iter + i) = (arr[(i/10)] >> (i%10)) & 1;
		}
		return b;
	}


	void part_eval(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1){
		int sz = inp.size();
		// std::cout << "sz: " << sz << "\n";
		// #pragma omp parallel num_threads(4) shared(sz, keyshare, inp, outp, q, q1)
		// {
			// #pragma omp taskloop num_tasks(2)
			for(int i = 0; i < sz; i++){
				// std::cout << "i: " << i << " " << omp_get_thread_num() << "\n";
				for(int j = 0; j < 13; j++){
					// std::cout << "j: " << j << " " << omp_get_thread_num() << "\n";
					NTL::ZZ_p outp_;
					// std::cout << "inp: " << inp[i][j][0] << " " << omp_get_thread_num() << "\n";
					NTL::InnerProduct(outp_, inp[i][j], keyshare);
					// std::cout << "i: " << outp_ << " " << omp_get_thread_num() << "\n";
					u64 interim = NTL::conv<ulong>(outp_);
					// std::cout << interim << "\n";
					(*outp)[i][j] = round_toL(interim, q, q1);
				}
				// std::cout << "i: " << i << "    " << omp_get_thread_num() << "\n";
			}
		// }
	}


	void part_eval_single(std::vector<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1){
		for(int j = 0; j < 13; j++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[j], keyshare);
			u64 interim = NTL::conv<ulong>(outp_);
			(*outp)[j] = round_toL(interim, q, q1);
		}
	}


	void direct_eval_single(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, u64 q, u64 p){
		std::vector<u16> outp_arr;
		outp_arr.resize(13);
		for(int i = 0; i < 13; i++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[i], key);
			u64 interim = NTL::conv<ulong>(outp_);
			outp_arr[i] = round_toL(interim, q, p);
			// direct_eval_basic3(inp[i], &(outp_arr[i]), key, q, p, t);
		}
		*outp = decimal_array_to_single_block(outp_arr);
	}


	void direct_eval(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, u64 q, u64 p){
		std::vector<std::vector<NTL::vec_ZZ_p>> inp;
		inp.resize(in.size());
		for(int i = 0; i < inp.size(); i++){
			inp[i].resize(13);
			std::vector<u16> outp_arr(13);
			for(int j = 0; j < 13; j++){
				inp[i][j].SetLength(512);
			}
			convert_block_to_extended_lwr_input(in[i], &(inp[i]));
			for(int j = 0; j < 13; j++){
				NTL::ZZ_p outp_;
				NTL::InnerProduct(outp_, inp[i][j], key);
				u64 interim = NTL::conv<ulong>(outp_);
				outp_arr[j] = round_toL(interim, q, p);
			}
			(*dir_out)[i] = decimal_array_to_single_block(outp_arr);
		}
	}
}