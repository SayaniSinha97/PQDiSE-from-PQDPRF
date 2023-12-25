#include <iostream>
#include <math.h>
#include <algorithm>
#include <map>
#include <vector>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/SmartPtr.h>

typedef std::uint64_t u64;


std::map<std::pair<int, int>, int> ncr_cache;

/* This function rounds an integer in modulo q to an integer in modulo p. Basically for x in Z_q the function maps
it to the nearest integer of (x*p/q) */
u64 round_toL(u64 x, u64 q, u64 p){
	x >>= (int)(log2(q) - log2(p) - 1);
	int flag = (x & 1) ? 1 : 0;
	x >>= 1;
	return (x + flag);
}

/* This function calculates x modulo q */
u64 moduloL(u64 x, u64 q){
	if(x >= 0){
		return x%q;
	}
	else{
		x = (-x)%q;
		return (x ? (q-x) : x);
	}
}

/* This function calculates nCr, (n Combination r) */
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

/* Given a group_id, find the party_ids present in (group_id)^th combination out of TCt combinations */
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

/* Given a t-sized list of party-ids compute its rank among total TCt combinations */
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


/* This function performs (t,T)-threshold secret sharing among T parties on a key in Z_q^n. It includes calculation of distribution
matrix, rho matrix, multiplication of distribution matrix and rho matrix theoretically. But for better space utilization, 
we generate partial rho matrix of smaller size for each t-sized subset, and generate shares corresponding to parties in such subset 
one after another. We then distribute the shares among T parties, such that each of the parties gets (T-1)C(t-1) shares to store */
void shareSecrettTL(int t, int T, NTL::vec_ZZ_p key, int n, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
	u64 group_count = ncr(T,t);
	std::vector<u64> parties;
	using namespace NTL;
	for(u64 gid = 1; gid <= group_count; gid++){
		findParties(parties, gid, t, T);
		VectorCopy(shared_key_repo_tT[parties[0]][gid], key, n);
		for(int i = 1; i < t; i++){
			random(shared_key_repo_tT[parties[i]][gid], n);
			shared_key_repo_tT[parties[0]][gid] += shared_key_repo_tT[parties[i]][gid];
		}
	}
	// for(int i = 0; i < n; i++){
	// 	std::cout << shared_key_repo_tT[1][1][i] << " ";
	// }
	// std::cout << "\n";
}

/* This function calculates the direct PRF evaluation using secret k */
u64 direct_PRF_eval(NTL::vec_ZZ_p x, NTL::vec_ZZ_p key, u64 n, u64 q, u64 p){
	NTL::ZZ_p eval;
	u64 res;
	NTL::InnerProduct(eval, x, key);
	u64 interim = NTL::conv<ulong>(eval);
	res = round_toL(interim, q, p);
	return res;
}

/* This function calculates threshold PRF evaluation */
u64 threshold_PRF_eval(NTL::vec_ZZ_p x, u64 n, u64 group_id, u64 t, u64 T, u64 q, u64 q1, u64 p, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
	std::vector<u64> parties;
	findParties(parties, group_id, t, T);

	NTL::ZZ_p tmp1;
	u64 tmp2, tmp3;
	u64 interim;

	u64 res;

	NTL::vec_ZZ_p cur_share;

	for(int i = 0; i < t; i++){
		NTL::VectorCopy(cur_share, shared_key_repo_tT[parties[i]][group_id], n);
		NTL::InnerProduct(tmp1, x, cur_share);
		tmp2 = NTL::conv<ulong>(tmp1);
		tmp3 = round_toL(tmp2, q, q1);
		if(i == 0){
			interim += tmp3;
			interim = moduloL(interim, q1);
		}
		else{
			interim -= tmp3;
			interim = moduloL(interim, q1);
		}
	}
	res = round_toL(interim, q1, p);
	return res;
}

int main(){
	u64 p = 1024, q = 4294967296, q1 = 268435456;
	u64 n = 512, t = 5, T = 10;
	std::cout << "[Base 2] log(p): " << log2(p) << ", log(q1): " << log2(q1) << ", log(q): " << log2(q) << "\n";
	std::cout << "Dimension: " << n << ", Threshold no of parties: " << t << ", Total no of parties: " << T << "\n";

	using namespace NTL;

	// Set ZZ_p modulus equal to q
	ZZ_p::init(conv<ZZ>(q));

	vec_ZZ_p x, key;

	/* shared_key_repo_tT stores all t*C(T,t) number of key shares, shared_key_repo_tT[i][j] stores key share of party i corresponding to group j */
	std::map<int, std::map<int, vec_ZZ_p>> shared_key_repo_tT;

	random(key, n);
	// std::cout << "LWR Key:\n";
	// for(int i = 0; i < n; i++){
	// 	std::cout << key[i] << " ";
	// }
	// std::cout << "\n";

	shareSecrettTL(t, T, key, n, shared_key_repo_tT);
	
	/* We will check the correctness of evaluation of threshold PRF for "iter" number of random values of x */ 
	u64 iter = 1000;

	/* group_count is the number of t-sized subsets among T parties */
	u64 group_count = ncr(T,t);

	u64 group_itr;
	int flag;
	std::vector<u64> validset;

	/* threshold_evals is the array containing the evaluated threshold PRF value w.r.t to all possible C(T,t) number of t-sized subset and for a particular value of x */
	// long long int *threshold_evals = (long long int*)malloc(group_count*sizeof(long long int));
	std::vector<u64> threshold_evals;
	threshold_evals.resize(group_count);

	long long int count = 0;
	long long int inconsistency_count = 0;
	long long int direct_eval, distributed_eval, diff, diff2, non_zero_count = 0, non_zero_count2 = 0, diff_bits, max_diff_bits = -1;
	
	while(count < iter){
		/* Choose a random x for each iteration */
		random(x, n);
		
		direct_eval = direct_PRF_eval(x, key, n, q, p);
		
		flag = 0;

		/* Iterate over all C(T,t) number of t-sized subsets and threshold_eval temporarily stores evaluation of threshold PRF w.r.t a specific t-sized subset/group. If the
		evaluated threshold PRF value by at least one t-sized subset differs from the directly evaluated PRF value, we will print the threshold evaluated value of all t-sized subsets. */
		group_itr = 1;
		while(group_itr <= group_count){
			distributed_eval = threshold_PRF_eval(x, n, group_itr, t, T, q, q1, p, shared_key_repo_tT);
			threshold_evals[group_itr-1] = distributed_eval;
			if(distributed_eval != direct_eval){
				flag = 1;
				inconsistency_count++;
			}
			group_itr++;
		}
		// std::cout << "\n";
		if(flag){
			std::cout << "\nDirect eval: " << direct_eval << "\n";
			for(int i = 1; i <= group_count; i++){
				std::cout << threshold_evals[i-1] << " ";
			}
			std::cout << "\n";
		}
		count++;
	}
	// std::cout << "inconsistency_count: " << inconsistency_count << "\n";
	std::cout << "fraction (inconsistency count/total testcases): " << inconsistency_count/(double)(iter * group_count) << "\n";
}