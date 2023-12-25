/* This file shows that real and simulated partial evaluations (by honest party) are from same distribution with toy values of parameters. See the output file "pqdprf/compare_count_tT.csv" after running this code. */

#include <iostream>
#include <fstream>
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

/* Calculation of actual partial evaluation of party party_id with its key share k_i corresponding to specific group_id, as round(<x,k_i>)_q1 */
u64 actual_part_eval(u64 group_id, u64 party_id, NTL::vec_ZZ_p x, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT, u64 n, u64 q, u64 q1, std::vector<u64> &actual_part_eval_count){
	NTL::vec_ZZ_p first_share;
	NTL::VectorCopy(first_share, shared_key_repo_tT[party_id][group_id], n);
	NTL::ZZ_p eval;
	NTL::InnerProduct(eval, x, first_share);
	u64 partial_eval_actual_unrounded = NTL::conv<ulong>(eval);
	u64 partial_eval_actual = round_toL(partial_eval_actual_unrounded, q, q1);
	actual_part_eval_count[partial_eval_actual]++;
	return partial_eval_actual;
}

/* Calculation of simulated partial evaluation without using specific key of a party, rather using the key shares of the corrupted parties */
u64 simulated_part_eval(u64 group_id, std::vector<u64> corrupted, NTL::vec_ZZ_p x, NTL::vec_ZZ_p key, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT, u64 n, u64 T, u64 q, u64 p, u64 q1, std::vector<u64> &simulated_part_eval_count){
	u64 sz = corrupted.size();
	std::vector<u64> parties;
	findParties(parties, group_id, sz+1, T);
	int group_leader = parties[0];	/* Party with minimum party_id is the group_leader */

	/* The array partial_evaluation stores partial evaluations of each of the corrupted parties before rounding to modulo q1 */
	NTL::vec_ZZ_p partial_evaluations;
	partial_evaluations.SetLength(sz);

	/* share is a temporary array to store key share of any one of the corrupted parties during loop execution */
	NTL::vec_ZZ_p share;

	/* Iterate over each of the corrupted parties and calculate their partial evaluations */
	for(int i = 0; i < sz; i++){
		NTL::VectorCopy(share, shared_key_repo_tT[corrupted[i]][group_id], n);
		NTL::InnerProduct(partial_evaluations[i], x, share);
	}

	/* Simulate partial evaluation of honest party using secret shares of corrupted parties. */
	u64 sum_partial_evals;
	NTL::ZZ_p temp = NTL::conv<NTL::ZZ_p>(0);
	for(int i = 0; i < sz; i++){
		if(corrupted[i] == group_leader){
			temp += partial_evaluations[i];
		}
		else{
			temp -= partial_evaluations[i];
		}
	}
	sum_partial_evals = NTL::conv<ulong>(temp);
	NTL::ZZ_p eval;
	NTL::InnerProduct(eval, x, key);
	u64 tmp = NTL::conv<ulong>(eval);
	u64 prf_eval = round_toL(tmp, q, p);
	u64 partial_eval_simulated_unrounded = moduloL(moduloL((prf_eval * (u64)q/p), q) + sum_partial_evals, q);
	u64 partial_eval_simulated = round_toL(partial_eval_simulated_unrounded, q, q1);
	simulated_part_eval_count[partial_eval_simulated]++;
	return partial_eval_simulated;
}

int main(){
	u64 p = 16, q = 512, q1 = 128;
	u64 n = 3, t = 5, T = 8;
	std::cout << "p: " << p << " q: " << q << " q1: " << q1 << " q/p: " << q/(double)p << " p/q1: " << p/(double)q1 << "\n";

	using namespace NTL;
	ZZ_p::init(conv<ZZ>(q));

	vec_ZZ_p x, key;

	std::map<int, std::map<int, vec_ZZ_p>> shared_key_repo_tT;

	std::vector<u64> actual_part_eval_count, simulated_part_eval_count;
	actual_part_eval_count.resize(q1);
	simulated_part_eval_count.resize(q1);

	random(key, n);

	// std::cout << "Key:\n";
	// for(int i = 0; i < n; i++){
	// 	std::cout << key[i] << " ";
	// }
	// std::cout << "\n";

	shareSecrettTL(t, T, key, n, shared_key_repo_tT);
	
	std::vector<u64> corrupted{2,4,7,8};
	std::vector<u64> validset{2,4,6,7,8};
	u64 group_id = findGroupId(validset, t, T);
	std::cout << "group id: " << group_id << "\n";

	u64 iter = (u64)pow((double)q,(double)n);
	// std::cout << iter << "\n";

	x.SetLength(n);
	for(int i = 0; i < n; i++){
		x[i] = 0;
	}

	u64 count = 0;
	u64 eval1, eval2, diff, non_zero_count = 0;

	std::vector<u64> divisors;
	divisors.resize(n);
	for(int i = 0; i < n; i++){
		divisors[i] = (u64)pow((double)q, (double)i);
	}
	
	/* Iterate over all q^n possible values of x one by one. */
	while(count < iter){

		/* Print x */
		// for(int i = 0; i < n; i++){
		// 	std::cout << x[i] << " ";
		// }
		// std::cout << "\n";	

		eval1 = actual_part_eval(group_id, 6, x, shared_key_repo_tT, n, q, q1, actual_part_eval_count);

		eval2 = simulated_part_eval(group_id, corrupted, x, key, shared_key_repo_tT, n, T, q, p, q1, simulated_part_eval_count);

		std::cout << eval1 << " " << eval2 << "\n";
		
		count++;

		/* Get next value of x */
		for(int i = 0; i < n; i++){
			if(count % divisors[i] == 0){
				x[i] = x[i] + 1;
			}
		}
	}

	/* This file stores the frequency of occurrance of values of 0 to (q1-1) as the output of actual and simulated partial evaluation respectively. */
	std::ofstream myfile("compare_count_tT.csv");
	for(int i = 0; i < q1; i++){
		myfile << i << "," << actual_part_eval_count[i] << "," << simulated_part_eval_count[i] << "\n";
	}
	myfile.close();

	double sum = 0;
	for(u64 i = 0; i < q1; i++){
		sum += abs((double)(actual_part_eval_count[i] - simulated_part_eval_count[i]));
	}
	sum = sum/(2*iter);
	std::cout << "Statistical distance: " << sum << "\n";

}