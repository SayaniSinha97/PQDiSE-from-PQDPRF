#include "LWRDPRF_tests.h"
#include <dEnc/dprf/LWRSymDprf.h>
// #include <dEnc/dprf/LWR_helper.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>

#include <dEnc/tools/GroupChannel.h>

using namespace dEnc;




void LWRSymDPRF_eval_test(){
	oc::setThreadName("__myThread__");

	u64 n = 4;
	u64 m = 2;

	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> comms(n);
	std::vector<LWRSymDprf> dprfs(n);

	oc::Finally f([&]() {
		for (auto& d : dprfs) d.close();
		dprfs.clear();
		comms.clear(); });

	for (u64 i = 0; i < n; ++i)
		comms[i].connect(i, n, ios);

    PRNG prng(oc::ZeroBlock);
    LWRSymDprf::KeyGen(n, m);
	for (u64 i = 0; i < n; ++i){
		dprfs[i].init(i, comms[i].mRequestChls, comms[i].mListenChls);
	}

	std::vector<block> x(trials), exp(trials);

	for (u64 t = 0; t < trials; ++t){
		x[t] = prng.get<block>();
		exp[t] = oc::ZeroBlock;
	}
	
	/* Direct evaluation of PRF on random block inputs of x with the LWR Key */
	direct_eval(x, &exp, LWRSymDprf::LWRKey, LWRSymDprf::q, LWRSymDprf::p);
	
	// std::cout << "input block: " << x[0] << "\n";

	for (u64 i = 0; i < n; ++i){

		/* Async batch evaluation of PRF on x, the input array of blocks by set of parties {i, i+1, ..., i+t-1} */
		auto out = dprfs[i].asyncEval(x).get();
		for (u64 t = 0; t < trials; ++t){

			/* Individual evaluation of PRF on input block x[t] by set of parties {i, i+1, ..., i+t-1} */
			auto fi = dprfs[i].eval(x[t]);

			// std::cout << "input block: " << x[t] << "\n";
			// std::cout << "distributed eval: " << fi << "\n";
			// std::cout << "distributed asynceval: " << out[t] << "\n";
			// std::cout << "direct eval: " << exp[t] << "\n";

			/* Check correctness of both batch evaluation and individual evaluation of PRF w.r.t direct evaluation */
			if (neq(fi, exp[t]) || neq(out[t], exp[t])){
				std::cout << "failed " << std::endl;
				throw std::runtime_error(LOCATION);
			}
		}
	}
}