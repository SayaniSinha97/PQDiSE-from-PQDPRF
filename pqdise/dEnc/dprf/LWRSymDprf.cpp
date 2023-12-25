#include "LWRSymDprf.h"
// #include "Dprf.h"
#include <random>
#include <map>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/MatrixView.h>
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Log.h"
#include <cryptoTools/Common/Timer.h>
#include <omp.h>


namespace dEnc{
	// std::map<std::pair<u64, u64>, u64> part_eval_time;
	// typedef struct short_int_block{
	// 	std::vector<short int> sib[13];
	// }short_int_block;

	// std::random_device rd;
	// std::mt19937_64 eng(rd());

	// std::uniform_int_distribution<u64> distr;
	// std::vector<u64> LWRSymDprf::LWRKey{0};
	// std::map<int, std::map<int, std::vector<u64>>> LWRSymDprf::shared_key_repo_tT;

	
	NTL::vec_ZZ_p LWRSymDprf::LWRKey;
	std::map<int, std::map<int, NTL::vec_ZZ_p>> LWRSymDprf::shared_key_repo_tT;
	u64 LWRSymDprf::t = 0;
	u64 LWRSymDprf::T = 0;
	
	LWRSymDprf::~LWRSymDprf(){
        close();

        // if we have started listening to the network, then 
        // wait for the server callbacks to complete.
		if (mServerListenCallbacks.size())
			mServerDone.get();
	}

	void LWRSymDprf::shareSecrettTL(u64 T, u64 t){
		// // std::cout << "inside secret sharing function:" << " T: " << T << " t: " << t << "\n";
		u64 group_count = ncr(T,t);
		std::vector<u64> parties;
		for(u64 gid = 1; gid <= group_count; gid++){
			findParties(parties, gid, t, T);
			NTL::VectorCopy(shared_key_repo_tT[parties[0]][gid], LWRKey, dim);
			for(int i = 1; i < t; i++){
				NTL::random(shared_key_repo_tT[parties[i]][gid], dim);
				shared_key_repo_tT[parties[0]][gid] += shared_key_repo_tT[parties[i]][gid];
			}
		}
	}


	void LWRSymDprf::KeyGen(u64 n, u64 m){
		using namespace NTL;
	    ZZ_p::init(conv<ZZ>(q));
		T = n;
		t = m;
		random(LWRKey, dim);

		shareSecrettTL(T, t);
	}

	NTL::vec_ZZ_p LWRSymDprf::getSubkey(u64 groupId){
    	// std::cout << "inside getsubkey:: partyId: " << partyId << ", groupId: " << groupId << ", dim: " << dim << "\n";
    	u64 party_id = this->partyId + 1;
    	return shared_key_repo_tT[party_id][groupId];
    }


    void LWRSymDprf::init(u64 partyId, span<Channel> requestChls, span<Channel> listenChls){
		this->partyId = partyId;
		this->mRequestChls = { requestChls.begin(), requestChls.end() };
		this->mListenChls = { listenChls.begin(), listenChls.end() };
	    this->mIsClosed = false;
	    using namespace NTL;
	    ZZ_p::init(conv<ZZ>(q));
	    // std::cout << "xor: " << (oc::ZeroBlock ^ oc::OneBlock) << "\n";
		startListening();
	}


	void LWRSymDprf::startListening(){
		mRecvBuff.resize(mRequestChls.size());
		mListens = mListenChls.size();
		mServerListenCallbacks.resize(mListenChls.size());

		// std::cout << "inside startlistening, partyId: " << this->partyId << "\n";
		for (u64 i = 0; i < mListenChls.size(); ++i)
		{
			mServerListenCallbacks[i] = [&, i]()
			{
                // If the client sends more than one byte, interpret this
                // as a request to evaluate the DPRF.
				if (mRecvBuff[i].size() > 1)
				{
                    // Evaluate the DPRF and send the result back.
                    // std::cout << "calling serveone with i: " << i << "\n";
					serveOne(mRecvBuff[i], i);

                    // Eueue up another receive operation which will call 
                    // this callback when the request arrives.
					mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
				}
				else
				{
                    // One byte means that the cleint is done requiresting 
                    // DPRf evaluations. We can close down.
					if (--mListens == 0)
					{
                        // If this is the last callback to close, set
                        // the promise that denotes that the server
                        // callback loops have all completed.
						mServerDoneProm.set_value();
					}
				}
			};

			mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
		}
	}


	// void LWRSymDprf::serveOne(span<u8> rr, u64 chlIdx){
 //        TODO("Add support for allowing the request to specify which parties are involved in this evaluation. "
 //            "This can be done by sending a bit vector of the parties that contribute keys and then have this "
 //            "party figure out which keys to use in a similar way that constructDefaultKeys(...) does it.");

 //        // Right now we only support allowing 16 bytes to be the DPRF input.
 //        // When a multiple is sent, this its interpreted as requesting 
 //        // several DPRF evaluations.
		
	// 	if((rr.size() % sizeof(u64) != 0) || (rr.size() % (sizeof(u64)*13*512) != sizeof(u64)))
	// 		throw std::runtime_error(LOCATION);

 //        // Get a view of the data as u64.
	// 	span<u64> request((u64*)rr.data(), rr.size()/sizeof(u64));
	// 	std::vector<u64> inp;
	// 	inp.insert(inp.end(), request.begin(), request.end());
		
	// 	u64 group_id = inp.back();
	// 	inp.pop_back();

	// 	std::vector<u64> keyshare = this->getSubkey(group_id);

	// 	u64 sz = inp.size()/(13*512);

	// 	// a vector to hold the DPRF output shares.
	// 	std::vector<u32> fx;
	// 	fx.resize(sz * 13);

	// 	std::vector<std::vector<std::vector<u64>>> inp_(sz, std::vector<std::vector<u64>>(13, std::vector<u64>(512)));
	// 	inp_.resize(sz);
	// 	// int threadnum = t <= 2 ? 4 : 2;
	// 	// int threadnum = 2;
	// 	// #pragma omp parallel for num_threads(threadnum) collapse(3)
	// 	for(int i = 0; i < sz; i++){
	// 		for(int j = 0; j < 13; j++){
	// 			for(int k = 0; k < 512; k++){
	// 				inp_[i][j][k] = inp[i * 13 * 512 + j * 512 + k];
	// 			}
	// 		}
	// 	}
		
	// 	std::vector<std::vector<u32>> tmp(sz, std::vector<u32>(13));
	// 	part_eval_extended_multiple(inp_, &tmp, keyshare, q, q1, t);

	// 	// #pragma omp parallel for num_threads(threadnum) collapse(2)
	// 	for(int i = 0; i < sz; i++){
	// 		for(int j = 0; j < 13; j++){
	// 			fx[i * 13 + j] = tmp[i][j];
	// 		}
	// 	}
	// 	mListenChls[chlIdx].asyncSend(fx);
	// }

void LWRSymDprf::serveOne(span<u8> rr, u64 chlIdx){
        TODO("Add support for allowing the request to specify which parties are involved in this evaluation. "
            "This can be done by sending a bit vector of the parties that contribute keys and then have this "
            "party figure out which keys to use in a similar way that constructDefaultKeys(...) does it.");

        // Right now we only support allowing 16 bytes to be the DPRF input.
        // When a multiple is sent, this its interpreted as requesting 
        // several DPRF evaluations.
		
		if((rr.size() % sizeof(u64) != 0) || (rr.size() % (sizeof(u64)*13*512) != sizeof(u64)))
			throw std::runtime_error(LOCATION);

  //       // Get a view of the data as u64.
		span<u64> request((u64*)rr.data(), rr.size()/sizeof(u64));
		std::vector<u64> inp;
		inp.insert(inp.end(), request.begin(), request.end());
		
		u64 group_id = inp.back();
		inp.pop_back();
		using namespace NTL;
        ZZ_p::init(conv<ZZ>(q));
		// std::vector<u64> keyshare = this->getSubkey(group_id);
		vec_ZZ_p keyshare = this->getSubkey(group_id);

		u64 sz = inp.size()/(13*512);

		// // a vector to hold the DPRF output shares.
		std::vector<u32> fx;
		fx.resize(sz * 13);

		// std::vector<std::vector<std::vector<u64>>> inp_(sz, std::vector<std::vector<u64>>(13, std::vector<u64>(512)));
		// inp_.resize(sz);
		std::vector<std::vector<vec_ZZ_p>> inp_;
		inp_.resize(sz);
        for(int i = 0; i < sz; i++){
        	inp_[i].resize(13);
        	for(int j = 0; j < 13; j++){
        		inp_[i][j].SetLength(512);
        	}
        }
		
		// // int threadnum = t <= 2 ? 4 : 2;
		// // int threadnum = 2;
		// // #pragma omp parallel for num_threads(threadnum) collapse(3)
		for(int i = 0; i < sz; i++){
			for(int j = 0; j < 13; j++){
				for(int k = 0; k < 512; k++){
					inp_[i][j][k] = conv<ZZ_p>(inp[i * 13 * 512 + j * 512 + k]);
				}
			}
		}
		
		std::vector<std::vector<u32>> tmp(sz, std::vector<u32>(13));
		part_eval(inp_, &tmp, keyshare, q, q1);

		// // #pragma omp parallel for num_threads(threadnum) collapse(2)
		for(int i = 0; i < sz; i++){
			for(int j = 0; j < 13; j++){
				fx[i * 13 + j] = tmp[i][j];
			}
		}
		mListenChls[chlIdx].asyncSend(fx);
	}


	block LWRSymDprf::eval(block input){
		// std::cout << "inside eval\n";
		return asyncEval(input).get()[0];
	}


	AsyncEval LWRSymDprf::asyncEval(block input){
		std::vector<block> inp;
		inp.resize(1);
		inp[0] = input;
		// std::cout << "inside asynceval block\n";
		return asyncEval(inp);
	}


	AsyncEval LWRSymDprf::asyncEval(span<block> in){
		// std::cout << "inside asynceval spanblock: " << in.size() << "\n";
		struct State
        {
            // to store DPRF input and final DPRF output blocks respectively
            std::vector<block> out;
            std::vector<u64> inp;
            std::vector<u32> fxx;
            std::vector<std::vector<u32>> interim_out;
            std::unique_ptr<std::future<void>[]> async;
        };
        auto state = std::make_shared<State>();
        using namespace NTL;
        ZZ_p::init(conv<ZZ>(q));
        // allocate space to store the DPRF outputs.
        state->out.resize(in.size());
        // allocate space to store the partial DPRF evaluation of the party itself.
        state->interim_out.resize(in.size(), std::vector<u32>(13));
        
        state->inp.resize(in.size() * 13 * 512);
        // Copy the inputs into a shared vector so that it 
        // can be sent to all parties using one allocation.
        std::vector<block> in_;
        in_.insert(in_.end(), in.begin(), in.end());

        std::vector<std::vector<vec_ZZ_p>> inp_;
        inp_.resize(in.size());
        for(int i = 0; i < in.size(); i++){
        	inp_[i].resize(13);
        	for(int j = 0; j < 13; j++){
        		inp_[i][j].SetLength(512);
        	}
        }

        for(int i = 0; i < in_.size(); i++){
        	convert_block_to_extended_lwr_input(in_[i], &inp_[i]);
        }

        // #pragma omp parallel for num_threads(8) collapse(3)
        for(int i = 0; i < in_.size(); i++){
        	for(int j = 0; j < 13; j++){
        		for(int k = 0; k < 512; k++){
        			state->inp[i * 13 * 512 + j * 512 + k] = conv<ulong>(inp_[i][j][k]);
        		}
        	}
        }

        // "collaborators" stores the party-ids of t consecutive parties 
        // starting from current party which will take part in threshold evaluation.
        // If current party is the group-leader among them, then flag = -1,
        // otherwise, flag stores which row of fx will have the partial evaluation of group-leader.
        // std::cout << "party-id: " << this->partyId << "\n";
        std::vector<u64> collaborators;
        int flag = -1;
        collaborators.resize(t);
		auto end = this->partyId + t;
		for(u64 i = 0; i < t; i++){
			u64 c = ((this->partyId + i) % T) + 1;
			if(this->partyId != 0 && c == 1){
				flag = i - 1;
			}
			collaborators[i] = c;
		}
		// std::cout << "collaborators\n";
		// for(int i = 0; i < t; i++){
		// 	std::cout << collaborators[i] << " ";
		// }
		// std::cout << "\n";
		u64 group_id = findGroupId(collaborators, t, T);
		state->inp.push_back(group_id);
		// send this input to all parties
		for (u64 i = this->partyId + 1; i < end; ++i)
		{
			auto c = i % T;
			if (c > this->partyId) --c;

            // This send is smart and will increment the ref count of
            // the shared pointer
			mRequestChls[c].asyncSend(state->inp);
		}
		
		state->inp.pop_back();

		// local DPRF partial evaluation with own keyshare
		// std::vector<u64> keyshare = this->getSubkey(group_id);
		vec_ZZ_p keyshare = this->getSubkey(group_id);
		// std::cout << "entering own part eval\n";
		part_eval(inp_, &state->interim_out, keyshare, q, q1);		
		
        // allocate space to store the other DPRF output shares
		auto numRecv = (t - 1);
        state->fxx.resize(numRecv * in.size() * 13);

        // Each row of fx will hold a the DPRF output shares from one party
		
		oc::MatrixView<u32> fx(state->fxx.begin(), state->fxx.end(), in.size()*13);

        // allocate space to store the futures which allow us to block until the
        // other DPRF output shares have arrived.
        state->async.reset(new std::future<void>[numRecv]);

        // schedule the receive operations for the other DPRF output shares.
		for (u64 i = this->partyId + 1, j = 0; j < numRecv; ++i, ++j)
		{
			auto c = i % T;
			if (c > this->partyId) --c;

			state->async[j] = mRequestChls[c].asyncRecv(fx[j]);
		}


        // construct the completion handler that is called when the user wants to 
        // actual DPRF output. This requires blocking to receive the DPRF output
        // and then combining it.
		AsyncEval ae;
		std::vector<std::vector<u32>> tmp(in.size(), std::vector<u32>(13));
		std::vector<std::vector<u16>> final_o(in.size(), std::vector<u16>(13));

		ae.get = [state, tmp, final_o, flag, numRecv, fx]() mutable -> std::vector<block>
		{
			auto& o = state->out;
			auto& interim_o = state->interim_out;

			// #pragma omp parallel for num_threads(std::min<u64>(8, numRecv))
			for(int k = 0; k < numRecv; k++){
				state->async[k].get();
			}
            if(flag == -1){
				// #pragma omp parallel for num_threads(8) collapse(2)
				for(int i = 0; i < o.size(); i++){
					for(int j = 0; j < 13; j++){
						tmp[i][j] = interim_o[i][j];
						for(int k = 0; k < numRecv; k++){
							tmp[i][j] -= fx[k][i * 13 + j];
							tmp[i][j] = moduloL(tmp[i][j], q1);
						}
					}
				}
			}
			else{
				// #pragma omp parallel for num_threads(8) collapse(2)
				for(int i = 0; i < o.size(); i++){
					for(int j = 0; j < 13; j++){
						tmp[i][j] = moduloL(fx[flag][i * 13 + j] - interim_o[i][j], q1);
						for(int k = 0; k < numRecv; k++){
							if(k != flag){
								tmp[i][j] -= fx[k][i * 13 + j];
								tmp[i][j] = moduloL(tmp[i][j], q1);
							}
						}
					}
				}
			}
			// #pragma omp parallel for num_threads(8) collapse(2)
			for(int j = 0; j < o.size(); j++){
				for(int k = 0; k < 13; k++){
					// tmp[j][k] = moduloL(tmp[j][k], q1);
					final_o[j][k] = round_toL(tmp[j][k], q1, p);
				}
			}
			// #pragma omp parallel for num_threads(8)
			for(int j = 0; j < o.size(); j++){
				o[j] = decimal_array_to_single_block(final_o[j]);
			}

			return std::move(o);
		};

		return ae;
	}

	void LWRSymDprf::close(){
        if (mIsClosed == false){
            mIsClosed = true;

		    u8 close[1];
		    close[0] = 0;

            // closing the channel is done by sending a single byte.
		    for (auto& c : mRequestChls)
			    c.asyncSendCopy(close, 1);

        }
	}
}