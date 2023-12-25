#pragma once
#include <dEnc/Defines.h>

namespace dEnc{
	void compare_partial_evaluations_LWR(int iters, int t, int T, u64 q, u64 q1);
	void compare_partial_evaluations_NPRSym(int iters, int t, int T);
	void compare_partial_evaluations_NPRASym(int iters, int t, int T);
}