#pragma once

#include <vector>
#include "volePSI/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
// #include "cryptoTools/Network/Channel.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include <atomic>

// © 2025 Digital Trust Centre - Nanyang Technological University. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using namespace volePSI;
using namespace oc;

class OSNReceiver
{
	size_t size;
	int ot_type;
	oc::Timer *timer;
	std::atomic<int> cpus;

	task<> rand_ot_send(std::vector<std::array<osuCrypto::block, 2>> &sendMsg, Socket &chl);
	osuCrypto::SilentOtExtSender &getSilentOtExtSender(osuCrypto::u64 numOTs);
	task<> silent_ot_send(std::vector<std::array<osuCrypto::block, 2>> &sendMsg, Socket &chl);

	task<> gen_benes_client_osn(int values, Socket &chl, std::vector<std::vector<block>> &ret_masks); // TKL added
	std::vector<std::vector<oc::block>> gen_benes_client_osn(int values, Socket &chl);
	void prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block> &src,
							std::vector<std::array<std::array<osuCrypto::block, 2>, 2>> &ot_output,
							std::vector<std::array<osuCrypto::block, 2>> &correction_blocks);

public:
	OSNReceiver(size_t size = 0, int ot_type = 0);
	void init(size_t size, int ot_type = 0);
	task<> run_osn(oc::span<block> inputs, Socket &chl, std::vector<oc::block> &output_masks);
	void setTimer(oc::Timer &timer);
	oc::Timer &getTimer() { return *timer; };
};
