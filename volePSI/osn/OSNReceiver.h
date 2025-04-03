#pragma once

#include <vector>
#include "volePSI/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
// #include "cryptoTools/Network/Channel.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include <atomic>

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
