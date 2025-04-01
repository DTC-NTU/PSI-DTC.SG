#pragma once

#include <vector>
#include <map>
#include <string>
#include "volePSI/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
// #include "cryptoTools/Network/Channel.h"
#include "benes.h"

using namespace volePSI;
using namespace oc;

class OSNSender
{
	size_t size;
	int ot_type;
	oc::Timer *timer;
	std::vector<int> mPi;
	Benes benes;
	osuCrypto::SilentOtExtReceiver &getSilentOtExtReceiver(osuCrypto::u64 numOTs);
	task<> silent_ot_recv(osuCrypto::BitVector &choices,
						  std::vector<osuCrypto::block> &recvMsg,
						  Socket &chl);
	task<> rand_ot_recv(osuCrypto::BitVector &choices,
						std::vector<osuCrypto::block> &recvMsg,
						Socket &chl);
	task<> gen_benes_server_osn(int values, Socket &chl, std::vector<std::array<osuCrypto::block, 2>> &recvMsg);

public:
	std::vector<int> dest;
	OSNSender(size_t size = 0, int ot_type = 0);
	void init(size_t size, int ot_type = 0, const std::string &osn_cache = "", const std::vector<uint64_t> intersection = {});
	void init_wj(size_t size, int ot_type, const std::string &osn_cache, std::map<int, int> &i2locptr);
	std::vector<int> getmyPi(const std::map<int, int> &i2loc, const std::vector<u64> &intersection);
	std::vector<int> getPi() { return mPi; }
	void setPi(std::vector<int> myPi) { mPi = myPi; }
	task<> run_osn(Socket &chl, std::vector<oc::block> &input_vec);
	void setTimer(oc::Timer &timer);
	oc::Timer &getTimer() { return *timer; };
};
