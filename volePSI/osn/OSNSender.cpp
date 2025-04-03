#include "OSNSender.h"
#include "libOTe/Base/BaseOT.h"
// #include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/AES.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"

using namespace std;
using namespace osuCrypto;

task<> OSNSender::gen_benes_server_osn(int values, Socket &chl, std::vector<std::array<osuCrypto::block, 2>> &recvMsg)
{
	block temp_msg[2];
	AES aes(ZeroBlock);
	auto switches = osuCrypto::BitVector{};
	auto recvCorr = std::vector<std::array<osuCrypto::block, 2>>{};
	auto tmpMsg = std::vector<osuCrypto::block>{};
	auto choices = osuCrypto::BitVector{};
	auto bit_correction = osuCrypto::BitVector{};

	switches = benes.return_gen_benes_switches(values);
	recvMsg = std::vector<std::array<osuCrypto::block, 2>>(switches.size());
	recvCorr = std::vector<std::array<osuCrypto::block, 2>>(switches.size());
	if (ot_type == 0)
	{
		tmpMsg = std::vector<osuCrypto::block>(switches.size());
		choices = osuCrypto::BitVector(switches.size());

		co_await (silent_ot_recv(choices, tmpMsg, chl));

		for (auto i = 0u; i < recvMsg.size(); i++)
		{
			recvMsg[i] = {tmpMsg[i], aes.ecbEncBlock(tmpMsg[i])};
		}
		bit_correction = switches ^ choices;
		co_await (chl.send(bit_correction));
	}
	else
	{
		tmpMsg = std::vector<osuCrypto::block>(switches.size());
		co_await (rand_ot_recv(switches, tmpMsg, chl));
		for (auto i = 0u; i < recvMsg.size(); i++)
			recvMsg[i] = {tmpMsg[i], aes.ecbEncBlock(tmpMsg[i])};
	}
	co_await (chl.recv(recvCorr));
	for (auto i = 0u; i < recvMsg.size(); i++)
	{
		if (switches[i] == 1)
		{
			temp_msg[0] = recvCorr[i][0] ^ recvMsg[i][0];
			temp_msg[1] = recvCorr[i][1] ^ recvMsg[i][1];
			recvMsg[i] = {temp_msg[0], temp_msg[1]};
		}
	}
}

task<> OSNSender::run_osn(Socket &chl, std::vector<oc::block> &input_vec)
{
	int values = size;
	int N = int(ceil(log2(values)));
	int levels = 2 * N - 1;
	int ctr = 0;
	auto matrix_ot_output = std::vector<std::vector<std::array<osuCrypto::block, 2>>>{};
	auto ot_output = std::vector<std::array<osuCrypto::block, 2>>{};

	co_await (gen_benes_server_osn(values, chl, ot_output));

	input_vec.resize(values);
	co_await (chl.recv(input_vec));

	matrix_ot_output = std::vector<std::vector<std::array<osuCrypto::block, 2>>>(
		levels, std::vector<std::array<osuCrypto::block, 2>>(values));
	// std::vector<std::vector<std::array<osuCrypto::block, 2>>> matrix_ot_output(
	// 	levels, std::vector<std::array<osuCrypto::block, 2>>(values));
	// int ctr = 0;
	for (int i = 0; i < levels; ++i)
	{
		for (int j = 0; j < values / 2; ++j)
			matrix_ot_output[i][j] = ot_output[ctr++];
	}

	benes.gen_benes_masked_evaluate(N, 0, 0, input_vec, matrix_ot_output);
}

void OSNSender::setTimer(Timer &timer)
{
	this->timer = &timer;
}
// TKL workaround for SilentOtExtReceiver deleted constructor function error
osuCrypto::SilentOtExtReceiver &OSNSender::getSilentOtExtReceiver(osuCrypto::u64 numOTs)
{
	osuCrypto::SilentOtExtReceiver recv;
	recv.configure(numOTs);
	return recv;
}

task<> OSNSender::silent_ot_recv(osuCrypto::BitVector &choices,
								 std::vector<osuCrypto::block> &recvMsg,
								 Socket &chl)
{
	// std::cout << "\n Silent OT receiver!!\n";

	auto prng0 = osuCrypto::PRNG(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	auto baseRecv = std::vector<osuCrypto::block>{};
	auto numOTs = size;

	co_await (getSilentOtExtReceiver(numOTs).silentReceive(choices, recvMsg, prng0, chl));
}

task<> OSNSender::rand_ot_recv(osuCrypto::BitVector &choices,
							   std::vector<osuCrypto::block> &recvMsg,
							   Socket &chl)
{

	auto prng0 = osuCrypto::PRNG(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	auto baseRecv = std::vector<osuCrypto::block>{};
	auto baseSend = std::vector<std::array<osuCrypto::block, 2>>{};
	auto baseChoice = osuCrypto::BitVector{};
	auto baseOTs = osuCrypto::DefaultBaseOT{};
	auto recv = std::move(osuCrypto::IknpOtExtReceiver{});

	baseRecv.resize(128);
	baseSend.resize(128);
	baseChoice.resize(128);

	prng0.get((osuCrypto::u8 *)baseSend.data()->data(), sizeof(osuCrypto::block) * 2 * baseSend.size());

	co_await (baseOTs.send(baseSend, prng0, chl, 1));

	recv.setBaseOts(baseSend);

	co_await (recv.receive(choices, recvMsg, prng0, chl));
}

OSNSender::OSNSender(size_t size, int ot_type) : size(size), ot_type(ot_type)
{
}

// WJ
void OSNSender::init_wj(size_t size, int ot_type, const std::string &osn_cache, std::map<int, int> &i2locptr)
{
	this->size = size;
	this->ot_type = ot_type;

	int values = size;
	int N = int(ceil(log2(values)));
	int levels = 2 * N - 1;
	oc::Timer mTimer_init;
	dest.resize(size);
	benes.initialize(values, levels);
	std::vector<int> src(values);

	for (auto i = 0u; i < src.size(); ++i)
		src[i] = dest[i] = i;

	osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // we need to modify this seed

	for (int i = size - 1; i > 0; i--)
	{
		int loc = prng.get<uint64_t>() % (i + 1); //  pick random location in the array
		std::swap(dest[i], dest[loc]);
		(i2locptr).insert({dest[i], i});
	}
	(i2locptr).insert({dest[0], 0});

	if (osn_cache != "")
	{
		string file = "./benes/" + osn_cache + "_" + to_string(size);
		if (!benes.load(file))
		{
			benes.gen_benes_route(N, 0, 0, src, dest);
			benes.dump(file);
		}
		else
		{
			cout << "OSNSender is using osn cache for size " + size << endl;
		}
	}
	else
	{
		benes.gen_benes_route(N, 0, 0, src, dest);
	}
}

// WJ: test performance of osn unit
std::vector<int> OSNSender::getmyPi(const std::map<int, int> &i2loc, const std::vector<u64> &intersection)
{
	std::vector<int> myPi;
	for (u64 i = 0; i < intersection.size(); i++) // WJ: generate myPi to contain the positions where the intersections locate
	{
		auto iter = i2loc.find(intersection[i]);
		if (iter != i2loc.end())
		{

			myPi.push_back(iter->second);
		}
		else
		{

			std::cout << "i2loc misses an intersection" << std::endl;
		}
	}
	mPi = myPi;
	return myPi;
}