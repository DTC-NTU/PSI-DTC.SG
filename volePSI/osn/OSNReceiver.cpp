#include "OSNReceiver.h"
#include "libOTe/Base/BaseOT.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/AES.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include <cstring>
#include <iostream>

using namespace std;
using namespace oc;

task<> OSNReceiver::rand_ot_send(std::vector<std::array<osuCrypto::block, 2>> &sendMsg, Socket &chl)
{
	// std::cout << "\n OT sender!! \n";

	auto prng1 = osuCrypto::PRNG(_mm_set_epi32(4253233465, 334565, 0, 235));
	auto baseRecv = std::vector<osuCrypto::block>{};
	auto baseChoice = osuCrypto::BitVector{};
	auto baseOTs = osuCrypto::DefaultBaseOT();
	auto sender = std::move(osuCrypto::IknpOtExtSender{});

	baseRecv.resize(128);
	baseChoice.resize(128);
	baseChoice.randomize(prng1);

	co_await (baseOTs.receive(baseChoice, baseRecv, prng1, chl, 1));
	sender.setBaseOts(baseRecv, baseChoice);

	co_await (sender.send(sendMsg, prng1, chl));
}

// TKL workaround for SilentOtExtReceiver deleted constructor function error
osuCrypto::SilentOtExtSender &OSNReceiver::getSilentOtExtSender(osuCrypto::u64 numOTs)
{
	osuCrypto::SilentOtExtSender sender;
	sender.configure(numOTs);
	return sender;
}

task<> OSNReceiver::silent_ot_send(std::vector<std::array<osuCrypto::block, 2>> &sendMsg, Socket &chl)
{
	auto prng1 = osuCrypto::PRNG(_mm_set_epi32(4253233465, 334565, 0, 235));
	auto numOTs = 0;
	co_await (getSilentOtExtSender(numOTs).silentSend(sendMsg, prng1, chl));
}

task<> OSNReceiver::gen_benes_client_osn(int values, Socket &chl, std::vector<std::vector<block>> &ret_masks)
{
	AES aes(ZeroBlock);
	int N = 0, levels = 0, switches = 0;
	auto temp = block{};
	auto masks = std::vector<block>{};
	auto prng = osuCrypto::PRNG(_mm_set_epi32(4253233465, 334565, 0, 235));
	auto tmp_messages = std::vector<std::array<osuCrypto::block, 2>>{};
	auto ot_messages = std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>{};
	auto bit_correction = osuCrypto::BitVector{};
	auto correction_blocks = std::vector<std::array<osuCrypto::block, 2>>{};
	N = int(ceil(log2(values)));
	levels = 2 * N - 1;
	switches = levels * (values / 2);

	ret_masks.resize(values);
	masks.resize(values);
	for (int j = 0; j < values; j++)
	{ // we sample the input masks randomly
		temp = prng.get<block>();
		masks[j] = temp;
		ret_masks[j].push_back(temp);
	}

	ot_messages = std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>(switches);
	// Channel& chl = chls[0];
	if (ot_type == 0)
	{
		tmp_messages = std::vector<std::array<osuCrypto::block, 2>>(switches);
		bit_correction = osuCrypto::BitVector(switches);
		co_await (silent_ot_send(tmp_messages, chl)); // sample random ot blocks

		co_await (chl.recv(bit_correction));
		osuCrypto::block tmp;
		for (auto k = 0u; k < tmp_messages.size(); k++)
		{
			if (bit_correction[k] == 1)
			{
				tmp = tmp_messages[k][0];
				tmp_messages[k][0] = tmp_messages[k][1];
				tmp_messages[k][1] = tmp;
			}
		}
		for (auto i = 0u; i < ot_messages.size(); i++)
		{
			ot_messages[i][0] = {tmp_messages[i][0], aes.ecbEncBlock(tmp_messages[i][0])};
			ot_messages[i][1] = {tmp_messages[i][1], aes.ecbEncBlock(tmp_messages[i][1])};
		}
	}
	else
	{
		tmp_messages = std::vector<std::array<osuCrypto::block, 2>>(switches);
		co_await (rand_ot_send(tmp_messages, chl)); // sample random ot blocks
		for (auto i = 0u; i < ot_messages.size(); i++)
		{
			ot_messages[i][0] = {tmp_messages[i][0], aes.ecbEncBlock(tmp_messages[i][0])};
			ot_messages[i][1] = {tmp_messages[i][1], aes.ecbEncBlock(tmp_messages[i][1])};
		}
	}

	cpus.store(1); // TKL to change!!! chls.size());
	correction_blocks = std::vector<std::array<osuCrypto::block, 2>>(switches);
	prepare_correction(N, values, 0, 0, masks, ot_messages, correction_blocks);

	co_await (chl.send(correction_blocks));

	for (int i = 0; i < values; ++i)
	{
		ret_masks[i].push_back(masks[i]);
	}
}

OSNReceiver::OSNReceiver(size_t size, int ot_type) : size(size), ot_type(ot_type)
{
}

void OSNReceiver::init(size_t size, int ot_type)
{
	this->size = size;
	this->ot_type = ot_type;
}

task<> OSNReceiver::run_osn(oc::span<block> inputs, Socket &chl, std::vector<oc::block> &output_masks)
{
	size_t values = size;
	auto ret_masks = std::vector<std::vector<block>>{};
	auto benes_input = std::vector<block>{};
	co_await (gen_benes_client_osn(values, chl, ret_masks));

	for (auto i = 0u; i < values; ++i)
		ret_masks[i][0] = ret_masks[i][0] ^ inputs[i];
	for (auto i = 0u; i < values; ++i)
		benes_input.push_back(ret_masks[i][0]);

	co_await (chl.send(benes_input));

	for (auto i = 0u; i < values; ++i)
		output_masks.push_back(ret_masks[i][1]);
}

void OSNReceiver::setTimer(Timer &timer)
{
	this->timer = &timer;
}

void OSNReceiver::prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block> &src,
									 std::vector<std::array<std::array<osuCrypto::block, 2>, 2>> &ot_output,
									 std::vector<std::array<osuCrypto::block, 2>> &correction_blocks)
{
	// ot message M0 = m0 ^ w0 || m1 ^ w1
	//  for each switch: top wire m0 w0 - bottom wires m1, w1
	//  M1 = m0 ^ w1 || m1 ^ w0
	int levels = 2 * n - 1, base_idx;
	int values = src.size();
	std::vector<block> bottom1;
	std::vector<block> top1;

	block m0, m1, w0, w1, M0[2], M1[2], corr_mesg[2];
	std::array<oc::block, 2> temp_block;

	if (values == 2)
	{
		if (n == 1)
		{
			base_idx = lvl_p * (Val / 2) + perm_idx;
			m0 = src[0];
			m1 = src[1];
			temp_block = ot_output[base_idx][0];
			memcpy(M0, temp_block.data(), sizeof(M0));
			w0 = M0[0] ^ m0;
			w1 = M0[1] ^ m1;
			temp_block = ot_output[base_idx][1];
			memcpy(M1, temp_block.data(), sizeof(M1));
			corr_mesg[0] = M1[0] ^ m0 ^ w1;
			corr_mesg[1] = M1[1] ^ m1 ^ w0;
			correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
			M1[0] = m0 ^ w1;
			M1[1] = m1 ^ w0;
			ot_output[base_idx][1] = {M1[0], M1[1]};
			src[0] = w0;
			src[1] = w1;
		}
		else
		{
			base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
			m0 = src[0];
			m1 = src[1];
			temp_block = ot_output[base_idx][0];
			memcpy(M0, temp_block.data(), sizeof(M0));
			w0 = M0[0] ^ m0;
			w1 = M0[1] ^ m1;
			temp_block = ot_output[base_idx][1];
			memcpy(M1, temp_block.data(), sizeof(M1));
			corr_mesg[0] = M1[0] ^ m0 ^ w1;
			corr_mesg[1] = M1[1] ^ m1 ^ w0;
			correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
			M1[0] = m0 ^ w1;
			M1[1] = m1 ^ w0;
			ot_output[base_idx][1] = {M1[0], M1[1]};
			src[0] = w0;
			src[1] = w1;
		}
		return;
	}

	if (values == 3)
	{
		base_idx = lvl_p * (Val / 2) + perm_idx;
		m0 = src[0];
		m1 = src[1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		w0 = M0[0] ^ m0;
		w1 = M0[1] ^ m1;
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		corr_mesg[0] = M1[0] ^ m0 ^ w1;
		corr_mesg[1] = M1[1] ^ m1 ^ w0;
		correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
		M1[0] = m0 ^ w1;
		M1[1] = m1 ^ w0;
		ot_output[base_idx][1] = {M1[0], M1[1]};
		src[0] = w0;
		src[1] = w1;

		base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
		m0 = src[1];
		m1 = src[2];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		w0 = M0[0] ^ m0;
		w1 = M0[1] ^ m1;
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		corr_mesg[0] = M1[0] ^ m0 ^ w1;
		corr_mesg[1] = M1[1] ^ m1 ^ w0;
		correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
		M1[0] = m0 ^ w1;
		M1[1] = m1 ^ w0;
		ot_output[base_idx][1] = {M1[0], M1[1]};
		src[1] = w0;
		src[2] = w1;

		base_idx = (lvl_p + 2) * (Val / 2) + perm_idx;
		m0 = src[0];
		m1 = src[1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		w0 = M0[0] ^ m0;
		w1 = M0[1] ^ m1;
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		corr_mesg[0] = M1[0] ^ m0 ^ w1;
		corr_mesg[1] = M1[1] ^ m1 ^ w0;
		correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
		M1[0] = m0 ^ w1;
		M1[1] = m1 ^ w0;
		ot_output[base_idx][1] = {M1[0], M1[1]};
		src[0] = w0;
		src[1] = w1;
		return;
	}

	// partea superioara
	for (int i = 0; i < values - 1; i += 2)
	{
		base_idx = (lvl_p) * (Val / 2) + perm_idx + i / 2;
		m0 = src[i];
		m1 = src[i ^ 1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		w0 = M0[0] ^ m0;
		w1 = M0[1] ^ m1;
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		corr_mesg[0] = M1[0] ^ m0 ^ w1;
		corr_mesg[1] = M1[1] ^ m1 ^ w0;
		correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
		M1[0] = m0 ^ w1;
		M1[1] = m1 ^ w0;
		ot_output[base_idx][1] = {M1[0], M1[1]};
		src[i] = w0;
		src[i ^ 1] = w1;

		bottom1.push_back(src[i]);
		top1.push_back(src[i ^ 1]);
	}

	if (values % 2 == 1)
	{
		top1.push_back(src[values - 1]);
	}

	cpus--;
	thread top_thrd, btm_thrd;
	if (cpus > 0)
	{
		top_thrd = thread(&OSNReceiver::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx + values / 4, std::ref(top1), std::ref(ot_output), std::ref(correction_blocks));
	}
	else
	{
		prepare_correction(n - 1, Val, lvl_p + 1, perm_idx + values / 4, top1, ot_output, correction_blocks);
	}
	if (cpus > 0)
	{
		btm_thrd = thread(&OSNReceiver::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx, std::ref(bottom1), std::ref(ot_output), std::ref(correction_blocks));
	}
	else
	{
		prepare_correction(n - 1, Val, lvl_p + 1, perm_idx, bottom1, ot_output, correction_blocks);
	}
	if (top_thrd.joinable())
		top_thrd.join();
	if (btm_thrd.joinable())
		btm_thrd.join();
	cpus++;

	// partea inferioara
	for (int i = 0; i < values - 1; i += 2)
	{
		base_idx = (lvl_p + levels - 1) * (Val / 2) + perm_idx + i / 2;
		m1 = top1[i / 2];
		m0 = bottom1[i / 2];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		w0 = M0[0] ^ m0;
		w1 = M0[1] ^ m1;
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		corr_mesg[0] = M1[0] ^ m0 ^ w1;
		corr_mesg[1] = M1[1] ^ m1 ^ w0;
		correction_blocks[base_idx] = {corr_mesg[0], corr_mesg[1]};
		M1[0] = m0 ^ w1;
		M1[1] = m1 ^ w0;
		ot_output[base_idx][1] = {M1[0], M1[1]};
		src[i] = w0;
		src[i ^ 1] = w1;
	}

	int idx = int(ceil(values * 0.5));
	if (values % 2 == 1)
	{
		src[values - 1] = top1[idx - 1];
	}
}
