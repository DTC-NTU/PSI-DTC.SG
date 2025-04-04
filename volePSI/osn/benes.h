#pragma once

#include <vector>

#include <cryptoTools/Common/BitVector.h>

// © 2025 Digital Trust Centre - Nanyang Technological University. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

class Benes
{
	std::vector<int> perm;
	std::vector<int> inv_perm;
	std::vector<std::vector<int>> switched;
	std::vector<char> path;

	void DFS(int idx, int route);

	void gen_benes_eval(int n, int lvl_p, int perm_idx, std::vector<uint64_t> &src);

public:
	bool dump(const std::string &filename);

	bool load(const std::string &filename);

	void initialize(int values, int levels);

	void gen_benes_route(int n, int lvl_p, int perm_idx, const std::vector<int> &src,
						 const std::vector<int> &dest);

	void gen_benes_eval(int n, int lvl_p, int perm_idx, std::vector<oc::block> &src);

	void gen_benes_masked_evaluate(int n, int lvl_p, int perm_idx, std::vector<oc::block> &src,
								   std::vector<std::vector<std::array<osuCrypto::block, 2>>> &ot_output);

	osuCrypto::BitVector return_gen_benes_switches(int values);
};