#pragma once
// © 2022 Visa.
// Modified version of original code by Visa
// © 2025 Digital Trust Centre - Nanyang Technological University. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <fstream>
#include <string>
#include <vector>
#include <assert.h>
#include "Defines.h"
#include "cryptoTools/Common/CLP.h"

namespace volePSI
{

	std::ifstream::pos_type filesize(std::ifstream &file);

	bool hasSuffix(std::string const &value, std::string const &ending);

	bool isHexBlock(const std::string &buff);
	block hexToBlock(const std::string &buff);

	enum class FileType
	{
		Bin,
		Csv,
		Unspecified
	};

	enum class Role
	{
		Sender = 0,
		Receiver = 1,
		Server = 2,
		Invalid
	};
	std::string stringToHex(const std::string &input);
	std::string blockToString(const block &block);																	// WJ
	std::string hexToString(const std::string &hexString);															// WJ
	std::vector<std::vector<block>> readSet(const std::string &path, FileType ft, bool debug, bool bHashIt = true); // TKL

	void doFileSpHshPSIwithOSN(const oc::CLP &cmd);

	inline bool exist(std::string path)
	{
		std::fstream stream;
		stream.open(path.c_str(), std::ios::in);
		return stream.is_open();
	}

	void Alice(std::string &ip, std::vector<block> &data);
	void Bob(std::string &ip, std::vector<block> &data);
}
