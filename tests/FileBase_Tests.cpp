#include "FileBase_Tests.h"

#include "volePSI/fileBased.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "coproto/Socket/AsioSocket.h"
#include "volePSI/RsPsi.h"

using namespace oc;
using namespace volePSI;

template<typename T>
std::vector<u64> setItersect(std::vector<T>& v, std::vector<T>& sub)
{
	std::unordered_set<T> ss(sub.begin(), sub.end());

	std::vector<u64> r;
	for (u64 i = 0; i < v.size(); ++i)
	{
		if (ss.find(v[i]) != ss.end())
			r.push_back(i);
	}

	return r;
}

void writeFileWthPayload(std::string path, u64 step, u64 size, FileType ft, std::string prefix)
{
	std::ofstream o;
	std::vector<std::vector<std::string>> r(2); //r.reserve(size);
	std::string strprefix = prefix; 
//	std::string hexStr = stringToHex(strprefix);
//    block blk = hexToBlock(hexStr);
	std::string tmpstr1="";
	std::string tmpstr2="";
	std::string substr="";

 	if (ft == FileType::Csv)
	{
		o.open(path, std::ios::trunc);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = i * step;
			block b(v, v);
			tmpstr1 = blockToString(b);
			substr = tmpstr1.substr(12, 4);
			tmpstr2 = strprefix + substr;
			//std::cout << tmpstr1<< ' ' << tmpstr2 << std::endl;
			r[0].push_back(tmpstr1); 
			r[1].push_back(tmpstr2); 
			//std::cout<< "passed push back" << std::endl;
			o << tmpstr1 << "," << tmpstr2 << ",\n";
		}
	}
	else
	{
		throw RTE_LOC;
	} 
}
void csvreadwrite_test()//WJ: read write csv test
{
	unsigned long n =1048576;
	std::string nstr = std::to_string(n);//1048576;

	auto ft = FileType::Csv;
//	std::string sFile = "./dataset/readwriteTest.csv";
/* 	std::string str = "attributeA";
	std::string strhex = stringToHex(str);
	std::cout << strhex << std::endl;
	std::string hexstr = hexToString(strhex);
	std::cout << hexstr << std::endl; */

	std::string suffix = ".csv";
	std::string sFile = "./dataset/sFileOsnPL_.csv";
	auto pos = sFile.rfind(suffix);
	if(pos != std::string::npos)
		sFile.insert(pos, nstr);
	writeFileWthPayload(sFile, 1, n, ft, "BB");

	std::string rFile = "./dataset/rFileOsnPL_.csv";
	auto pos2 = rFile.rfind(suffix);
	if(pos2 != std::string::npos)
		rFile.insert(pos2, nstr);
	writeFileWthPayload(rFile, 2, n, ft, "AA");

/*		std::vector<std::vector<block>> dataset;
	dataset = readSet(sFile, ft, 0, 0);
	// Print the contents
    for (const auto& inner_vector : dataset) {
        for (const auto& element : inner_vector) {
            std::cout << element << " ";
        }
        std::cout << std::endl;
    }
*/
}
std::vector<block> writeFile(std::string path, u64 step, u64 size, FileType ft)
{
	std::ofstream o;
	std::vector<block> r; r.reserve(size);
	if (ft == FileType::Bin)
	{
		o.open(path, std::ios::trunc | std::ios::binary);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = i * step;
			block b(v, v);
			r.push_back(b);
			o.write((char*)&b, 16);
		}
	}
	else if(ft == FileType::Csv)
	{
		o.open(path, std::ios::trunc);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = i * step;
			block b(v, v);
			r.push_back(b);
			o << b << "\n";
		}
	}
	else
	{
		o.open(path, std::ios::trunc);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = "prefix_" + std::to_string(i * step) + "\n";

			oc::RandomOracle ro(16);
			ro.Update(v.data(), v.size());
			block b;
			ro.Final(b);
			r.push_back(b);

			o << v;
		}
	}

	return r;
}

bool checkFile(std::string path,std::vector<u64>& exp, FileType ft)
{

	if (ft == FileType::Bin)
	{
		std::ifstream o;
		o.open(path, std::ios::in | std::ios::binary);
		if (o.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);

		auto size = static_cast<size_t>(filesize(o));
		if (size % sizeof(u64))
			throw RTE_LOC;

		auto s = size / sizeof(u64);
		if (s != exp.size())
			return false;

		std::vector<u64> vals(s);

		o.read((char*)vals.data(), size);

		std::unordered_set<u64> ss(vals.begin(), vals.end());

		if (ss.size() != s)
			throw RTE_LOC;

		for (u64 i = 0; i < exp.size(); ++i)
		{
			if (ss.find(exp[i]) == ss.end())
				return false;
		}
	}
	else 
	{
		std::ifstream file(path, std::ios::in);
		if (file.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);

		std::unordered_set<u64> ss;

		while (file.eof() == false)
		{
			u64 i = -1;
			file >> i;

			if (ss.find(i) != ss.end())
				throw RTE_LOC;
			ss.insert(i);
		}

		for (u64 i = 0; i < exp.size(); ++i)
		{
			if (ss.find(exp[i]) == ss.end())
				return false;
		}
	}

	return true;
}


void filebase_readSet_Test()//WJ : changed 
{
	u64 ns = 1048576;//1048576;
	auto ft = FileType::Csv;
	std::string sFile = "./dataset/sFile_deleteMe.csv";
	auto s = writeFile(sFile, 1, ns, ft);

	auto s2 = readSetOrig(sFile, ft, true);  // WJ, original readSet
	auto s3 = readSet(sFile, ft, true)[0];  // TKL index column

	if (s != s2 || s !=s3)
		throw RTE_LOC;
}

void filebase_psi_bin_Test()
{
#if defined(COPROTO_ENABLE_BOOST) 

	u64 ns = 3124;
	u64 nr = 12352;
	auto ft = FileType::Bin;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("indexSet");
	rCmd.set("indexSet");
	sCmd.set("quiet");
	rCmd.set("quiet");

	sCmd.set("bin");
	rCmd.set("bin");

	sCmd.set("debug");
	rCmd.set("debug");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);
	
	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;

#endif
}

void filebase_psi_csv_Test()
{
#if defined(COPROTO_ENABLE_BOOST) 

	u64 ns = 1024;
	u64 nr = 1024;
	auto ft = FileType::Csv;

	std::string sFile = "./dataset/sFile.csv";
	std::string rFile = "./dataset/rFile.csv";
	std::string oFile = "./dataset/oFile.csv";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("indexSet");
	rCmd.set("indexSet");
//	sCmd.set("quiet");
//	rCmd.set("quiet");

	sCmd.set("csv");
	rCmd.set("csv");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	//std::remove(sFile.c_str());
	//std::remove(rFile.c_str());
	//std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;
#endif
}


void filebase_psi_csvh_Test()
{
#if defined(COPROTO_ENABLE_BOOST) 

	u64 ns = 1048576;
	u64 nr = 1048576;
	auto ft = FileType::Unspecified;

	std::string sFile = "./dataset/sFile_deleteMe.csv";
	std::string rFile = "./dataset/rFile_deleteMe.csv";
	std::string oFile = "./dataset/oFile_deleteMe.csv";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("csv");
	rCmd.set("csv");

	sCmd.set("indexSet");
	rCmd.set("indexSet");
	sCmd.set("quiet");
	rCmd.set("quiet");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, FileType::Csv);
	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;

#endif
}

void filebase_SpHshPsi_csv_osn_Test()
{
#if defined(COPROTO_ENABLE_BOOST)
        u64 ns = 16384;//1048576;//64;;
        u64 nr = 16384;//1048576;//64;;
        auto ft = FileType::Csv;
        std::string sFile = "./dataset/sFileOsn_deleteMe.csv";
        std::string rFile = "./dataset/rFileOsn_deleteMe.csv";
        std::string oFile = "./dataset/oFileOsn_deleteMe.csv";

		auto s = writeFile(sFile, 1, ns, ft);
        auto r = writeFile(rFile, 2, nr, ft);
        auto i = setItersect(s, r);

		CLP sCmd, rCmd, shsCmd;
        sCmd.setDefault("SpHsh", sFile);
        rCmd.setDefault("SpHsh", rFile);
        shsCmd.setDefault("SpHsh", rFile);
		shsCmd.setDefault("out", oFile);

		sCmd.setDefault("r", "0");
        rCmd.setDefault("r", "1");
        shsCmd.setDefault("r", "2");

		sCmd.setDefault("hash", "0");
        rCmd.setDefault("hash", "0");
        shsCmd.setDefault("hash", "0");

		shsCmd.set("indexSet");

    //    sCmd.set("quiet");
    //    rCmd.set("quiet");
    //    shsCmd.set("quiet");
	//	sCmd.set("v");
	//	rCmd.set("v");
	//	shsCmd.set("v");
        sCmd.set("csv");
        rCmd.set("csv");
        shsCmd.set("csv");

		auto f0 = std::async([&]() { doFileSpHshPSIwithOSN(sCmd); });
        auto f1 = std::async([&]() { doFileSpHshPSIwithOSN(rCmd); });
        auto f2 = std::async([&]() { doFileSpHshPSIwithOSN(shsCmd); });
        f0.get();
        f1.get();
        f2.get();
        bool passed = checkFile(oFile, i, ft);
//        std::remove(sFile.c_str());
//        std::remove(rFile.c_str());
//        std::remove(oFile.c_str());
        if (!passed)
                throw RTE_LOC;
#endif
}
	
 void filebase_psi_csv_osn_Test()
{
#if defined(COPROTO_ENABLE_BOOST)
        u64 ns = 64;//3423411;
        u64 nr = 64;//2435611;
        auto ft = FileType::Csv;
        std::string sFile = "./dataset/sFileOsn_deleteMe.csv";
        std::string rFile = "./dataset/rFileOsn_deleteMe.csv";
        std::string oFile = "./dataset/oFileOsn_deleteMe.csv";

        auto s = writeFile(sFile, 1, ns, ft);
        auto r = writeFile(rFile, 2, nr, ft);
        auto i = setItersect(s, r);


        CLP sCmd, rCmd, shsCmd;
        sCmd.setDefault("osn", sFile);
        rCmd.setDefault("osn", rFile);
        shsCmd.setDefault("osn", rFile);
        // sCmd.setDefault("server", "0");
        // rCmd.setDefault("server", "1");
        //auto s2 = readSet(dFile, ft, true)[0];  // TKL index column
        sCmd.setDefault("r", "0");
        rCmd.setDefault("r", "1");
        shsCmd.setDefault("r", "2");
        // sCmd.set("v");
        // rCmd.set("v");
        // shsCmd.set("v");
        sCmd.setDefault("vo", "0");
        rCmd.setDefault("vo", "0");
        shsCmd.setDefault("vo", "0");
        sCmd.setDefault("hash", "0");
        rCmd.setDefault("hash", "0");
        shsCmd.setDefault("hash", "0");
//        sCmd.set("indexSet");
//        rCmd.set("indexSet");
        shsCmd.set("indexSet");
        sCmd.set("quiet");
        rCmd.set("quiet");
        shsCmd.set("quiet");
        sCmd.set("csv");
        rCmd.set("csv");
        shsCmd.set("csv");
        sCmd.setDefault("senderSize", ns);
//        rCmd.setDefault("senderSize", ns);
//        shsCmd.setDefault("senderSize", ns);
//        sCmd.setDefault("receiverSize", nr);
        rCmd.setDefault("receiverSize", nr);
//        shsCmd.setDefault("receiverSize",nr);
        rCmd.setDefault("osn", rFile);
        sCmd.setDefault("osn", sFile);
        shsCmd.setDefault("osn", rFile);
        //rCmd.setDefault("out", oFile);
        shsCmd.setDefault("out", oFile);
		
        auto f0 = std::async([&]() { doFilePSIwithOSN(sCmd); });
        auto f1 = std::async([&]() { doFilePSIwithOSN(rCmd); });
        auto f2 = std::async([&]() { doFilePSIwithOSN(shsCmd); });
        f0.get();
        f1.get();
        f2.get();
        bool passed = checkFile(oFile, i, ft);
//        std::remove(sFile.c_str());
//        std::remove(rFile.c_str());
//        std::remove(oFile.c_str());
        if (!passed)
                throw RTE_LOC;
#endif
} 

//WJ: test bulk data transmision
std::vector<block> generateItems(int size, int step)
{
	std::vector<block> r; 
	for (u64 i = 0; i < size; ++i)
	{
		auto v = i * step;
		block b(v, v);
		r.push_back(b);
	}
	return r;
}
bool checkTransfer(std::vector<block>& sent, std::vector<block>& recved, int size)
{
	std::cout << "sent size: " <<sent.size() << ", ";
	std::cout << "recved size: " << recved.size() << std::endl;
	if (sent.size()!=size || recved.size()!=size)
	{
		throw RTE_LOC;		
	}
	else
	{
		std::unordered_set<block> ss(sent.begin(), sent.end());
		for (int i ; i < recved.size() ; i++)
		{	
			if (ss.find(recved[i]) == ss.end())
			{
				return false;
			}		
		}
		return true;
	}		
}
void bulkdata_transfer_Test()
{		
	std::string ip = "localhost:1212";
	int size = 1048576;
	int step = 1;
//	std::unique_ptr<u8[]> ptr = std::make_unique<u8[]>(size * sizeof(block));	
//	sent.resize(size * sizeof(block));

	std::vector<block> sent = generateItems(size, step);
	std::vector<block> tmp(sent);
	std::vector<block> recved(size);
//	std::vector<block> recved =	std::vector<block>((block*)ptr.get(), size);
	std::cout << "Bob: items generated." << std::endl;
/*  	for(int i ; i < size ; i++)
	{
		std::cout << "sent[" << i <<"]=" << sent[i] << ", ";
	}  */
	std::cout << std::endl;
    auto f0 = std::async([&]() { Alice(ip, recved); });
    auto f1 = std::async([&]() { Bob(ip, sent); });
    f0.get();
    f1.get();
	auto pass = checkTransfer(tmp,recved, size);
	if (!pass)
	{
		throw RTE_LOC;	/* code */
	}
	
}


