#include "fileBased.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "RsPsi.h"

#include "coproto/Socket/AsioSocket.h"

namespace volePSI
{
    const std::string WHITESPACE = " \n\r\t\f\v";

    std::ifstream::pos_type filesize(std::ifstream &file)
    {
        auto pos = file.tellg();
        file.seekg(0, std::ios_base::end);
        auto size = file.tellg();
        file.seekg(pos, std::ios_base::beg);
        return size;
    }

    bool hasSuffix(std::string const &value, std::string const &ending)
    {
        if (ending.size() > value.size())
            return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    bool isHexBlock(const std::string &buff)
    {
        if (buff.size() != 32)
            return false;
        auto ret = true;
        for (u64 i = 0; i < 32; ++i)
            ret &= (bool)std::isxdigit(buff[i]);
        return ret;
    }

    block hexToBlock(const std::string &buff)
    {
        assert(buff.size() == 32);

        std::array<u8, 16> vv;
        char b[3];
        b[2] = 0;

        for (u64 i = 0; i < 16; ++i)
        {
            b[0] = buff[2 * i + 0];
            b[1] = buff[2 * i + 1];
            vv[15 - i] = (char)strtol(b, nullptr, 16);
            ;
        }
        return oc::toBlock(vv.data());
    }
    // TKL
    std::string blockToString(const block &block)
    {
        std::stringstream ss;
        // ss << std::hex << std::setfill('0');
        ss << block;
        return ss.str();
    }

    // Function to convert a string to hexadecimal
    std::string stringToHex(const std::string &input)
    {
        assert(input.size() < 17); // support up to 32 hex char only, max is 16 char string
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(32);
        ss << std::hex << std::uppercase;
        for (char c : input)
        {
            ss << static_cast<int>(c);
        }
        std::string s1 = ss.str().substr(ss.str().size() - 32);
        return s1;
    }

    std::string ltrim(const std::string &s)
    {
        size_t start = s.find_first_not_of(WHITESPACE);
        return (start == std::string::npos) ? "" : s.substr(start);
    }

    std::string rtrim(const std::string &s)
    {
        size_t end = s.find_last_not_of(WHITESPACE);
        return (end == std::string::npos) ? "" : s.substr(0, end + 1);
    }

    // Function to convert a hexadecimal string to its original string representation
    std::string hexToString(const std::string &hexString)
    {
        std::string result;

        for (size_t i = 0; i < hexString.length(); i += 2)
        {
            // Extract a pair of characters from the hex string
            std::string hexPair = hexString.substr(i, 2);

            // Convert the hex pair to an integer
            unsigned int asciiValue;
            std::istringstream(hexPair) >> std::hex >> asciiValue;

            // Append the corresponding ASCII character to the result
            // Replace null characters with a space
            result += (asciiValue != 0) ? static_cast<unsigned char>(asciiValue) : ' ';
        }

        return rtrim(ltrim(result));
    }

    std::vector<std::vector<std::string>> readCSVFile(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            std::cerr << "Error opening file: " << filename << std::endl;
            return {}; // Return an empty vector if the file cannot be opened
        }

        std::vector<std::vector<std::string>> columns;
        std::string line;

        while (std::getline(file, line))
        {
            std::stringstream ss(line);
            std::string field;
            size_t columnIndex = 0;

            while (std::getline(ss, field, ','))
            {
                // Resize the vector if necessary
                if (columnIndex >= columns.size())
                {
                    columns.resize(columnIndex + 1);
                }
                field.erase(std::remove(field.begin(), field.end(), '\r'), field.end());
                field.erase(std::remove(field.begin(), field.end(), '\n'), field.end());
                columns[columnIndex].push_back(field);
                columnIndex++;
            }
        }

        file.close();
        return columns;
    }

    std::vector<std::vector<block>> readSet(const std::string &path, FileType ft, bool debug, bool bHashIt) // TKL
    {
        std::vector<block> retIndex;
        std::vector<std::vector<block>> ret;
        if (ft == FileType::Bin)
        {
            std::ifstream file(path, std::ios::binary | std::ios::in);
            if (file.is_open() == false)
                throw std::runtime_error("failed to open file: " + path);
            auto size = filesize(file);
            if (size % 16)
                throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

            retIndex.resize(size / 16);
            file.read((char *)retIndex.data(), size);
            ret.push_back(retIndex);
        }
        else if (ft == FileType::Csv)
        {
            // we will use this to hash large inputs
            oc::RandomOracle hash(sizeof(block));

            std::vector<std::vector<std::string>> data = readCSVFile(path);

            // Process column 1 (index column) differently
            if (data.size() > 0)
                for (const auto &buffer : data[0])
                {
                    // if the input is already a 32 char hex
                    // value, just parse it as is.
                    if (isHexBlock(buffer))
                    {
                        retIndex.push_back(hexToBlock(buffer));
                    }
                    else if (!bHashIt)
                    {
                        std::string hexStr = stringToHex(buffer);
                        block blk = hexToBlock(hexStr);
                        // std::string s = blockToString(blk);
                        retIndex.push_back(blk);
                    }
                    else
                    {
                        retIndex.emplace_back();
                        hash.Reset();
                        hash.Update(buffer.data(), buffer.size());
                        hash.Final(retIndex.back());
                    }
                }
            ret.push_back(retIndex);
            // Process other columns
            if (data.size() > 1)
                for (auto k = 1u; k < data.size(); k++)
                {
                    std::vector<block> retPayload;
                    auto column = data[k];
                    for (const auto &buffer : column)
                    {
                        if (isHexBlock(buffer))
                        {
                            retPayload.push_back(hexToBlock(buffer));
                        }
                        else
                        {
                            std::string hexStr = stringToHex(buffer);
                            block blk = hexToBlock(hexStr);
                            // std::string s = blockToString(blk);
                            retPayload.push_back(blk);
                        }
                    }
                    ret.push_back(retPayload);
                    retPayload.clear();
                }
        }
        else
        {
            throw std::runtime_error("unknown file type");
        }

        if (debug)
        {
            u64 maxPrint = 40;
            std::unordered_map<block, u64> hashes;
            for (u64 i = 0; i < retIndex.size(); ++i)
            {
                auto r = hashes.insert({retIndex[i], i});
                if (r.second == false)
                {
                    std::cout << "duplicate at index " << i << " & " << r.first->second << std::endl;
                    --maxPrint;

                    if (!maxPrint)
                        break;
                }
            }
            if (maxPrint != 40)
                throw RTE_LOC;
        }

        return ret;
    }

    template <typename InputIterator>
    void counting_sort(InputIterator first, InputIterator last, u64 endIndex)
    {
        using ValueType = typename std::iterator_traits<InputIterator>::value_type;
        std::vector<u64> counts(endIndex);

        for (auto value = first; value < last; ++value)
        {
            ++counts[*value];
        }

        for (u64 i = 0; i < counts.size(); ++i)
        {
            ValueType &value = i;
            u64 &size = counts[i];
            std::fill_n(first, size, value);
            std::advance(first, size);
        }
    }

    void doFileSpHshPSIwithOSN(const oc::CLP &cmd)
    {
        try
        {
            oc::Timer timer;
            auto protoBegin = timer.setTimePoint("PSI+OSN begin");

            auto path = cmd.getOr<std::string>("SpHsh", ""); // shs -SpHsh .dataset/cleartext.csv
            // auto outPath = cmd.getOr<std::string>("out", path + ".out");
            std::string outPath = path;
            std::string prefix = "./dataset/";
            std::string outprefix = "Out";
            size_t pos = outPath.rfind(prefix);
            if (pos != std::string::npos)
            {
                outPath = outPath.insert(pos + prefix.length(), outprefix);
            }
            //            auto outPath = cmd.getOr<std::string>("out", path); // JW: remove suffix .out
            bool debug = cmd.isSet("debug");
            bool quiet = cmd.isSet("quiet");
            bool verbose = cmd.isSet("v");

            FileType ft = FileType::Unspecified;
            if (cmd.isSet("csv"))
                ft = FileType::Csv;
            if (ft == FileType::Unspecified)
            {
                if (hasSuffix(path, ".csv"))
                    ft = FileType::Csv;
            }
            if (ft == FileType::Unspecified)
                throw std::runtime_error("unknown file extension, must be .csv or you must specify the or -csv flags.");
            auto bHashIt = cmd.getOr<int>("hash", 1); // TKL hash dataset when read and write
            auto ip1 = cmd.getOr<std::string>("ip", "localhost:1212");
            auto ip2 = cmd.getOr<std::string>("ip1", "localhost:1213");
            auto ip3 = cmd.getOr<std::string>("ip2", "localhost:1214");
            auto r = (Role)cmd.getOr<int>("r", 2);
            if (r != Role::Sender && r != Role::Receiver && r != Role::Server)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver) or 2 (server).");

            bool isServer = false;
            if (r != Role::Sender && r != Role::Receiver && r != Role::Server)
                throw std::runtime_error("-server tag must be set with value 0, 1 or 2.");
            //            oc::Timer timer;

            bool isPSIServer = false;
            if (r == Role::Server)
            {
                isPSIServer = false;
                isServer = true;
            }
            else if (r == Role::Receiver)
            {
                isPSIServer = true;
                isServer = false;
            }
            else
            {
                isPSIServer = false;
                isServer = false;
            }
            if (!quiet)
            {
                if (isServer)
                {
                    ;
                }
                else
                {
                    if (isPSIServer)
                    {
                        std::cout << "\nAlice:" << std::endl;
                    }
                    else
                    {
                        std::cout << "\nBob: " << std::endl;
                    }
                }
            }
            std::vector<block> set;
            std::vector<std::vector<block>> dataset;
            bool withPayload = false;

            if (!isServer)
            {

                auto readBegin = timer.setTimePoint("");
                std::cout << path << std::endl;
                dataset = readSet(path, ft, debug, bHashIt);
                set = dataset[0];
                if (dataset.size() > 1)
                    withPayload = true; // TKL flag for payload
                auto readEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << "reading input file takes " << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << " ms" << std::endl;
            }
            coproto::Socket chl;
            coproto::Socket ch2;
            coproto::Socket ch3;
            auto connBegin = timer.setTimePoint("");
#ifdef COPROTO_ENABLE_BOOST
            if (isServer)
            { // is SHS
                ch2 = coproto::asioConnect(ip2, isServer);
                ch3 = coproto::asioConnect(ip3, isServer);
            }
            else if (isPSIServer)
            { // is Alice
                chl = coproto::asioConnect(ip1, isPSIServer);
                ch2 = coproto::asioConnect(ip2, isServer);
            }
            else
            { // is Bob
                chl = coproto::asioConnect(ip1, isPSIServer);
                ch3 = coproto::asioConnect(ip3, isServer);
            }
#else
            throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
#endif
            auto connEnd = timer.setTimePoint("");
            if ((!quiet) && (!isServer))
                std::cout << "Establishing connection takes " << std::chrono::duration_cast<std::chrono::milliseconds>(connEnd - connBegin).count()
                          << " ms,\nstart to run secure inner join... " << std::flush;
            if (r == Role::Sender)
            {
                RsPsi3rdPSenderB sender;
                std::vector<block> sendSet_sharesB;
                std::vector<block> recvSet_sharesB;
                std::vector<block> interShareB2SHS;
                macoro::sync_wait(sender.runSpHshPsiOsn(chl, ch3, set, (withPayload ? dataset[1] : set)));

                sendSet_sharesB = sender.getReceiver_shares();
                recvSet_sharesB = sender.getSenderA_shares();

                // WJ: write PL shares into output file.
                auto myPiB = sender.getmyPi();
                if (myPiB.size() != recvSet_sharesB.size())
                    throw std::runtime_error("Mismatch between myPi size and Bob's inter shares' size!");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0u; i < myPiB.size(); i++)
                {
                    //*to write SenderB's Payload*//
                    auto j1 = myPiB[i];
                    auto tmpPL1 = sendSet_sharesB[j1];
                    interShareB2SHS.push_back(tmpPL1);
                    std::string ss1 = blockToString(tmpPL1);

                    //*to recover SenderA's Payload*//
                    block tmpPL2 = recvSet_sharesB[i];
                    std::string ss2 = blockToString(tmpPL2);

                    outFile << ss2 << "," << ss1 << "\n"; // Write each string followed by a newline
                }
                outFile.close();
                // TKL just for testing
                macoro::sync_wait(ch3.send(interShareB2SHS)); // sent its share to neutral
                macoro::sync_wait(chl.flush());
                macoro::sync_wait(ch3.flush());
                if (verbose)
                {
                    std::cout << "sendSet_sharesB size= " << sendSet_sharesB.size() << std::endl;
                    std::cout << "recvSet_sharesB size=" << recvSet_sharesB.size() << std::endl;
                }
            }
            else if (r == Role::Receiver)
            {
                RsPsi3rdPSenderA recver;
                std::vector<block> sendSet_sharesA;
                std::vector<block> recvSet_sharesA;
                std::vector<block> interShareA2SHS;
                macoro::sync_wait(recver.runSpHshPsiOsn(chl, ch2, set, (withPayload ? dataset[1] : set)));

                recvSet_sharesA = recver.getReceiver_shares(); // share of Sender A's payload derived by OSN
                sendSet_sharesA = recver.getSenderB_shares();  // share of Sender B's payload sentby SHS

                // WJ: write PL shares into output file.
                auto myPiA = recver.getmyPi();
                if (myPiA.size() != sendSet_sharesA.size())
                    throw std::runtime_error("Mismatch between myPi size and Bob's inter shares' size!");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0u; i < myPiA.size(); i++)
                {
                    //*to write SenderA's Payload*//
                    auto j1 = myPiA[i];
                    auto tmpPL1 = recvSet_sharesA[j1];
                    interShareA2SHS.push_back(tmpPL1);
                    std::string ss1 = blockToString(tmpPL1);

                    //*to recover SenderB's Payload*//
                    block tmpPL2 = sendSet_sharesA[i];
                    std::string ss2 = blockToString(tmpPL2);

                    outFile << ss1 << "," << ss2 << "\n"; // Write each string followed by a newline
                }
                outFile.close();
                // TKL just for testing
                macoro::sync_wait(ch2.send(interShareA2SHS)); // sent its share to neutral
                macoro::sync_wait(chl.flush());
                macoro::sync_wait(ch2.flush());

                if (verbose)
                {
                    //    std::cout << "\n Intesection_size = " << cardinality << std::endl;
                    std::cout << "recvSet_sharesA size= " << recvSet_sharesA.size() << std::endl;
                    std::cout << "sendSet_sharesA size=" << sendSet_sharesA.size() << std::endl;
                }
            }
            else
            {
                RsPsi3rdPReceiver server;

                std::vector<block> mSenderA_shares;
                std::vector<block> mSenderB_shares;
                macoro::sync_wait(server.runSpHshPsiOsn(ch3, ch2));

                auto protoEnd = timer.setTimePoint("");
                if (!quiet)
                {
                    std::cout << "\nOverall time overhead is " << std::chrono::duration_cast<std::chrono::milliseconds>(protoEnd - protoBegin).count() << " ms,\n";
                    std::cout << "Overall communication overhead is " << ch3.bytesSent() + ch3.bytesReceived() << " Bytes, " << std::endl;
                }

                mSenderA_shares = server.getSenderA_shares();
                mSenderB_shares = server.getSenderB_shares();
                // TKL just for testing
                std::vector<block> mSenderA_Ownshares;
                std::vector<block> mSenderB_Ownshares;
                mSenderA_Ownshares.resize(server.getCardinality());
                mSenderB_Ownshares.resize(server.getCardinality());
                macoro::sync_wait(ch2.recv(mSenderA_Ownshares)); // recv senderA's own shares
                macoro::sync_wait(ch3.recv(mSenderB_Ownshares)); // recv senderB's own shares

                macoro::sync_wait(ch2.flush());
                macoro::sync_wait(ch3.flush());

                std::vector<int> myPi_A = server.getMyPi_A();
                std::vector<int> myPi_B = server.getMyPi_B();

                if (myPi_A.size() != myPi_B.size())
                    throw std::runtime_error("Mismatch between myPi_A and myPi_B !");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0u; i < myPi_A.size(); i++)
                {
                    //*to recover SenderA's Payload*//
                    auto j1 = myPi_A[i];
                    auto tmpPL1 = mSenderA_shares[j1] ^ mSenderA_Ownshares[i];

                    std::string ss1 = hexToString(blockToString(tmpPL1));

                    //*to recover SenderB's Payload*//
                    auto j2 = myPi_B[i];
                    block tmpPL2 = mSenderB_shares[j2] ^ mSenderB_Ownshares[i];

                    std::string ss2 = hexToString(blockToString(tmpPL2)); // 24/03/2025 jwang

                    outFile << ss1 << "," << ss2 << "\n"; // Write each string followed by a newline
                }
                outFile.close();
                if (verbose)
                {
                    std::cout << "SHS :" << std::endl;
                    std::cout << "\n Intesection_size A = " << server.getmIntersectionA().size() << std::endl;
                    std::cout << "\n Intesection_size B = " << server.getmIntersectionB().size() << std::endl;
                }
            }
        }
        catch (std::exception &e)
        {
            std::cout << oc::Color::Red << "Exception:: " << e.what() << std::endl
                      << oc::Color::Default;
            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }

    // WJ: test bulk data transmision

    void Alice(std::string &ip, std::vector<block> &data)
    {
        coproto::Socket chl;
        chl = coproto::asioConnect(ip, true);
        std::cout << "Alice: Connection established." << std::endl;
        int size = 0;
        macoro::sync_wait(chl.recv(size));
        data.resize(size);
        macoro::sync_wait(chl.recv(data));
        macoro::sync_wait(chl.flush());
        std::cout << "received  data : \n"
                  << std::flush;
    }
    void Bob(std::string &ip, std::vector<block> &data)
    {
        coproto::Socket chl;
        chl = coproto::asioConnect(ip, false);
        std::cout << "Bob: Connection established." << std::endl;
        int size = data.size();
        macoro::sync_wait(chl.send(size));
        macoro::sync_wait(chl.send(std::move(data)));
        macoro::sync_wait(chl.flush());
    }

}