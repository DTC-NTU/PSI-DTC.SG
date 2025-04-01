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

    bool isNumber(std::string &s)
    {
        s = rtrim(ltrim(s));
        std::string::const_iterator it = s.begin();
        while (it != s.end() && std::isdigit(*it))
            ++it;
        return !s.empty() && it == s.end();
    }

    bool is_ascii(const char *c, size_t len)
    {
        for (size_t i = 0; i < len; i++)
        {
            if (c[i] < 0)
                return false;
        }
        return true;
    }

    std::string hexBlockToString(const block &hexBlock)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        // Use reinterpret_cast to treat the block as an array of characters
        const unsigned char *bytePtr = reinterpret_cast<const unsigned char *>(&hexBlock);

        // Read each byte and append to the stringstream
        for (size_t i = 0; i < sizeof(hexBlock); ++i)
        {
            ss << std::setw(2) << static_cast<unsigned int>(bytePtr[i]);
        }

        return ss.str();
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
    std::vector<block> readSetOrig(const std::string &path, FileType ft, bool debug) // WJ
    {
        std::vector<block> ret;
        if (ft == FileType::Bin)
        {
            std::ifstream file(path, std::ios::binary | std::ios::in);
            if (file.is_open() == false)
                throw std::runtime_error("failed to open file: " + path);
            auto size = filesize(file);
            if (size % 16)
                throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

            ret.resize(size / 16);
            file.read((char *)ret.data(), size);
        }
        else if (ft == FileType::Csv)
        {
            // we will use this to hash large inputs
            oc::RandomOracle hash(sizeof(block));

            std::ifstream file(path, std::ios::in);
            if (file.is_open() == false)
                throw std::runtime_error("failed to open file: " + path);
            std::string buffer;
            while (std::getline(file, buffer))
            {
                // if the input is already a 32 char hex
                // value, just parse it as is.
                if (isHexBlock(buffer))
                {
                    ret.push_back(hexToBlock(buffer));
                }
                else
                {
                    ret.emplace_back();
                    hash.Reset();
                    hash.Update(buffer.data(), buffer.size());
                    hash.Final(ret.back());
                }
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
            for (u64 i = 0; i < ret.size(); ++i)
            {
                auto r = hashes.insert({ret[i], i});
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
                for (int k = 1; k < data.size(); k++)
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

    void writeOutput(std::string outPath, FileType ft, const std::vector<u64> &intersection, bool indexOnly, std::string inPath, bool bHashIt = true)
    {
        std::ofstream file;

        if (ft == FileType::Bin)
            file.open(outPath, std::ios::out | std::ios::trunc | std::ios::binary);
        else
            file.open(outPath, std::ios::out | std::ios::trunc);

        if (file.is_open() == false)
            throw std::runtime_error("failed to open the output file: " + outPath);

        if (indexOnly)
        {

            if (ft == FileType::Bin)
            {
                file.write((char *)intersection.data(), intersection.size() * sizeof(u64));
            }
            else
            {
                for (auto i : intersection)
                    file << i << "\n";
            }
        }
        else
        {
            // std::set<u64> set(intersection.begin(), intersection.end());
            if (ft == FileType::Bin)
            {
                std::ifstream inFile(inPath, std::ios::binary | std::ios::in);
                if (inFile.is_open() == false)
                    throw std::runtime_error("failed to open file: " + inPath);
                auto size = filesize(inFile);
                if (size % 16)
                    throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

                auto n = size / 16;
                std::vector<block> fData(n);
                inFile.read((char *)fData.data(), size);
                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    file.write((char *)fData[intersection[i]].data(), sizeof(block));
                }
            }
            else if (ft == FileType::Csv)
            {
                // we will use this to hash large inputs
                oc::RandomOracle hash(sizeof(block));

                std::ifstream inFile(inPath, std::ios::in);
                if (inFile.is_open() == false)
                    throw std::runtime_error("failed to open file: " + inPath);

                u64 size = filesize(inFile);
                std::vector<char> fData(size);
                inFile.read(fData.data(), size);

                std::vector<span<char>> beg;
                auto iter = fData.begin();
                for (u64 i = 0; i < size; ++i)
                {
                    if (fData[i] == '\n')
                    {
                        beg.push_back(span<char>(iter, fData.begin() + i));
                        iter = fData.begin() + i + 1;
                        assert(beg.back().size());
                    }
                }

                if (iter != fData.end())
                    beg.push_back(span<char>(iter, fData.end()));

                for (u64 i = 0; i < intersection.size(); ++i)
                {
                    auto w = beg[intersection[i]];
                    if (!bHashIt)
                        file.write(w.data(), w.size());
                    else
                    {
                        hash.Reset();
                        hash.Update(w.data(), w.size());
                        block ww;
                        hash.Final(ww);
                        file << ww;
                    }
                    file << '\n';
                }
            }
            else
            {
                throw std::runtime_error("unknown file type");
            }
        }
    }

    void doFilePSI(const oc::CLP &cmd)
    {
        try
        {

            auto path = cmd.get<std::string>("in");
            auto outPath = cmd.getOr<std::string>("out", path + ".out");
            bool debug = cmd.isSet("debug");
            bool mal = cmd.isSet("malicious");
            bool indexOnly = cmd.isSet("indexSet");
            bool sortOutput = !cmd.isSet("noSort");
            bool tls = cmd.isSet("tls");
            bool quiet = cmd.isSet("quiet");
            bool verbose = cmd.isSet("v");

            block seed;
            if (cmd.hasValue("seed"))
            {
                auto seedStr = cmd.get<std::string>("seed");
                oc::RandomOracle ro(sizeof(block));
                ro.Update(seedStr.data(), seedStr.size());
                ro.Final(seed);
            }
            else
                seed = oc::sysRandomSeed();

            // The vole type, default to expand accumulate.
            auto type = oc::DefaultMultType;
#ifdef ENABLE_INSECURE_SILVER
            type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
#endif
#ifdef ENABLE_BITPOLYMUL
            type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
#endif

            FileType ft = FileType::Unspecified;
            if (cmd.isSet("bin"))
                ft = FileType::Bin;
            if (cmd.isSet("csv"))
                ft = FileType::Csv;
            if (ft == FileType::Unspecified)
            {
                if (hasSuffix(path, ".bin"))
                    ft = FileType::Bin;
                else if (hasSuffix(path, ".csv"))
                    ft = FileType::Csv;
            }
            if (ft == FileType::Unspecified)
                throw std::runtime_error("unknown file extension, must be .csv or .bin or you must specify the -bin or -csv flags.");

            u64 statSetParam = cmd.getOr("ssp", 40);
            auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
            auto r = (Role)cmd.getOr<int>("r", 2);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

            auto isServer = cmd.getOr<int>("server", (int)r);
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-server tag must be set with value 0 or 1.");
            oc::Timer timer;

            if (!quiet)
                std::cout << "reading set... " << std::flush;
            auto readBegin = timer.setTimePoint("");
            std::vector<std::vector<block>> dataset = readSet(path, ft, debug);
            std::vector<block> set = dataset[0];
            auto readEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;

            if (!quiet)
                std::cout << "connecting as " << (tls ? "tls " : "") << (isServer ? "server" : "client") << " at address " << ip << std::flush;
            coproto::Socket chl;
            auto connBegin = timer.setTimePoint("");
            if (tls)
            {
                std::string CACert = cmd.get<std::string>("CA");
                auto privateKey = cmd.get<std::string>("sk");
                auto publicKey = cmd.get<std::string>("pk");

                if (!exist(CACert) || !exist(privateKey) || !exist(privateKey))
                {
                    std::cout << "\n";
                    if (!exist(CACert))
                        std::cout << "CA cert " << CACert << " does not exist" << std::endl;
                    if (!exist(privateKey))
                        std::cout << "private key " << privateKey << " does not exist" << std::endl;
                    if (!exist(publicKey))
                        std::cout << "public key " << publicKey << " does not exist" << std::endl;

                    std::cout << "Please correctly set -CA=<path> -sk=<path> -pk=<path> to the CA cert, user private key "
                              << " and public key respectively." << std::endl;

                    throw std::runtime_error("bad TLS parameter.");
                }

#ifdef COPROTO_ENABLE_OPENSSL
                boost::asio::ssl::context ctx(!isServer ? boost::asio::ssl::context::tlsv13_client : boost::asio::ssl::context::tlsv13_server);

                ctx.set_verify_mode(
                    boost::asio::ssl::verify_peer |
                    boost::asio::ssl::verify_fail_if_no_peer_cert);
                ctx.load_verify_file(CACert);
                ctx.use_private_key_file(privateKey, boost::asio::ssl::context::file_format::pem);
                ctx.use_certificate_file(publicKey, boost::asio::ssl::context::file_format::pem);

                chl = coproto::sync_wait(
                    !isServer ? macoro::make_task(coproto::AsioTlsConnect(ip, coproto::global_io_context(), ctx)) : macoro::make_task(coproto::AsioTlsAcceptor(ip, coproto::global_io_context(), ctx)));
#else
                throw std::runtime_error("COPROTO_ENABLE_OPENSSL must be define (via cmake) to use TLS sockets. " COPROTO_LOCATION);
#endif
            }
            else
            {
#ifdef COPROTO_ENABLE_BOOST
                chl = coproto::asioConnect(ip, isServer);
#else
                throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
#endif
            }
            auto connEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(connEnd - connBegin).count()
                          << "ms\nValidating set sizes... " << std::flush;

            if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                throw std::runtime_error("File does not contain the specified set size.");
            u64 theirSize;
            macoro::sync_wait(chl.send(set.size()));
            macoro::sync_wait(chl.recv(theirSize));

            if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                throw std::runtime_error("Other party's set size does not match.");

            auto valEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(valEnd - connEnd).count()
                          << "ms\nrunning PSI... " << std::flush;

            if (r == Role::Sender)
            {
                RsPsiSender sender;

                sender.mDebug = debug;
                sender.setMultType(type);
                sender.init(set.size(), theirSize, statSetParam, seed, mal, 1);
                macoro::sync_wait(sender.run(set, chl));
                macoro::sync_wait(chl.flush());

                auto psiEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                              << "ms\nDone" << std::endl;
            }
            else
            {
                RsPsiReceiver recver;

                recver.mDebug = debug;
                recver.setMultType(type);
                recver.init(theirSize, set.size(), statSetParam, seed, mal, 1);
                macoro::sync_wait(recver.run(set, chl));
                macoro::sync_wait(chl.flush());

                auto psiEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                              << "ms\nWriting output to " << outPath << std::flush;

                if (sortOutput)
                    counting_sort(recver.mIntersection.begin(), recver.mIntersection.end(), set.size());

                writeOutput(outPath, ft, recver.mIntersection, indexOnly, path);

                auto outEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - psiEnd).count()
                              << "ms\n"
                              << std::flush;

                if (verbose)
                    std::cout << "intesection_size = " << recver.mIntersection.size() << std::endl;
            }
        }
        catch (std::exception &e)
        {
            std::cout << oc::Color::Red << "Exception: " << e.what() << std::endl
                      << oc::Color::Default;

            std::cout << "Try adding command line argument -debug" << std::endl;
        }
    }
    void doFilePSIwithOSN(const oc::CLP &cmd)
    {
        try
        {

            auto path = cmd.getOr<std::string>("osn", "");
            auto outPath = cmd.getOr<std::string>("out", path + ".out");
            bool debug = cmd.isSet("debug");
            bool mal = cmd.isSet("malicious");
            bool indexOnly = cmd.isSet("indexSet");
            bool sortOutput = !cmd.isSet("noSort");
            bool tls = cmd.isSet("tls");
            bool quiet = cmd.isSet("quiet");
            bool verbose = cmd.isSet("v");

            block seed;
            if (cmd.hasValue("seed"))
            {
                auto seedStr = cmd.get<std::string>("seed");
                oc::RandomOracle ro(sizeof(block));
                ro.Update(seedStr.data(), seedStr.size());
                ro.Final(seed);
            }
            else
                seed = oc::sysRandomSeed();

            // The vole type, default to expand accumulate.
            auto type = oc::DefaultMultType;
#ifdef ENABLE_INSECURE_SILVER
            type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
#endif
#ifdef ENABLE_BITPOLYMUL
            type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
#endif

            FileType ft = FileType::Unspecified;
            if (cmd.isSet("bin"))
                ft = FileType::Bin;
            if (cmd.isSet("csv"))
                ft = FileType::Csv;
            if (ft == FileType::Unspecified)
            {
                if (hasSuffix(path, ".bin"))
                    ft = FileType::Bin;
                else if (hasSuffix(path, ".csv"))
                    ft = FileType::Csv;
            }
            if (ft == FileType::Unspecified)
                throw std::runtime_error("unknown file extension, must be .csv or .bin or you must specify the -bin or -csv flags.");

            auto bIntegrated = cmd.getOr<int>("vo", 0); // TKL integrated version or step-by-step
            auto bHashIt = cmd.getOr<int>("hash", 1);   // TKL hash dataset when read and write
            u64 statSetParam = cmd.getOr("ssp", 40);
            auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
            auto ip1 = cmd.getOr<std::string>("ip1", "localhost:1213");
            auto ip2 = cmd.getOr<std::string>("ip2", "localhost:1214");
            auto r = (Role)cmd.getOr<int>("r", 2);
            if (r != Role::Sender && r != Role::Receiver && r != Role::Server)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver) or 2 (server).");

            auto isServer = cmd.getOr<int>("server", (int)r);
            if (r != Role::Sender && r != Role::Receiver && r != Role::Server)
                throw std::runtime_error("-server tag must be set with value 0, 1 or 2.");
            oc::Timer timer;

            bool isPSIServer = false;
            if (r == Role::Server)
            {
                isPSIServer = false;
                isServer = 1;
            }
            else if (r == Role::Receiver)
            {
                isPSIServer = true;
                isServer = 0;
            }
            else
            {
                isPSIServer = false;
                isServer = 0;
            }
            if (!quiet)
            {
                if (isServer)
                    std::cout << " Connecting as " << (tls ? "tls " : "") << "PSI helper & OSN sender" << " at address " << ip1 << " and  at address " << ip2 << std::flush;
                else
                {
                    std::cout << " Connecting as " << (tls ? "tls " : "") << (isPSIServer ? "vole senderA" : "vole senderB") << " at address " << ip << std::flush;
                    if (isPSIServer)
                        std::cout << " Connecting as " << (tls ? "tls " : "") << "OSN receiver to address " << ip1 << std::flush;
                    else
                        std::cout << " Connecting as " << (tls ? "tls " : "") << "OSN receiver to address " << ip2 << std::flush;
                }
            }
            std::vector<block> set;
            std::vector<std::vector<block>> dataset;
            bool withPayload = false;

            if (!isServer)
            {
                if (!quiet)
                    std::cout << "\nreading set......." << std::flush;
                auto readBegin = timer.setTimePoint("");
                dataset = readSet(path, ft, debug, bHashIt);
                set = dataset[0];
                if (dataset.size() > 1)
                    withPayload = true; // TKL flag for payload
                auto readEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << "ms" << std::endl;
            }
            coproto::Socket chl;
            coproto::Socket ch2;
            coproto::Socket ch3;
            auto connBegin = timer.setTimePoint("");
            if (tls)
            {
                std::string CACert = cmd.get<std::string>("CA");
                auto privateKey = cmd.get<std::string>("sk");
                auto publicKey = cmd.get<std::string>("pk");

                if (!exist(CACert) || !exist(privateKey) || !exist(privateKey))
                {
                    std::cout << "\n";
                    if (!exist(CACert))
                        std::cout << "CA cert " << CACert << " does not exist" << std::endl;
                    if (!exist(privateKey))
                        std::cout << "private key " << privateKey << " does not exist" << std::endl;
                    if (!exist(publicKey))
                        std::cout << "public key " << publicKey << " does not exist" << std::endl;

                    std::cout << "Please correctly set -CA=<path> -sk=<path> -pk=<path> to the CA cert, user private key "
                              << " and public key respectively." << std::endl;

                    throw std::runtime_error("bad TLS parameter.");
                }

#ifdef COPROTO_ENABLE_OPENSSL
                boost::asio::ssl::context ctx(!isServer ? boost::asio::ssl::context::tlsv13_client : boost::asio::ssl::context::tlsv13_server);

                ctx.set_verify_mode(
                    boost::asio::ssl::verify_peer |
                    boost::asio::ssl::verify_fail_if_no_peer_cert);
                ctx.load_verify_file(CACert);
                ctx.use_private_key_file(privateKey, boost::asio::ssl::context::file_format::pem);
                ctx.use_certificate_file(publicKey, boost::asio::ssl::context::file_format::pem);

                chl = coproto::sync_wait(
                    !isPSIServer ? macoro::make_task(coproto::AsioTlsConnect(ip, coproto::global_io_context(), ctx)) : macoro::make_task(coproto::AsioTlsAcceptor(ip, coproto::global_io_context(), ctx)));
                ch2 = coproto::sync_wait(
                    !isServer ? macoro::make_task(coproto::AsioTlsConnect(ip1, coproto::global_io_context(), ctx)) : macoro::make_task(coproto::AsioTlsAcceptor(ip1, coproto::global_io_context(), ctx)));
                ch3 = coproto::sync_wait(
                    !isServer ? macoro::make_task(coproto::AsioTlsConnect(ip2, coproto::global_io_context(), ctx)) : macoro::make_task(coproto::AsioTlsAcceptor(ip2, coproto::global_io_context(), ctx)));
#else
                throw std::runtime_error("COPROTO_ENABLE_OPENSSL must be define (via cmake) to use TLS sockets. " COPROTO_LOCATION);
#endif
            }
            else
            {
#ifdef COPROTO_ENABLE_BOOST
                if (isServer)
                {
                    ch2 = coproto::asioConnect(ip1, isServer);
                    ch3 = coproto::asioConnect(ip2, isServer);
                }
                else if (!isPSIServer)
                {
                    chl = coproto::asioConnect(ip, isPSIServer);
                    ch2 = coproto::asioConnect(ip1, isServer);
                }
                else
                {
                    chl = coproto::asioConnect(ip, isPSIServer);
                    ch3 = coproto::asioConnect(ip2, isServer);
                }
#else
                throw std::runtime_error("COPROTO_ENABLE_BOOST must be define (via cmake) to use tcp sockets. " COPROTO_LOCATION);
#endif
            }
            auto connEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(connEnd - connBegin).count()
                          << "ms\nValidating set sizes... " << std::flush;
            if (!isServer)
            {
                if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                    throw std::runtime_error("File does not contain the specified set size.");
            }
            u64 theirSize;
            u64 theirSize1;
            if (!isServer)
            {
                macoro::sync_wait(chl.send(set.size()));
                macoro::sync_wait(chl.recv(theirSize));
                if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                    throw std::runtime_error("Other party's set size does not match.");
            }

            auto valEnd = timer.setTimePoint("");
            if (!quiet)
                std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(valEnd - connEnd).count()
                          << "ms\nrunning PSI... " << std::flush;

            if (r == Role::Sender)
            {
                RsPsi3rdPSenderB sender;

                sender.mDebug = debug;
                sender.setMultType(type);

                //   size_t cardinality;
                std::vector<block> mReceiver_shares;
                std::vector<block> mSenderA_shares;
                if (!bIntegrated)
                {
                    sender.init(set.size(), theirSize, statSetParam, seed, mal, 1);
                    macoro::sync_wait(ch2.send(set.size())); // TKL
                    macoro::sync_wait(sender.run(set, chl, ch2));

                    //    macoro::sync_wait(ch2.recv(cardinality));   // recv cardinality frem server
                    if (withPayload)
                        set = dataset[1];
                    sender.getOSNReceiver().init(set.size(), 1); // TKL
                    macoro::sync_wait(sender.getOSNReceiver().run_osn(set, ch2, mReceiver_shares));
                    mSenderA_shares.resize(mReceiver_shares.size());
                    macoro::sync_wait(ch2.recv(mSenderA_shares)); // recv senderB's shares
                }
                else
                {
                    macoro::sync_wait(sender.run_OSN_integrated(chl, ch2, set, (withPayload ? dataset[1] : set), theirSize, statSetParam, seed, mal, 1));
                    mReceiver_shares = sender.getReceiver_shares();
                    mSenderA_shares = sender.getSenderA_shares();
                    //    cardinality = sender.getCardinality();
                }
                // TKL just for testing
                macoro::sync_wait(ch2.send(mReceiver_shares)); // sent its share to neutral

                macoro::sync_wait(chl.flush());
                macoro::sync_wait(ch2.flush());

                auto psiEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                              << "ms\nDone!" << std::endl;
                if (verbose)
                {
                    std::cout << "\nUsing integrated version = " << bIntegrated << std::endl;
                    //     std::cout << "\nIntesection_size = " << cardinality << std::endl;
                    std::cout << "Receiver_shares size= " << mReceiver_shares.size() << std::endl;
                    std::cout << "SenderA_shares size=" << mSenderA_shares.size() << std::endl;
                }
            }
            else if (r == Role::Receiver)
            {
                RsPsi3rdPSenderA recver;

                recver.mDebug = debug;
                recver.setMultType(type);

                //   size_t cardinality;
                std::vector<block> mReceiver_shares;
                std::vector<block> mSenderB_shares;
                if (!bIntegrated)
                {
                    recver.init(theirSize, set.size(), statSetParam, seed, mal, 1);
                    macoro::sync_wait(ch3.send(set.size())); // TKL
                    macoro::sync_wait(recver.run(set, chl, ch3));
                    //    macoro::sync_wait(ch3.recv(cardinality));   // recv cardinality frem server
                    if (withPayload)
                        set = dataset[1];
                    recver.getOSNReceiver().init(set.size(), 1); // TKL
                    macoro::sync_wait(recver.getOSNReceiver().run_osn(set, ch3, mReceiver_shares));
                    mSenderB_shares.resize(mReceiver_shares.size());
                    macoro::sync_wait(ch3.recv(mSenderB_shares)); // recv senderB's shares
                }
                else
                {
                    macoro::sync_wait(recver.run_OSN_integrated(chl, ch3, set, (withPayload ? dataset[1] : set), theirSize, statSetParam, seed, mal, 1));
                    mReceiver_shares = recver.getReceiver_shares();
                    mSenderB_shares = recver.getSenderB_shares();
                    //    cardinality = recver.getCardinality();
                }

                // TKL just for testing
                macoro::sync_wait(ch3.send(mReceiver_shares)); // sent its share to neutral

                macoro::sync_wait(chl.flush());
                macoro::sync_wait(ch3.flush());
                auto psiEnd = timer.setTimePoint("");

                auto outEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - psiEnd).count()
                              << "ms\nDone!" << std::flush;

                if (verbose)
                    std::cout << "\nUsing integrated version = " << bIntegrated << std::endl;
                //     std::cout << "\nIntesection_size = " << cardinality << std::endl;
                std::cout << "Receiver_shares size= " << mReceiver_shares.size() << std::endl;
                std::cout << "SenderB_shares size=" << mSenderB_shares.size() << std::endl;
            }
            else
            {
                RsPsi3rdPReceiver server;

                server.mDebug = debug;
                server.setMultType(type);
                std::vector<block> mSenderA_shares;
                std::vector<block> mSenderB_shares;
                if (!bIntegrated)
                {
                    macoro::sync_wait(ch2.recv(theirSize)); // TKL
                    macoro::sync_wait(ch3.recv(theirSize1));
                    server.init(theirSize, theirSize1, statSetParam, seed, mal, 1);
                    macoro::sync_wait(server.run(ch2, ch3));

                    //    macoro::sync_wait(ch2.send(server.getmIntersectionB().size()));  // send cardinality to sender B
                    //    macoro::sync_wait(ch3.send(server.getmIntersectionA().size()));  // send cardinality to sender A

                    macoro::sync_wait(server.run_OSN_Ssingle(ch2, server.getOsnSenderB(), server.getmIntersectionB(), theirSize, mSenderB_shares));
                    macoro::sync_wait(server.run_OSN_Ssingle(ch3, server.getOsnSenderA(), server.getmIntersectionA(), theirSize1, mSenderA_shares));

                    macoro::sync_wait(ch3.send(mSenderB_shares)); // send senderB's shares to sender A
                    macoro::sync_wait(ch2.send(mSenderA_shares)); // send senderA's shares  to sender B
                }
                else
                {
                    macoro::sync_wait(server.run_OSN_integrated(ch2, ch3, statSetParam, seed, mal, 1));
                    mSenderA_shares = server.getSenderA_shares();
                    mSenderB_shares = server.getSenderB_shares();
                }

                // TKL just for testing
                std::vector<block> mSenderA_Ownshares;
                std::vector<block> mSenderB_Ownshares;
                mSenderA_Ownshares.resize(mSenderA_shares.size());
                mSenderB_Ownshares.resize(mSenderB_shares.size());
                macoro::sync_wait(ch3.recv(mSenderA_Ownshares)); // recv senderA's own shares
                macoro::sync_wait(ch2.recv(mSenderB_Ownshares)); // recv senderB's own shares

                macoro::sync_wait(ch2.flush());
                macoro::sync_wait(ch3.flush());
                auto psiEnd = timer.setTimePoint("");

                if (!quiet)
                    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(psiEnd - valEnd).count()
                              << "ms\nWriting output to " << outPath << std::flush;

                // if (sortOutput)
                //     counting_sort(server.getmIntersectionA().begin(), server.getmIntersectionA().end(), server.getReceiverSize());
                writeOutput(outPath, ft, server.getmIntersectionB(), indexOnly, path, bHashIt);

                // if (sortOutput) // TKL
                //     counting_sort(server.getmIntersectionB().begin(), server.getmIntersectionB().end(), server.getSenderSize());

                auto outEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << " " << std::chrono::duration_cast<std::chrono::milliseconds>(outEnd - psiEnd).count()
                              << "ms\nDone!" << std::flush;

                if (verbose)
                {
                    std::cout << "\nUsing integrated version = " << bIntegrated << std::endl;
                    std::cout << "\nIntesection_size A = " << server.getmIntersectionA().size() << std::endl;
                    std::cout << "\nIntesection_size B = " << server.getmIntersectionB().size() << std::endl;
                    // TKL for verification
                    std::cout << "******* Receiver Set *******" << std::endl;
                    uint64_t value, total = 0;
                    std::vector<u64> intersectionA = server.getmIntersectionA();
                    std::vector<u64> intersectionB = server.getmIntersectionB();
                    std::vector<int> myPi_A = server.getMyPi_A();
                    std::vector<int> myPi_B = server.getMyPi_B();
                    for (auto i = 0; i < myPi_A.size(); i++)
                    {
                        auto j = myPi_A[i];
                        auto tmp = mSenderA_shares[j] ^ mSenderA_Ownshares[j];
                        std::string ss = hexToString(blockToString(tmp));
                        ss = is_ascii(ss.c_str(), ss.length()) ? ss : "";
                        std::cout << i << " tmp=" << tmp << "[" << intersectionA[i] << "] = " << ss << std::endl;

                        if (isNumber(ss))
                        {
                            value = std::stoul(ss, nullptr, 0);
                            total += value;
                        }
                    }
                    std::cout << " total =" << total << std::endl;

                    std::cout << "******* Sender Set *******" << std::endl;
                    for (auto i = 0; i < myPi_B.size(); i++)
                    {
                        auto j = myPi_B[i];
                        block tmp = mSenderB_shares[j] ^ mSenderB_Ownshares[j];
                        std::string ss = hexToString(blockToString(tmp));
                        ss = is_ascii(ss.c_str(), ss.length()) ? ss : "";
                        std::cout << i << " tmp=" << tmp << "[" << intersectionB[i] << "] = " << ss << std::endl;

                        if (isNumber(ss))
                        {
                            value = std::stoul(ss, nullptr, 0);
                            total += value;
                        }
                    }
                    std::cout << " total =" << total << std::endl;
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
            bool indexOnly = cmd.isSet("indexSet");
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
                    // std::cout << "\nConnecting as "
                    //           << "PSI helper & OSN sender"
                    //           << " at address " << ip2 << " and  at address " << ip3 << std::flush;
                }
                else
                {
                    //                    std::cout << " Connecting as " << (isPSIServer ? "PSI Alice" : "PSI Bob") << " at address " << ip << std::flush;
                    if (isPSIServer)
                    {
                        std::cout << "\nAlice:" << std::endl;
                        //                                  << " at address " << ip1 << std::flush;
                        //                        std::cout << " Connecting as "
                        //                                  << "OSN receiver to address " << ip2 << std::flush;
                    }
                    else
                    {
                        std::cout << "\nBob: " << std::endl;
                        //                                  << " to address " << ip1 << std::flush;
                        //                        std::cout << " Connecting as "
                        //                                  << "OSN receiver to address " << ip3 << std::flush;
                    }
                }
            }
            std::vector<block> set;
            std::vector<std::vector<block>> dataset;
            bool withPayload = false;

            if (!isServer)
            {
                // if (!quiet)
                //     std::cout << "\nreading set.......\n"
                //               << std::flush;
                auto readBegin = timer.setTimePoint("");
                std::cout << path << std::endl;
                dataset = readSet(path, ft, debug, bHashIt);
                set = dataset[0];
                if (dataset.size() > 1)
                    withPayload = true; // TKL flag for payload
                auto readEnd = timer.setTimePoint("");
                if (!quiet)
                    std::cout << "reading input file takes " << std::chrono::duration_cast<std::chrono::milliseconds>(readEnd - readBegin).count() << " ms" << std::endl;
                //        << "Validating set sizes... "  << std::endl;
                //    if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                //        throw std::runtime_error("File does not contain the specified set size.");
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
            //            auto protoBegin = timer.setTimePoint("PSI+OSN begin");
            if (r == Role::Sender)
            {
                RsPsi3rdPSenderB sender;
                //    size_t cardinality;
                std::vector<block> sendSet_sharesB;
                std::vector<block> recvSet_sharesB;
                std::vector<block> interShareB2SHS;
                macoro::sync_wait(sender.runSpHshPsiOsn(chl, ch3, set, (withPayload ? dataset[1] : set)));

                auto protoEnd = timer.setTimePoint("PSI+OSN end");
                //                if (!quiet)
                //                {
                //                    std::cout << "Bob : protocol takes " << std::chrono::duration_cast<std::chrono::milliseconds>(protoEnd - protoBegin).count()  << std::endl;
                //          << " ms ! \n Writing output to " << outPath << std::endl;
                // std::cout << "Bob sends SHS : " << ch3.bytesSent() << " Bytes," << std::endl;
                //                }

                sendSet_sharesB = sender.getReceiver_shares();
                recvSet_sharesB = sender.getSenderA_shares();

                // WJ: write PL shares into output file.
                auto myPiB = sender.getmyPi();
                if (myPiB.size() != recvSet_sharesB.size())
                    throw std::runtime_error("Mismatch between myPi size and Bob's inter shares' size!");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0; i < myPiB.size(); i++)
                {
                    //*to write SenderB's Payload*//
                    auto j1 = myPiB[i];
                    auto tmpPL1 = sendSet_sharesB[j1];
                    interShareB2SHS.push_back(tmpPL1);
                    std::string ss1 = blockToString(tmpPL1);
                    //                    std::string ss1 = hexToString(blockToString(tmpPL1));

                    //*to recover SenderA's Payload*//
                    block tmpPL2 = recvSet_sharesB[i];
                    std::string ss2 = blockToString(tmpPL2);
                    // std::string ss2 = hexToString(blockToString(tmpPL2));

                    outFile << ss2 << "," << ss1 << "\n"; // Write each string followed by a newline
                }
                outFile.close();
                // TKL just for testing
                macoro::sync_wait(ch3.send(interShareB2SHS)); // sent its share to neutral
                macoro::sync_wait(chl.flush());
                macoro::sync_wait(ch3.flush());
                if (verbose)
                {
                    // std::cout << "\nIntesection_size = " << cardinality << std::endl;
                    std::cout << "sendSet_sharesB size= " << sendSet_sharesB.size() << std::endl;
                    std::cout << "recvSet_sharesB size=" << recvSet_sharesB.size() << std::endl;
                }
            }
            else if (r == Role::Receiver)
            {
                RsPsi3rdPSenderA recver;
                //     size_t cardinality;
                std::vector<block> sendSet_sharesA;
                std::vector<block> recvSet_sharesA;
                std::vector<block> interShareA2SHS;
                macoro::sync_wait(recver.runSpHshPsiOsn(chl, ch2, set, (withPayload ? dataset[1] : set)));

                auto protoEnd = timer.setTimePoint("");
                //    if (!quiet)
                //    {
                //        std::cout << "Alice : protocol takes " << std::chrono::duration_cast<std::chrono::milliseconds>(protoEnd - protoBegin).count()
                //                  << " ms ! \n Writing output to " << outPath << std::endl;
                //        std::cout << "Alice sends SHS : " << ch2.bytesSent() << " Bytes," << std::endl;
                //    }

                recvSet_sharesA = recver.getReceiver_shares(); // share of Sender A's payload derived by OSN
                sendSet_sharesA = recver.getSenderB_shares();  // share of Sender B's payload sentby SHS
                //    cardinality = recver.getCardinality();

                // WJ: write PL shares into output file.
                auto myPiA = recver.getmyPi();
                if (myPiA.size() != sendSet_sharesA.size())
                    throw std::runtime_error("Mismatch between myPi size and Bob's inter shares' size!");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0; i < myPiA.size(); i++)
                {
                    //*to write SenderA's Payload*//
                    auto j1 = myPiA[i];
                    auto tmpPL1 = recvSet_sharesA[j1];
                    interShareA2SHS.push_back(tmpPL1);
                    std::string ss1 = blockToString(tmpPL1);
                    //                    std::string ss1 = hexToString(blockToString(tmpPL1));

                    //*to recover SenderB's Payload*//
                    block tmpPL2 = sendSet_sharesA[i];
                    std::string ss2 = blockToString(tmpPL2);
                    // std::string ss2 = hexToString(blockToString(tmpPL2));

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
                    //         << " ms ! \n Writing output to " << outPath << std::endl;
                    std::cout << "Overall communication overhead is " << ch3.bytesSent() + ch3.bytesReceived() << " Bytes, " << std::endl;
                    //                    std::cout << " SHS sends Bob : " << ch3.bytesSent() << " Bytes, " << std::flush;
                    //                    std::cout << " SHS sends Alice : " << ch2.bytesSent() << " Bytes, " << std::endl;
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

                // writeOutput(outPath, ft, server.getmIntersectionB(), indexOnly, path, bHashIt);
                //  TKL for verification
                // std::cout << "******* Receiver Set *******" << std::endl;
                // uint64_t value, total = 0;
                // std::vector<u64> intersectionA = server.getmIntersectionA();
                // std::vector<u64> intersectionB = server.getmIntersectionB();
                std::vector<int> myPi_A = server.getMyPi_A();
                std::vector<int> myPi_B = server.getMyPi_B();

                if (myPi_A.size() != myPi_B.size())
                    throw std::runtime_error("Mismatch between myPi_A and myPi_B !");

                std::ofstream outFile(outPath, std::ios::trunc); // WJ: write attribute in csv.
                if (!outFile.is_open())
                    throw std::runtime_error("Error opening file for writing !");

                for (auto i = 0; i < myPi_A.size(); i++)
                {
                    //*to recover SenderA's Payload*//
                    auto j1 = myPi_A[i];
                    auto tmpPL1 = mSenderA_shares[j1] ^ mSenderA_Ownshares[i];
                    // std::cout << i << " tmpPL1=" << tmpPL1 << " [" << intersectionA[i] << "]  " << std::endl;
                    //  Only for non 32 char hex payload
                    // std::string ss1 = blockToString(tmpPL1); // 24/03/2025 jwang
                    std::string ss1 = hexToString(blockToString(tmpPL1)); // 24/03/2025 jwang
                    // wj delete//     ss1 = is_ascii(ss1.c_str(), ss1.length())? ss1 : "" ;
                    // std::cout << "i=" << i << ", j1=" << j1 << ", tmp=" << tmpPL1 << "[" << intersectionA[i] << "] = " << ss1 << std::endl;
                    /*wj delete//    if (isNumber(ss1)) {
                                          value = std::stoul (ss1,nullptr,0);
                                          total += value;
                                      }*/

                    //*to recover SenderB's Payload*//
                    auto j2 = myPi_B[i];
                    block tmpPL2 = mSenderB_shares[j2] ^ mSenderB_Ownshares[i];
                    // std::cout << i << " tmpPL2=" << tmpPL2 << " [" << intersectionB[i] << "] " << std::endl;
                    //  Only for non 32 char hex payload
                    //  std::string ss2 = blockToString(tmpPL2); // 24/03/2025 jwang
                    std::string ss2 = hexToString(blockToString(tmpPL2)); // 24/03/2025 jwang
                    //  wj delete//     ss2 = is_ascii(ss2.c_str(), ss2.length())? ss2 : "" ;
                    //  std::cout << "i=" << i << ", j2=" << j2 << " tmpPL2=" << tmpPL2 << "[" << intersectionB[i] << "] = " << ss2 << std::endl;
                    /*wj delete//       if (isNumber(ss2)) {
                                            value = std::stoul (ss2,nullptr,0);
                                            total += value;
                                        }*/
                    // std::cout << i << mSenderA_Ownshares[i] << ", " << mSenderB_shares[j2] << std::endl;
                    // std::cout << i << mSenderA_shares[j1] << ", " << mSenderB_Ownshares[i] << std::endl;
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
        /*        for (int i; i < size; i++)
                {
                    std::cout << data[i] << ", " << std::flush;
                }
                std::cout << std::endl; */
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

    std::vector<block> writeCsvSetFile(std::string path, u64 step, u64 size)
    {
        std::ofstream o;
        std::vector<block> r;
        r.reserve(size);

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

        return r;
    }
    void filebase_generateFiles(const oc::CLP &cmd)
    {
        u64 n = cmd.getOr("n", 16);
        std::stringstream ss;
        ss << n;
        std::string strN = ss.str();
        std::string sFile = "./dataset/sFileOsn_" + strN + ".csv";
        std::string rFile = "./dataset/rFileOsn_" + strN + ".csv";
        std::cout << sFile << std::endl;
        auto s = writeCsvSetFile(sFile, 1, n);
        auto r = writeCsvSetFile(rFile, 2, n);
    }

}