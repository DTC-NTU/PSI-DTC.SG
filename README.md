# PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data (Demo)

**PSA** is a privacy-preserving technique enabling secure, collaborative analytics between two parties with vertically partitioned datasets, without directly sharing sensitive data. This demo integrates **Private Set Intersection (PSI)** and an **Oblivious Switching Network** to achieve efficient and secure **Private Set Alignment (PSA)**.

This project depends on [libOTe](https://github.com/osu-crypto/libOTe), [sparsehash](https://github.com/sparsehash/sparsehash), [Coproto](https://github.com/Visa-Research/coproto), [volepsi](https://github.com/Visa-Research/volepsi), [PSU](https://github.com/dujiajun/PSU/tree/master/benes)

## Performance Metrics

- Dataset Join Time: 35.5 seconds (1 million records)
- Performance Improvement: ~100× faster than existing methods



## How It Works
Private Set Alignment (PSA) enables secure analytics on combined datasets without exposing raw data. The protocol involves three parties: Alice, Bob and the Service Provider that it's going to perform the private set alignment.

Key Steps for Privacy-Preserving Data Processing:
1. Data Submission
    - Participants: Alice and Bob
    - Action: Alice and Bob securely submit their data to the Service Provider. This ensures that sensitive information is protected during transmission.

2. Private Set Alignment
    - Action: The Service Provider uses a privacy-preserving technique to align and identify matching records between Alice and Bob’s datasets without revealing any individual IDs or private information.

3. Result Generation
    - Action: After matching the records, the Service Provider generates the linked records through secret-sharing protocols.

For technical details, see our paper (linked below).



## Installation & Run
⚠️ Note: Building the application may take more than 20 minutes to complete depending on your system.

### Option 1: Docker (Recommended)
```bash
# Clone repository
git clone https://github.com/DTC-NTU/PSI-DTC.SG.git

# Build and launch container
docker-compose build && docker-compose up
```
Docker automatically handles all dependencies

### Option 2: Manual Build (Linux Only)
⚠️ Requires Pre-installed Dependencies, the commands can be found inside the `dockerfile`.

| Dependency         | Purpose                                                                  |
|--------------------|--------------------------------------------------------------------------|
| build-essential    | Compiler and basic development tools (version 12.9ubuntu3)               |
| gdb                | Debugger (version 12.1)                                                  |
| libssl-dev         | SSL library for encryption support (version 3.0.2-0ubuntu1.19)           |
| gcc-11             | GNU C compiler (version 11)                                              |
| g++-11             | GNU C++ compiler (version 11)                                            |
| wget               | File download utility                                                    |
| curl               | Data transfer tool                                                       |
| libboost-all-dev   | Boost C++ libraries                                                      |
| libtool            | Library management tools (version 2.4.6-15build2)                        |
| git                | Version control system                                                   |
| cmake (v4.0.0)     | Build system generator (version 4.0.0)                                   |


```bash
# 1. Clone repository
git clone https://github.com/DTC-NTU/PSI-DTC.SG.git

# 2. Build project
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON

# 3. Run services in separate terminals:
# Service Provider (Service Provider)
./out/build/linux/frontend/frontend -SpHsh ./dataset/cleartext.csv -r 2 -csv -hash 0

# Receiver (Bob)
./out/build/linux/frontend/frontend -SpHsh ./dataset/receiver.csv -r 1 -csv -hash 0

# Sender (Alice)
./out/build/linux/frontend/frontend -SpHsh ./dataset/sender.csv -r 0 -csv -hash 0
```

### Expected Terminal Output
After the application is built and executed, you should see the following output in your terminal to confirm a correct execution:
```bash
Attaching to psi-app-1
psi-app-1  | 
psi-app-1  | Alice:
psi-app-1  | ./dataset/receiver.csv
psi-app-1  | 
psi-app-1  | Bob: 
psi-app-1  | ./dataset/sender.csv
psi-app-1  | reading input file takes 1 ms
psi-app-1  | reading input file takes 2 ms
psi-app-1  | Establishing connection takes 1 ms,
psi-app-1  | start to run secure inner join... Alice sends to Bob: 48 Bytes.
psi-app-1  | Establishing connection takes 1 ms,
psi-app-1  | start to run secure inner join... 
psi-app-1  | 
psi-app-1  | 
psi-app-1  | Overall time overhead is 25 ms,
psi-app-1  | Overall communication overhead is 110928 Bytes, 
```



## Input and Output Validation

To verify the correct execution, you can inspect the input and output files:

### Input Data Format

The input files from Alice and Bob are **CSV files** with the following format:

- **Column 1**: ID
- **Column 2**: Attribute/Payload (Alice's or Bob's, depending on the file)

For example:

**Alice Input CSV** (`dataset/sender.csv`):

```
FIMbdVN0P2hWkmQp,697626930337
bg4t3fVY1Tw3ASlv,61650378238787
6jJykxRGyuCz5ciy,43313803051
yKE23VylSP1OKELN,75738363176449
OGvQHQP2rm4D6GZR,006609232196
WkYkdx24K2t646BK,658936928362438
...
```

**Bob Input CSV** (`dataset/receiver.csv`):

```
FIMbdVN0P2hWkmQp,intersection8
bKdYp0OZYmlCwUXx,apple
B9syDpwL6b8jUTr5,elephant
lUcaUy90isDcKkaV,dog
rQR2DOLJxU0PvrVe,zebra
0EadHpwt7NqUE3tF,intersection6
...
```

### Output Data Format

The expected output file, `dataset/out_cleartext.csv`, will have the following format:

- **Column 1**: Attribute/Payload from Alice 
- **Column 2**: Attribute/Payload from Bob

For example:

**Output CSV** (`dataset/out_cleartext.csv`):

```
intersection8,697626930337
...
```

## DOI

For more details, access the full paper via DOI:  
[10.48550/arXiv.2410.04746](https://arxiv.org/abs/2410.04746)

## Licensing

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Citation

```
@article{article,
author = {Wang, Jiabo and Huang, Elmo and Duan, Pu and Wang, Huaxiong and Lam, Kwok-Yan},
year = {2024},
title = {PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data},
doi = {10.48550/arXiv.2410.04746}
}
```

## Authors

- **Jiabo Wang**
- **Federico Giorgio Pfahler**
- **Elmo Xuyun Huang**
- **Pu Duan**
- **Huaxiong Wang**
- **Kwok-Yan Lam**
