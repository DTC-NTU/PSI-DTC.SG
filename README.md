# PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data (Demo)

**PSA** is a privacy-preserving technique enabling secure, collaborative analytics between two parties with vertically partitioned datasets, without directly sharing sensitive data. This demo integrates **Private Set Intersection (PSI)** and an **Oblivious Switching Network** to achieve efficient and secure **Private Set Alignment (PSA)**.

This project depends on [libOTe](https://github.com/osu-crypto/libOTe), [sparsehash](https://github.com/sparsehash/sparsehash), [Coproto](https://github.com/Visa-Research/coproto), [volepsi](https://github.com/Visa-Research/volepsi).

## Performance Metrics

- Dataset Join Time: 35.5 seconds (1 million records)
- Performance Improvement: ~100× faster than existing methods

## Installation

PSA requires Python 3.9 and has been tested on **Linux Ubuntu 22.04.5 LTS** with **GCC (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0**. The project needs to be built before running.

### Setup

1. **Clone the repository**
2. **Build the project & dependencies**:
   ```bash
   python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON
   ```

## Quickstart

To run PSA with Alice (Sender), Bob (Receiver), and the Service Provider:

1. **Run the Service Provider**:
   ```bash
   ./out/build/linux/frontend/frontend -SpHsh ./dataset/cleartext.csv -r 2 -csv -hash 0 -indexSet
   ```
2. **Run the Receiver (Bob)**:
   ```bash
   ./out/build/linux/frontend/frontend -SpHsh ./dataset/receiver.csv -r 1 -csv -hash 0
   ```
3. **Run the Sender (Alice)**:
   ```bash
   ./out/build/linux/frontend/frontend -SpHsh ./dataset/sender.csv -r 0 -csv -hash 0
   ```

These three roles (Alice, Bob, and Service Provider) work together to perform secure inner join. Alice and Bob exchange secret shares to create a "virtual table" with the inner join of their datasets based on common user IDs, while the Service Provider facilitates coordination and compilation.

## Input and Output Validation

To verify the correct execution, you can inspect the input and output files:

### Input Data Format

The input files from Alice and Bob are **CSV files** with the following format:

- **Column 1**: ID
- **Column 2**: Attribute (Alice's or Bob's, depending on the file)

For example:

**Alice Input CSV** (sender.csv):

```
FIMbdVN0P2hWkmQp,697626930337
bg4t3fVY1Tw3ASlv,61650378238787
6jJykxRGyuCz5ciy,43313803051
yKE23VylSP1OKELN,75738363176449
OGvQHQP2rm4D6GZR,006609232196
WkYkdx24K2t646BK,658936928362438
...
```

**Bob Input CSV** (receiver.csv):

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

The expected output file, `out_cleartext.csv`, will have the following format:

- **Column 1**: Attribute from Alice (AttributeAlice)
- **Column 2**: Attribute from Bob (AttributeBob)

For example:

**Output CSV** (out_cleartext.csv):

```
intersection8,697626930337
...
```

### Expected Output

After running the scripts for **Alice**, **Bob**, and the **Service Provider**, the output file `out_cleartext.csv` should contain the aligned records based on common IDs. Each row should show the corresponding attributes from Alice and Bob for the same ID.

### Example of Expected Output

If the input CSV files for Alice and Bob are:

**sender.csv**:

```
1, A1
2, A2
3, A3
4, A4
5, A5
6, A6
```

**receiver.csv**:

```
0, B0
2, B2
3, B3
6, B6
7, B8
```

The output file `out_cleartext.csv` should look like this:

```
A2, B2
A3, B3
A6, B6
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
