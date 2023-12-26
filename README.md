# PQDiSE-from-PQDPRF
PQDPRF stands for post-quantum secure distributed PRF (Pseudo Random Function), constructed from quantum-safe LWR (Learning with Rounding) assumption. Furthermore, the efficacy of this DPRF is shown by using it in the construction of post-quantum secure distributed symmetric key encryption (abbreviated as PQDiSE).

## PQDiSE-from-PQDPRF
This repository has two separate and independent folders: **pqdprf** and **pqdise**. The codebase uses NTL library.<br/>
# pqdprf
Here, we provide codes to implement our proposed quantum-safe DPRF and verify its correctness, consistency and security. You can compile each of the cpp files here independently and execute the binary as follows.
```
cd pqdprf
g++ ThPRF_correctness.cpp -lntl -o ThPRF_correctness
./ThPRF_correctness
```
# pqdise
This is built over existing DiSE library, has dependency on cryptoTools library as well. Run the following commands on a Linux system.
```
cd pqdise
cmake --preset linux
cmake --build out/build/linux
cd out/build/linux/dEncFrontend
```
Now to run the unit tests, run
```
./dEncFrontend -u
```
To see the encryption performance, run
```
./dEncFrontend -sl -nStart 4 -nEnd 16 -nStep 2 -mf 0.5
```
Significance of all the options are written in the codebase. Use "-sl" option to get encryption performance using LWR-based DPRF. Replace it with "-ss" and "-sa" to get encryption performance using AES-based DPRF and DDH-based DPRF respectively.<br/>
To see just the DPRF performances, run
```
./dEncFrontend -comp -sl -thr 5 -total 8
```
"-thr" option takes value of threshold number of parties, "-total" takes value of total number of parties, "-sl" for LWR-based DPRF, "-ss" for AES-based DPRF, "-sa" for DDH-based DPRF.
