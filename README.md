# PrimeHE: A First Homomorphic Encryption based on NTRUPrime
## How to use
### Using the following command to run the PrimeHE test program:
```bash
sage primehe_test.sage
```
Note: you can also run your own test program by importing the `primehe.sage` file, which contains the implementation of the PrimeHE scheme.
## File Description
- `primehe.sage`: The implementation of the PrimeHE scheme based on NTRUPrime.
- `primehe_test.sage`: A test program to demonstrate the functionality of the PrimeHE scheme.
- `sntrup.sage`: The main implementation of the NTRUPrime scheme.
- `sntrup_test.sage`: A test program to demonstrate the functionality of the NTRUPrime scheme.
- `parameters.sage`: Find the parameters of PrimeHE scheme.
====================================================================================================
                           Performance Analysis (Average over iterations)                           
====================================================================================================
Parameter Set   | KeyGen (s)   | Encrypt (ms) | Add (ms)   | Mult (ms)    | Decrypt (ms)
----------------------------------------------------------------------------------------------------
sntrupHo653     |      47.9999 |         9.16 |     1.9898 |      1537.26 |         7.32
sntrupHo761     |      56.3268 |        10.18 |     2.3931 |      1757.63 |         8.84
sntrupHo857     |      63.0508 |        10.51 |     2.5723 |      1983.42 |         9.66
sntrupHo953     |      88.1209 |        13.58 |     3.3756 |      2960.93 |        12.23
sntrupHo1013    |     101.1071 |        13.90 |     3.4000 |      3243.88 |        16.35
sntrupHo1277    |     130.0095 |        16.86 |     5.0572 |      3958.01 |        15.30
sntrupHo1609    |     195.7399 |        21.36 |     6.2381 |      6172.53 |        20.92
sntrupHo1637    |     201.6608 |        22.20 |     6.7628 |      6208.88 |        21.06
----------------------------------------------------------------------------------------------------
Success Rates:
 - sntrupHo653: Add 100.0%, Mult 100.0%
 - sntrupHo761: Add 100.0%, Mult 100.0%
 - sntrupHo857: Add 100.0%, Mult 100.0%
 - sntrupHo953: Add 100.0%, Mult 100.0%
 - sntrupHo1013: Add 100.0%, Mult 100.0%
 - sntrupHo1277: Add 100.0%, Mult 100.0%
 - sntrupHo1609: Add 100.0%, Mult 100.0%
 - sntrupHo1637: Add 100.0%, Mult 100.0%
====================================================================================================