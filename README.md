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
## 📊 效能分析 (Performance Analysis)

以下數據為演算法在 SageMath 環境下執行的基準測試結果（各項操作的平均執行時間）。

> ⚠️ **環境聲明 (Disclaimer)**: 
> 本實作主要為學術研究的概念驗證 (Proof-of-Concept)。由於 SageMath 為直譯式語言且包含較多高階代數運算開銷，此處的絕對執行時間（Absolute Time）不能與 C++ 高度優化庫（如 YASHE, OpenFHE）直接比較。
> 本表的重點在於展示 NTRU 結構下，運算成本隨安全參數 $N$ 增加而呈現的**準線性成長趨勢 (Quasi-linear scaling)**。

| 參數集 (Parameter Set) | KeyGen (s) | Encrypt (ms) | Add (ms) | Mult (ms) | Decrypt (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **primehe653** | 48.00 | 9.16 | 1.99 | 1537.26 | 7.32 |
| **primehe761** | 56.33 | 10.18 | 2.39 | 1757.63 | 8.84 |
| **primehe857** | 63.05 | 10.51 | 2.57 | 1983.42 | 9.66 |
| **primehe953** | 88.12 | 13.58 | 3.38 | 2960.93 | 12.23 |
| **primehe1013** | 101.11 | 13.90 | 3.40 | 3243.88 | 16.35 |
| **primehe1277** | 130.01 | 16.86 | 5.06 | 3958.01 | 15.30 |
| **primehe1609** | 195.74 | 21.36 | 6.24 | 6172.53 | 20.92 |
| **primehe1637** | 201.66 | 22.20 | 6.76 | 6208.88 | 21.06 |

### ✅ 運算準確率 (Success Rates)
在所有測試的參數集（primehe653 ~ primehe1637）中，經過多輪隨機明文測試：
* **同態加法 (Homomorphic Add): 100.0%**
* **同態乘法 (Homomorphic Mult): 100.0%**

這證明了本方案在張量積與密鑰切換 (Key Switching) 過程中的雜訊擴張受到了良好的控制，能夠確保解密的絕對正確性。