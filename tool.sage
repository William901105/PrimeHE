import os
load('primehe.sage')
def system_random8():
    return int(os.urandom(1)[0])
setparameters('sntrup653', system_random8)

    # ==========================================

    # 驗證測試 (Verification)
    # ==========================================

print("\n=== 開始驗證 BitDecompose 和 PowerOf2 ===")

# 1. 準備隨機多項式 A 和 B
# 我們用 Inputs_random 生成係數為 -1,0,1 的多項式，再放大一些讓它更有趣
rand_poly1 = Rq_fromR(Inputs_random())
rand_poly2 = Rq_fromR(Inputs_random())

# 讓 A 的係數變大一點 (模擬一般 Rq 元素)
A = rand_poly1 * 123 + 456 
B = rand_poly2

print(f"多項式 A (部分): {list(A)[:5]} ...")
print(f"多項式 B (部分): {list(B)[:5]} ...")

# ------------------------------------------
# 測試 1: 自我還原 (Reconstruction)
# 驗證: Sum( bit_i * 2^i ) == A
# ------------------------------------------
print("\n[測試 1] 自我還原測試: Sum(BD(A) * 2^i) == A ?")

vec_A = BitDecompose_poly(A)
l = get_log_q()

reconstructed_A = Rq(0)
for i in range(l):
    # 將分解出的第 i 個多項式，乘上 2^i 加回去
    reconstructed_A += vec_A[i] * (2**i)

if reconstructed_A == A:
    print("  -> ★ SUCCESS: 還原成功！")
else:
    print("  -> X FAILURE: 還原失敗！")
    print(f"     原 A: {A}")
    print(f"     還原: {reconstructed_A}")

# ------------------------------------------
# 測試 2: GSW 乘法技巧 (Gadget Product)
# 驗證: < BitDecompose(A), PowerOf2(B) > == A * B
# ------------------------------------------
print("\n[測試 2] GSW 乘法測試: DotProduct(BD(A), Pow2(B)) == A * B ?")

# 1. 計算標準乘法
expected_product = A * B

# 2. 計算 Gadget 乘法
# 分解 A
vec_decomp_A = BitDecompose_poly(A)
# 擴展 B
vec_pow2_B = PowerOf2_poly(B)

# 3. 計算內積 (Dot Product)
gadget_product = Gadget_Product(A, B)

# 4. 比對結果
if gadget_product == expected_product:
    print("  -> ★ SUCCESS: 乘法結果一致！")
    print(f"     預期值 (前5項): {list(expected_product)[:5]}")
    print(f"     計算值 (前5項): {list(gadget_product)[:5]}")
else:
    print("  -> X FAILURE: 乘法結果不一致！")
