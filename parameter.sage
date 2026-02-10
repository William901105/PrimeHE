def find_valid_parameters(start_p=17, max_p=1000):
    print(f"開始搜尋參數 (p 範圍: {start_p} ~ {max_p})...")
    print(f"{'p':<6} | {'q':<20} | {'w':<6} | {'l':<10} | {'Check'}")
    print("-" * 45)

    # 1. 遍歷質數 p
    for p in primes(start_p, max_p):
        # 條件: p % 4 == 1
        if p % 4 != 1:
            continue

        # 2. 遍歷 w
        # 條件: 2*p >= 3*w  =>  w <= 2*p/3
        max_w = floor((2 * p) / 3)
        
        # 為了演示，我們從一個合理的 w 大小開始 (例如 p/4)，避免 w 太小導致安全性不足
        # 也可以改為 range(1, max_w + 1)
        start_w = max(1, floor(p/5)) 
        
        for w in range(start_w, max_w + 1):
            
            # 3. 計算 q 的下界 (處理 l 的循環依賴)
            # q >= 14w^2 + 30w^2*p + 12w*p*l + 12w*l + 1
            # l = log2(q)
            
            # 初始猜測 l (例如 10)
            l = 10
            q_lower_bound = 0
            
            # 迭代修正 l，直到穩定
            for _ in range(5):
                q_lower_bound = 14*(w**2) + 30*(w**2)*p + 12*w*p*l + 12*w*l + 1
                new_l = Integer(q_lower_bound).nbits() # nbits ≈ ceil(log2(q))
                if new_l == l:
                    break
                l = new_l
            
            # 4. 尋找符合條件的質數 q
            # 從計算出的下界開始找下一個質數
            q = next_prime(q_lower_bound - 1)
            
            found_q = False
            # 設定一個搜尋上限，避免無限迴圈 (例如找接下來的 100 個質數)
            search_limit = 100 
            count = 0
            
            while count < search_limit:
                # 條件: q % 6 == 1
                if q % 6 == 1:
                    # 更新 l 以符合當前的 q
                    current_l = Integer(q).nbits()
                    
                    # 再次檢查 q 的大小限制 (因為 l 可能變大了)
                    rhs = 14*(w**2) + 30*(w**2)*p + 12*w*p*current_l + 12*w*current_l + 1
                    
                    if q >= rhs:
                        # 5. 檢查多項式不可約性 (這是最耗時的一步)
                        # 檢查 x^p - x - 1 在 GF(q) 上是否不可約
                        F = GF(q)
                        R.<x> = PolynomialRing(F)
                        poly = x^p - x - 1
                        
                        if poly.is_irreducible():
                            assert p.is_prime()

                            assert q.is_prime()

                            assert w > 0

                            assert 2*p >= 3*w

                            assert q >= 14*w**2 + 30*w**2*p + 12*w*p*current_l + 12*w*current_l + 1

                            assert q%6 == 1

                            assert p%4 == 1

                            print(f"{p:<6} | {q:<20} | {w:<6} | {current_l:<10} | Pass")
                            # 找到一組就回傳 (或是用 yield 繼續找)
                            # return (p, q, w) 
                            found_q = True
                            break 
                
                q = next_prime(q)
                count += 1
            
            # 如果只想找第一組符合的 p，可以在這裡 break
            if found_q:
                # 為了展示多樣性，這裡不 break，繼續找下一個 w
                pass

# 執行函式
find_valid_parameters(start_p=600, max_p=15000)