def ceil_log_b(val, b):
    """
    計算 ceil(log_b(val))。
    使用純整數運算，避免大整數在計算浮點數 log 時遺失精準度。
    """
    if val <= 1:
        return 0
    res = 0
    curr = 1
    while curr < val:
        curr *= b
        res += 1
    return res

def find_valid_parameters(b=2): # 將 b 作為參數傳入，預設為 2
    print(f"開始搜尋參數 (使用底數 b = {b})")
    print(f"{'p':<6} | {'q':<20} | {'w':<6} | {'l':<10} | {'Check'}")
    print("-" * 55)

    # 1. 遍歷質數 p:[653, 761, 857, 953, 1013, 1277, 1601, 1609, 1613, 1621, 1637]
    for p in [653, 1637]:
        print(f"{p}")
        # 條件: p % 4 == 1
        if p % 4 != 1:
            continue

        # 2. 遍歷 w
        # 條件: 2*p >= 3*w  =>  w <= 2*p/3
        max_w = floor((2 * p) / 3)
        
        # 為了演示，我們從一個合理的 w 大小開始
        start_w = max(1, floor(p/5)) 
        
        for w in range(start_w, max_w + 1):
            
            # 3. 計算 q 的下界 (處理 l 的循環依賴)
            # 新公式: q >= 14w^2 + 30w^2*p + 6b*w*p*l + 6b*w*l + 1
            # l = log_b(q)
            
            # 初始猜測 l
            l = 10
            q_lower_bound = 0
            
            # 迭代修正 l，直到穩定
            for _ in range(10): # 稍微增加迭代次數以確保大底數也能收斂
                q_lower_bound = 14*(w**2) + 30*(w**2)*p + 6*b*w*p*l + 6*b*w*l + 1
                new_l = ceil_log_b(q_lower_bound, b) 
                if new_l == l:
                    break
                l = new_l
            
            # 4. 尋找符合條件的質數 q
            # 從計算出的下界開始找下一個質數
            q = next_prime(q_lower_bound - 1)
            
            found_q = False
            # 設定一個搜尋上限，避免無限迴圈
            search_limit = 100 
            count = 0
            
            while count < search_limit:
                # 條件: q % 6 == 1
                if q % 6 == 1:
                    # 更新 l 以符合當前的 q (使用 log_b)
                    current_l = ceil_log_b(q, b)
                    
                    # 再次檢查 q 的大小限制，套用新公式
                    rhs = 14*(w**2) + 30*(w**2)*p + 6*b*w*p*current_l + 6*b*w*current_l + 1
                    
                    if q >= rhs:
                        # 5. 檢查多項式不可約性
                        # 檢查 x^p - x - 1 在 GF(q) 上是否不可約
                        F = GF(q)
                        R.<x> = PolynomialRing(F)
                        poly = x^p - x - 1
                        
                        if poly.is_irreducible():
                            assert p.is_prime()
                            assert q.is_prime()
                            assert w > 0
                            assert 2*p >= 3*w
                            assert q >= 14*w**2 + 30*w**2*p + 6*b*w*p*current_l + 6*b*w*current_l + 1
                            assert q%6 == 1
                            assert p%4 == 1

                            print(f"{p:<6} | {q:<20} | {w:<6} | {current_l:<10} | Pass")
                            found_q = True
                            break 
                
                q = next_prime(q)
                count += 1
            
            if found_q:
                break

# 執行函式 (可以修改這裡的 b 值，例如 b=3, b=16 等等)
find_valid_parameters(b=2**4)