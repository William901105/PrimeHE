import os
import time

print("=== 1. 載入 sntrupcore.sage 核心 (PKE 模式 - 修正版) ===")
try:
    load('strupcore.sage')
    print("-> 載入成功！")
except Exception as e:
    print(f"-> [錯誤] 無法載入 sntrupcore.sage: {e}")
    exit()

# 輔助函式：將 byte string 轉為 hex 字串以便閱讀
def to_hex(b, limit=32):
    # 確保輸入是 bytes
    if not isinstance(b, bytes):
        return f"[非 Bytes 物件: {type(b)}]"
    h = b.hex()
    if len(h) > limit:
        return h[:limit] + "..." + h[-4:] + f" (Total {len(b)} bytes)"
    return h

# [FIXED] 輔助函式：將多項式轉為字串
def poly_to_str(p, limit=10):
    try:
        # 關鍵修正：將 Sage 多項式物件強制轉為 Python List
        p_list = list(p)
        
        if len(p_list) > limit:
            # 顯示前 5 個和後 5 個係數
            start = str(p_list[:5]).replace('[', '').replace(']', '')
            end = str(p_list[-5:]).replace('[', '').replace(']', '')
            return f"[{start}, ..., {end}] (Length {len(p_list)})"
        return str(p_list)
    except Exception:
        return str(p)

# 隨機數生成器適配器
def system_random8():
    return int(os.urandom(1)[0])

def run_pke_test(sys_name):
    print(f"\n" + "="*60)
    print(f"正在測試參數集: [{sys_name}]")
    print("="*60)
    
    try:
        # 1. 設定參數
        setparameters(sys_name, system_random8)
        print(f"參數設定: p={p}, q={q}, w={w}")
        
        # 2. KeyGen
        print("\n[步驟 1] 生成 PKE 密鑰對 (ZKeyGen)...")
        pk, sk = ZKeyGen()
        print(f"  -> 公鑰 (pk): {to_hex(pk)}")
        print(f"  -> 私鑰 (sk): {to_hex(sk)}")
        
        # 3. 準備明文
        print("\n[步驟 2] 生成明文 (Random Short Polynomial)...")
        r_original = Inputs_random()
        # 這裡會呼叫 poly_to_str，修正後應可正常顯示
        print(f"  -> 明文 r: {poly_to_str(r_original)}")

        # 4. 加密
        print("\n[步驟 3] 執行加密 (ZEncrypt)...")
        c = ZEncrypt(r_original, pk)
        print(f"  -> 密文 c: {to_hex(c)}")
        
        # 5. 解密
        print("\n[步驟 4] 執行解密 (ZDecrypt)...")
        r_decrypted = ZDecrypt(c, sk)
        print(f"  -> 解出 r': {poly_to_str(r_decrypted)}")
        
        # 6. 比對
        print("\n[步驟 5] 驗證結果...")
        if r_original == r_decrypted:
            print(f"  -> ★ SUCCESS: 解密結果與原始明文完全一致！")
            return True
        else:
            print(f"  -> X FAILURE: 解密結果不匹配！")
            # 為了除錯，若不匹配也嘗試轉 list 顯示
            r_orig_list = list(r_original)
            r_dec_list = list(r_decrypted)
            print(f"     預期: {r_orig_list[:10]}...")
            print(f"     實際: {r_dec_list[:10]}...")
            return False

    except Exception as e:
        print(f"  -> [ERROR] 程式執行錯誤: {e}")
        import traceback
        traceback.print_exc()
        return False

# --- 主程式 ---

print("\n=== 2. 開始執行所有參數集測試 ===")

# 排序參數集
all_systems = sorted(sntrup.keys(), key=lambda x: int(''.join(filter(str.isdigit, x)) or 0))

results = {}

for sys_name in all_systems:
    success = run_pke_test(sys_name)
    results[sys_name] = "PASS" if success else "FAIL"

print("\n" + "="*40)
print(f"{'參數集 (Parameter Set)':<20} | {'結果'}")
print("-" * 40)
for name, res in results.items():
    print(f"{name:<20} | {res}")
print("="*40)