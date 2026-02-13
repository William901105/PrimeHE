import sys

# TODO
# 設計足夠大的q以支援Homomorphic Multiplication

# Python 3 bytes 處理
def to_bytes(n):
    return bytes([n])

# 參數集定義
sntrup = { # round1, p, q, w, lpr
  'sntrup4591761': (True, 761, 4591, 143, False),
  'sntrup761':    (False, 761, 4591, 143, False),
  'sntrup653':    (False, 653, 4621, 144, False),
  'sntrup857':    (False, 857, 5167, 161, False),
  'sntrup953':    (False, 953, 6343, 198, False),
  'sntrup1013':   (False, 1013, 7177, 224, False),
  'sntrup1277':   (False, 1277, 7879, 246, False),
  'sntrupHo653':     (False, 653, 389069029, 135, False),#4
  'sntrupHo761':     (False, 761, 613622227, 158, False),
  'sntrupHo857':     (False, 857, 823331527, 173, False),
  'sntrupHo953':     (False, 953, 1241158411, 202, False),
  'sntrupHo1013':    (False, 1013, 1655076961, 227, False),
  'sntrupHo1277':    (False, 1277, 3230435893, 284, False),
  'sntrupHo1609':    (False, 1609, 5249595271, 323, False),
  'sntrupHo1637':    (False, 1637, 5669857537, 341, False),# 4
}

def setparameters(system, random8):
  global round1
  global p
  global q
  global w
  global b
  
  global PublicKeys_bytes
  global SecretKeys_bytes
  global Ciphertexts_bytes
  global Inputs_bytes
  global Rq_encode
  global Inputs_random
  global ZKeyGen
  global ZEncrypt
  global ZDecrypt
  global homomorphic_add
  global mult_count

  mult_count = 1
  b = 2**2

  if system in sntrup:
    round1, p, q, w, lpr_flag = sntrup[system]
    
    assert lpr_flag == False
  else:
    raise Exception('%s is not one of the selected parameter sets' % system)

  assert p.is_prime()
  assert q.is_prime()
  assert w > 0
  assert 2*p >= 3*w
  assert q >= 32*w+1
  assert q%6 == 1
  assert p%4 == 1

  if round1:
    assert p == 761
    assert q == 4591

  # ----- 1. 數學結構定義 (Arithmetic) -----

  # Mod 3
  F3 = GF(3)
  def ZZ_fromF3(c):
    assert c in F3
    return ZZ(c+1)-1

  # Mod q
  Fq = GF(q)
  q12 = ZZ((q-1)/2)
  def ZZ_fromFq(c):
    assert c in Fq
    return ZZ(c+q12)-q12

  # 整數多項式環 R
  global R
  Zx.<x> = ZZ[]
  R.<xp> = Zx.quotient(x^p-x-1)

  def Weightw_is(r):
    assert r in R
    return w == len([i for i in range(p) if r[i] != 0])

  def Small_is(r):
    assert r in R
    return all(abs(r[i]) <= 1 for i in range(p))

  def Short_is(r):
    return Small_is(r) and Weightw_is(r)

  # Mod 3 多項式環 R3
  F3x.<x3> = F3[]
  R3.<x3p> = F3x.quotient(x^p-x-1)

  global R_fromR3
  def R_fromR3(r):
    assert r in R3
    return R([ZZ_fromF3(r[i]) for i in range(p)])

  global R3_fromR
  def R3_fromR(r):
    assert r in R
    return R3([r[i] for i in range(p)])

  # Mod q 多項式環 Rq
  Fqx.<xq> = Fq[]
  assert (xq^p-xq-1).is_irreducible()

  global Rq
  Rq.<xqp> = Fqx.quotient(x^p-x-1)

  global R_fromRq
  def R_fromRq(r):
    assert r in Rq
    return R([ZZ_fromFq(r[i]) for i in range(p)])

  global Rq_fromR
  def Rq_fromR(r):
    assert r in R
    return Rq([r[i] for i in range(p)])

  # ----- 2. 輔助運算 (Rounding & Sorting) -----

  def Rounded_is(r):
    assert r in R
    return (all(r[i]%3 == 0 for i in range(p))
      and all(r[i] >= -q12 for i in range(p))
      and all(r[i] <= q12 for i in range(p)))

  def Round(a):
    assert a in Rq
    c = R_fromRq(a)
    r = [3*round(c[i]/3) for i in range(p)]
    assert all(abs(r[i]-c[i]) <= 1 for i in range(p))
    r = R(r)
    assert Rounded_is(r)
    return r

  global Short_fromlist
  def Short_fromlist(L): # L is list of p uint32
    L = [L[i]&-2 for i in range(w)] + [(L[i]&-3)|1 for i in range(w,p)]
    assert all(L[i]%2 == 0 for i in range(w))
    assert all(L[i]%4 == 1 for i in range(w,p))
    L.sort()
    L = [(L[i]%4)-1 for i in range(p)]
    assert all(abs(L[i]) <= 1 for i in range(p))
    assert sum(abs(L[i]) for i in range(p)) == w
    r = R(L)
    assert Short_is(r)
    return r

  # ----- 3. 隨機數生成 (Randomness) -----

  def urandom32():
    c0 = random8()
    c1 = random8()
    c2 = random8()
    c3 = random8()
    return c0 + 256*c1 + 65536*c2 + 16777216*c3

  global Short_random
  def Short_random(): 
    if round1:
      L = [urandom32() for i in range(p)]
      L = [L[i].__xor__(1<<31) for i in range(p)]
      return Short_fromlist(L)

    L = [urandom32() for i in range(p)]
    return Short_fromlist(L)

  def randomrange3():
    return ((urandom32() & 0x3fffffff) * 3) >> 30

  def Small_random():
    r = R([randomrange3()-1 for i in range(p)])
    assert Small_is(r)
    return r

  # ----- 4. 核心邏輯 (Core PKE Logic) -----

  
  global TensorProduct_poly
  global KeyGen
  global Encrypt
  global Decrypt


  def TensorProduct_poly(vec_a, vec_b):
    """
    計算兩個多項式向量的張量積 
    
    數學定義:
    若 vec_a = [a0, a1], vec_b = [b0, b1]
    結果 = [a0*b0, a0*b1, a1*b0, a1*b1]
    
    輸入:
        vec_a: List of polynomials in R (長度 n)
        vec_b: List of polynomials in R (長度 m)
    輸出:
        List of polynomials in R (長度 n * m)
    """
    result_vector = []
    
    # 雙層迴圈遍歷每一對元素
    for p1 in vec_a:
        for p2 in vec_b:
            # 在 R 環中進行多項式乘法
            prod = p1 * p2
            result_vector.append(prod)
            
    return result_vector

  def KeyGen():
    while True:
      g = Small_random()
      f = Short_random()
      h = Rq_fromR(g)/Rq_fromR(3*f)
      if Rq_fromR(g).is_unit(): break
    """
    產生 Evaluation Key
    Formula: evk = [ (3f)^-1 P((D(3f) ⊗ D(3f)) ) + h'*s + e ]_q
    """
    # 1. 準備變數
    three_f = 3*f
    
    # 3. 計算 BitDecompose(3f)
    vec_D = BitDecompose_poly(three_f)
    
    # 計算 Tensor Product D ⊗ D
    DD = TensorProduct_poly(vec_D, vec_D)
    
    # 4. 構建 EVK
    # 這是一個 l x l x l 的三維結構，我們將其展平為列表
    # 公式: evk = [ (3f)^-1 *P(  (D(3f) ⊗ D(3f)) ) + h'*s + e ]_q
    evk_list = []
    
    hprime = R_fromR3(R3_fromR(R_fromRq(h)))
    for tensor in DD:
        
        power_evk_poly = PowerOf2_poly(tensor)
        
        for p in power_evk_poly:
            s = Small_random()
            error = Small_random()
            p = Rq_fromR(p)/Rq_fromR(three_f)+Rq_fromR(hprime * s + error)
            p = R_fromRq(p)
            evk_list.append(p)

    return h,(f,1/R3_fromR(g)), evk_list
    # return h,(f,1/R3_fromR(g))

  def Encrypt(m,h):
    #assert Short_is(r)
    assert h in Rq
    return Round(h*Rq_fromR(m))

  def Decrypt(c,k):
    global mult_count
    f,v = k
    #assert Rounded_is(c)
    assert Short_is(f)
    assert v in R3
    # print(f"list(3*Rq_fromR(f)*Rq_fromR(c)) = {list(R_fromRq(3*Rq_fromR(f)*Rq_fromR(c)))}")
    r = R3_fromR(R_fromRq(3*Rq_fromR(f)*Rq_fromR(c)))
    m = r*v
    mult_count -= 1
    while mult_count>0:
        m = m*v
        mult_count -= 1
    mult_count = 1
    return R_fromR3(m)
    #if Weightw_is(r): return r
    #return R([1]*w+[0]*(p-w))

  # ----- 5. 編碼與解碼 (Encoding/Decoding) -----

  global tostring
  def tostring(s):
    return bytes(s)

  def fromstring(s):
    return list(s)

  # Small Polynomial Encoding
  Small_bytes = ceil(p/4)

  def Small_encode(r):
    assert Small_is(r)
    R = [r[i]+1 for i in range(p)]
    while len(R) < 4*Small_bytes: R += [0]
    assert all(R[i] >= 0 for i in range(4*Small_bytes))
    assert all(R[i] <= 2 for i in range(4*Small_bytes))
    assert len(R) >= p
    assert len(R)%4 == 0
    S = [R[i]+4*R[i+1]+16*R[i+2]+64*R[i+3] for i in range(0,len(R),4)]
    return tostring(S)

  def Small_decode(s):
    S = fromstring(s)
    r = [(S[i//4]//4^(i%4))%4 for i in range(p)]
    assert all(r[i] >= 0 for i in range(p))
    assert all(r[i] <= 2 for i in range(p))
    r = [r[i]-1 for i in range(p)]
    return R(r)

  # General Infrastructure for Encoding
  if round1:
    import itertools
    def concat(lists): return list(itertools.chain.from_iterable(lists))
    def int2str(u,bytes_len): return bytes([(u//256^i)%256 for i in range(bytes_len)])
    def str2int(s): return sum(s[i]*256^i for i in range(len(s)))
    def seq2str(u,radix,batch,bytes_len): 
      return b''.join(int2str(sum(u[i+t]*radix^t for t in range(batch)),bytes_len)
                     for i in range(0,len(u),batch))
    def str2seq(s,radix,batch,bytes_len):
      u = [str2int(s[i:i+bytes_len]) for i in range(0,len(s),bytes_len)]
      return concat([(u[i]//radix^j)%radix for j in range(batch)] for i in range(len(u)))
  else:
    limit = 16384
    def Encode(R,M):
      if len(M) == 0: return []
      S = []
      if len(M) == 1:
        r,m = R[0],M[0]
        while m > 1:
          S += [r%256]
          r,m = r//256,(m+255)//256
        return S
      R2,M2 = [],[]
      for i in range(0,len(M)-1,2):
        m,r = M[i]*M[i+1],R[i]+M[i]*R[i+1]
        while m >= limit:
          S += [r%256]
          r,m = r//256,(m+255)//256
        R2 += [r]
        M2 += [m]
      if len(M)&1:
        R2 += [R[-1]]
        M2 += [M[-1]]
      return S+Encode(R2,M2)
    def Decode(S,M):
      if len(M) == 0: return []
      if len(M) == 1: return [sum(S[i]*256**i for i in range(len(S)))%M[0]]
      k = 0
      bottom,M2 = [],[]
      for i in range(0,len(M)-1,2):
        m,r,t = M[i]*M[i+1],0,1
        while m >= limit:
          r,t,k,m = r+S[k]*t,t*256,k+1,(m+255)//256
        bottom += [(r,t)]
        M2 += [m]
      if len(M)&1:
        M2 += [M[-1]]
      R2 = Decode(S[k:],M2)
      R = []
      for i in range(0,len(M)-1,2):
        r,t = bottom[i//2]
        r += t*R2[i//2]
        R += [r%M[i]]
        R += [(r//M[i])%M[i+1]]
      if len(M)&1:
        R += [R2[-1]]
      return R

  # Rq Encoding
  if round1:
    def Rq_encode(h):
      h = [q12 + ZZ_fromFq(h[i]) for i in range(p)] + [0]*(-p % 5)
      return seq2str(h,6144,5,8)[:1218]
    def Rq_decode(hstr):
      h = str2seq(hstr,6144,5,8)
      if max(h) >= q: raise Exception('pk out of range')
      return Rq([h[i]-q12 for i in range(p)])
  else:
    def Rq_encode(r):
      assert r in Rq
      R = [ZZ_fromFq(r[i])+q12 for i in range(p)]
      M = [q]*p
      assert all(0 <= R[i] for i in range(p))
      assert all(R[i] < M[i] for i in range(p))
      return tostring(Encode(R,M))
    def Rq_decode(s):
      assert len(s) == Rq_bytes
      M = [q]*p
      R = Decode(fromstring(s),M)
      assert all(0 <= R[i] for i in range(p))
      assert all(R[i] < M[i] for i in range(p))
      r = [R[i]-q12 for i in range(p)]
      return Rq(r)

  global Rq_bytes
  Rq_bytes = len(Rq_encode(Rq(0)))

  # Rounded Encoding
  if round1:
    q61 = ZZ((q-1)/6)
    def Rounded_encode(c):
      c = [q61 + ZZ(c[i]/3) for i in range(p)] + [0]*(-p % 6)
      return seq2str(c,1536,3,4)[:1015]
    def Rounded_decode(cstr):
      c = str2seq(cstr,1536,3,4)
      c = [ci%(q61*2+1) for ci in c]
      return 3*R([c[i]-q61 for i in range(p)])
  else:
    def Rounded_encode(r):
      assert Rounded_is(r)
      R = [ZZ((ZZ_fromFq(r[i])+q12)/3) for i in range(p)]
      M = [ZZ((q-1)/3+1)]*p
      assert all(0 <= R[i] for i in range(p))
      assert all(R[i] < M[i] for i in range(p))
      return tostring(Encode(R,M))
    def Rounded_decode(s):
      assert len(s) == Rounded_bytes
      M = [ZZ((q-1)/3+1)]*p
      r = Decode(fromstring(s),M)
      assert all(0 <= r[i] for i in range(p))
      assert all(r[i] < M[i] for i in range(p))
      r = [3*r[i]-q12 for i in range(p)]
      return R(r)

  global Rounded_bytes
  Rounded_bytes = len(Rounded_encode(R(0)))

  # ----- 6. PKE Interface (Z-Functions) -----

  Inputs_random = Short_random
  Inputs_bytes = Small_bytes
  Ciphertexts_bytes = Rounded_bytes
  SecretKeys_bytes = 2*Small_bytes
  PublicKeys_bytes = Rq_bytes

  # 生成加密用的公鑰 (pk) 與私鑰 (sk)
  # 回傳: (bytes, bytes)
  def ZKeyGen():
    h, (f, v), evk = KeyGen()
    return Rq_encode(h), Small_encode(f) + Small_encode(R_fromR3(v)), evk
    # h, (f, v), evk = KeyGen()
    # return Rq_encode(h), Small_encode(f) + Small_encode(R_fromR3(v)), evk

  # 使用公鑰 pk 對多項式 m 進行加密
  # 輸入: m (Polynomial), pk (bytes)
  # 回傳: c (bytes)
  def ZEncrypt(m, pk):
    assert len(pk) == PublicKeys_bytes
    h = Rq_decode(pk)
    return Encrypt(m, h)
    #return Rounded_encode(Encrypt(m, h))

  # 使用私鑰 sk 對密文 c 進行解密
  # 輸入: c (bytes), sk (bytes)
  # 回傳: r (Polynomial)
  def ZDecrypt(c, sk):
    assert len(sk) == SecretKeys_bytes
    #assert len(c) == Ciphertexts_bytes
    f = Small_decode(sk[:Small_bytes])
    v = R3_fromR(Small_decode(sk[Small_bytes:]))
    #c = Rounded_decode(c)
    return Decrypt(c, (f, v))

  def homomorphic_add(c_1, c_2):
    c_sum = R_fromRq(Rq_fromR(c_1) + Rq_fromR(c_2))
    return c_sum
  
  global get_log_q
  global BitDecompose_poly
  global PowerOf2_poly
  global Gadget_Product
  global Vector_DotProduct

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
  
  def BitDecompose_poly(A):
    """
    輸入: 
        A: 必須是 R 中的多項式 (Integer Polynomial)
        b: 分解的基底 (Base, 大於 1 的整數)
    輸出: [p0, p1, ..., pl-1] (每個 pi 都是 R 中的多項式，且係數介於 0 到 b-1 之間)
    """
    global b
    # 1. 計算 l = ceil(log_b(q))
    # 利用不斷整除來求得精確的層數 l，避免 math.log 的浮點數誤差
    l = ceil_log_b(q, b)

    # 2. 驗證輸入型別
    if A.parent() != R:
        try:
            A = R(A)
        except TypeError:
            raise TypeError(f"BitDecompose 輸入必須是 R 中的多項式，目前是: {A.parent()}")

    # 3. 係數正規化 (Normalization)
    raw_coeffs = list(A)
    coeffs = [int(c) % q for c in raw_coeffs]
    
    # 補齊長度到 p (Sage 有時會省略高次項的 0)
    if len(coeffs) < p:
        coeffs += [0] * (p - len(coeffs))
    
    # 4. 進行 b-進制分解
    poly_list = []
    
    for i in range(l):
        # 計算當前層級的除數 (b 的 i 次方)
        divisor = b ** i
        
        # 對於第 i 層，取出所有係數在 b-進制下的第 i 個位數 (digit)
        # 數學公式對應: (c // b^i) mod b
        digit_row = [(c // divisor) % b for c in coeffs]
        
        # 5. 將列表轉為 R (整數環) 的多項式
        poly_in_R = R(digit_row)
        poly_list.append(poly_in_R)
        
    return poly_list

  def PowerOf2_poly(B):
    """
    輸入: 多項式 B (在 R 中)
    輸出: 多項式向量 [B, 2B, 4B, ..., 2^(l-1)B]
    """
    assert B in R

    l = ceil_log_b(q, b)
    
    # 生成 2 的冪次列表
    result_vector = []
    for i in range(l):
        scale = b**i
        result_vector.append(R_fromRq(Rq_fromR(B * scale)))
        
    return result_vector

  def Vector_DotProduct(A, B):
    """
    計算兩個多項式向量的內積
    A, B: List of polynomials in R
    回傳: Single polynomial in R
    """
    if len(A) != len(B):
        raise ValueError("向量長度不一致")
    return sum(a * b for a, b in zip(A, B))
  
  def KeySwitch(c_mult_tilde_D, evk):
    return R_fromRq(Rq_fromR(Vector_DotProduct(c_mult_tilde_D, evk)))
  
  global homomorphic_mult
  def homomorphic_mult(c_1,c_2,evk):
    global mult_count
    mult_count += 1
    # 1. 計算 P(c1) 和 P(c2)
    # vec1 和 vec2 都是長度為 l 的向量
    vec1 = PowerOf2_poly(c_1)
    vec2 = PowerOf2_poly(c_2)
    
    c_tilde = []
    
    # 2. 計算張量積 (Tensor Product)
    # 數學上是對每一對元素做乘法: v1[i] * v2[j]
    # 我們將 l x l 的矩陣展平為長度 l^2 的向量
    c_tilde = TensorProduct_poly(vec1, vec2)
    
    c_mult_tilde_B = []
    # 3. 使用 Evaluation Key 進行 Key Switching
    for c in c_tilde:
        for cB in BitDecompose_poly(c):
            c_mult_tilde_B.append(cB)
    

    c_mult = KeySwitch(c_mult_tilde_B, evk)
    return c_mult