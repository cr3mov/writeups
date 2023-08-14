---
title: "ctfzone23 pwn/test"
publishDate: "13 Aug 2023"
description: "Author: @es3n1n"
tags: ["ctfzone23", "pwn"]
---

#### Some decompiled code

![img](pug.jpeg)

Some code
```cpp
004538bb  void* sub_4538bb(void* arg1, int32_t arg2)
004538c5      void* ecx_1 = *(arg1 + 0x3c) + arg1
004538ce      void* edx_1 = ecx_1 + 0x18 + zx.d(*(ecx_1 + 0x14))
004538d7      void* esi_1 = zx.d(*(ecx_1 + 6)) * 0x28 + edx_1
004538db      if (edx_1 != esi_1)
004538ed          while (not(arg2 u>= *(edx_1 + 0xc) && arg2 u< *(edx_1 + 8) + *(edx_1 + 0xc)))
004538ef              edx_1 = edx_1 + 0x28
004538f4              if (edx_1 == esi_1)
004538f4                  break
004538ed      void* eax_5
004538ed      if (edx_1 == esi_1 || (edx_1 != esi_1 && not(arg2 u>= *(edx_1 + 0xc) && arg2 u< *(edx_1 + 8) + *(edx_1 + 0xc))))
004538f6          eax_5 = nullptr
004538ed      if (edx_1 != esi_1 && arg2 u>= *(edx_1 + 0xc) && arg2 u< *(edx_1 + 8) + *(edx_1 + 0xc))
004538fb          eax_5 = edx_1
004538fa      return eax_5
```

#### Some pasted latex

$$
\begin{aligned}
y_1 &= f_1(x_0,y_0,a_1,b_1,b_2) = x_0y_0 + b_2\\
y_2 &= f_2(x_0,y_0,a_1,b_1,b_2) = ...\\
y_3 &= f_3(x_0,y_0,a_1,b_1,b_2) = ...\\
y_4 &= f_4(x_0,y_0,a_1,b_1,b_2) = ...\\
y_5 &= f_5(x_0,y_0,a_1,b_1,b_2) = ...
\end{aligned}
$$
