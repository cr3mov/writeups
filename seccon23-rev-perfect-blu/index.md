---
title: "seccon23 rev/Perfect Blu"
publishDate: "18 Sep 2023"
description: "Author: es3n1n"
tags: ["rev", "seccon23"]
---


#### Description

Perfect Blu (135 pt)

No, I'm real!

[perfect-blu.tar.gz](https://score.quals.seccon.jp/api/download?key=quals2023%2FPerfect_Blu%2Fperfect-blu.tar.gz) 367b6ed67dda0afbbc975ee70ee946b4c7bf9268


#### Overview

Once i opened the downloaded `.tar.gz` file i observed that there's an `.iso` file inside and once i mounted it i saw that it has a file structure that looked 
like a fs structure of a DVD disc. So what i did is i dragged this `.iso` file to the VLC and got very surprised.

![1](./img/1.png)

As you probably already figured, this task is a DVD image that has an interactive menu where you need to enter the flag, press on the `CHECK` button and, depending on the flag it would, either show a `SUCCESS` or a `WRONG...` message.

#### Analysing

_I'm gonna be completely honest, i never had any experience with all this DVD stuff before, so i had to spend a couple hours googling how to analyse this stuff first._

There a multiple types of DVD menus that i'm aware of:
- Java menus
- IGS Menus

What i did first is i checked for any .jar files or just something that could remind me of java, but i didn't find anything and it meant that i was dealing with IGS menu.

First step in IGS menu analysis is to download [BDEdit](https://bdedit.pel.hu/) and open up our mounted `BDMV\index.bdmv`

![2](./img/2.png)

Looks scary, i know. What i did is, i checked the clip infos for the `und` streams. In order to do this i clicked at the `CLIPINFO` menu and found the `und` stream in the gui that contained our buttons logic.

![3](./img/3.png)

Here, at the left top corner there's a combo box with clip selector, there are 96 clips and all of them have some buttons. 

When i double-clicked at the `und` stream, the menu with buttons opened up and i saw a lot of buttons and the disasm of the code that they're doing.

![4](./img/4.png)

By messing around and guessing i found that first default valid button(`1FDE` on the screenshot) contains some random stuff that i wasn't interested in, and i should check others instead.

In this asm(or w/e this stuff is called) there's a `Call Object **` instruction that basically just starts playing another menu that you provide as a first operand, knowing it, i started analysing what the other buttons are doing.

By observing all the other buttons i saw three types of buttons.

---

Type 1, what most buttons are doing.

![6](./img/6.png)

This button jumps from our current menu(`0`) to the menu `48`.

---

Type 2.
![7](./img/7.png)

This button jumps from our current menu(`0`) to the next menu (`1`).

---

Type 3.
![8](./img/8.png)

This button is jumping to the clip 96, which i checked by playing the `BDMV\STREAM\00096.m2ts` file in VLC.

![9](./img/9.png)

---

After that i knew that there are only three destinations from the first menu
* Clip 1
* Clip 48
* Clip 96 (`WRONG...`) 

When i checked the menu buttons for clip 1 the pattern looked still the same so i checked menu 48 instead, and on the clip 48 all the menu buttons were doing the same thing, jumping to menu 48 (or 96).

Seems odd, huh? I investigated it a bit and it seemed like we would always end up on the menu 96 if we are on the menu thats index is >= 48.

There's one exception though, that i just guessed. Remember how i opened a stream 96 in vls? Well, i did the same thing for clip 95 and got this.

![10](./img/10.png)

From now on the solving of this challenge looked really trivial, i needed to parse all the clips and find what buttons are leading us to the clip 95.

#### Solving

While the idea is easy enough, i struggled for a half an hour trying to parse the clips.

I tried really many things/libs to parse the clips and extract this bytecode from them but none of them really worked so i decided that i should just do it by myself.

![11](./img/11.png)

What i did is i grabbed the `Call Object` instruction opcode (`21820000`), converted it to BE bytes and searched in HxD within all the files from the disk.

```py
>>> [hex(x) for x in int.to_bytes(0x21820000, 4, 'big')]
['0x21', '0x82', '0x0', '0x0']
>>>
```

I end up in the same m2ts files and got a lot of occurencies, from now on i assumed that this bytecode is indeed stored in the same file as the stream itself, so i should've parsed it from these files

![12](./img/12.png)

The whole assembled instruction from this asm looks like this.
```js
>───────┐ ┌───────┐ ┌───────> │
2182 0000 0000 0030 0000 0000 │ !......0....
│         │         │
2182──────│─────────│───────────────────────── Opcode
          30────────│───────────────────────── Operand 1
                    00──────────────────────── Operand 2
```

Let's write all of these as the constants for the solver

```py
OPCODE_SIZE: int = 4
OPERAND_SIZE: int = 4
INSN_SIZE = OPCODE_SIZE + (OPERAND_SIZE * 2)

CALL_OBJECT = b'\x21\x82\x00\x00'  # Call Object {DST}
```

After that i iterated over the first 47 streams and extracted their buttons.
```py
# Returns { button_id: jmp_to }
def parse_buttons(mnu_data: bytes) -> dict[int, int]:
    result = dict()
    i = 0
    start_off = 0

    while True:
        # Searching for `Call Object` opcode
        s = mnu_data.find(CALL_OBJECT, start_off)
        if s == -1:
            break

        # Move next iter
        start_off = s + INSN_SIZE

        # Read current chunk and extract op1 from it
        chunk = mnu_data[s:s + INSN_SIZE]
        op1 = int.from_bytes(chunk[4:8], 'big')

        # Save the dst
        result[i] = op1
        i += 1

    return result


# menu index -> buttons from `parse_buttons`
menus: dict[int, dict[int, int]] = dict()


for menu in p2.iterdir():
    menu_id = int(menu.name.split('.')[0])
    if menu_id > 47:
        break

    with open(menu, 'rb') as f:
        content = f.read()

    menus[menu_id] = parse_buttons(content)
```

At this point i already had all the playlists and parsed buttons from these playlists. To make the other logic a bit easier to implement, i collected all the successors and predecessors for menus into a separate dicts.
```py
# menu index -> possible exits
menus_possibilities: dict[int, list[int]] = dict()
# menu index -> { jmp_dst: [buttons] }
menus_referrers: dict[int, dict[int, list[int]]] = dict()

for key in sorted(menus.keys()):
    value = menus[key]
    menus_possibilities[key] = list()
    menus_referrers[key] = dict()

    for k, possible_value in value.items():
        if possible_value not in menus_referrers[key]:
            menus_referrers[key][possible_value] = list()

        menus_referrers[key][possible_value].append(k)

        if possible_value in menus_possibilities[key]:
            continue
        menus_possibilities[key].append(possible_value)
```

And noooow, i _finally_ solved the challenge by finding a path from menu 0 to the menu 95.
```py
# menu -> button
path: dict[int, int] = dict()

for k, v in menus_possibilities.items():
    tgt = None

    # Selecting the first menu that id is <=47 (or 95)
    for possible_move in v:
        if possible_move > 47 and possible_move != 95:
            continue

        tgt = possible_move
        break

    if not tgt:
        print('[!] Unknown tgt?!')
        break

    path[k] = menus_referrers[k][tgt][0]
    print('[+] Menu:', k, 'Button:', path[k], 'Next:', tgt)
```

By looking at the output i tried to guess what alphabet i needed to use in order to convert these button ids to the characters.
```js
[+] Menu: 0 Button: 21 Next: 1
[+] Menu: 1 Button: 12 Next: 2
[+] Menu: 2 Button: 32 Next: 3
[+] Menu: 3 Button: 32 Next: 4
[+] Menu: 4 Button: 18 Next: 5
[+] Menu: 5 Button: 35 Next: 6
[+] Menu: 6 Button: 29 Next: 7
...
```

The first button id that i should click on is 21. Knowing that the flag starts with `SECCON{` i know that the first char is `S` and its id is 21, by looking at the button layout i tried to guess the alphabet.
```js
1 2 3 4 5 6 7 8 9 0
Q W E R T Y U I O P
A S D F G H J K L {
Z X C V B N M _ - }
```
And oh well, when i tried to concat it to one string `1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}` and find `S` there i got
```py
>>> '1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}'.find('S')
21
>>>
```

So what i did is i just grabbed all the button ids and converted them to the chars using this alphabet.
```py
ALPHABET = '1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}'
FLAG: str = ''

for k, v in path.items():
    if v >= len(ALPHABET):
        break

    FLAG += ALPHABET[v]

print('[+] Flag:', FLAG)
```

And it worked just fine.


#### Flag
`SECCON{JWBH-58EL-QWRL-CLSW-UFRI-XUY3-YHKK-KFBV}`

#### Full solver code

```py
from pathlib import Path


p2 = Path(__file__).parent / 'menus'
# p2 = Path('F:\\BDMV\\STREAM')

"""
95 - win
96 - lose
"""

# DST - first operand
# SRC - second operand

# in bytes
OPCODE_SIZE: int = 4
OPERAND_SIZE: int = 4
INSN_SIZE = OPCODE_SIZE + (OPERAND_SIZE * 2)

BIT_CLEAR = b'\x50\x40\x00\x0D'  # Bit Clear GPR{DST}, {SRC}
CALL_OBJECT = b'\x21\x82\x00\x00'  # Call Object {DST}


# Returns { button_id: jmp_to }
def parse_buttons(mnu_data: bytes) -> dict[int, int]:
    result = dict()
    i = 0
    start_off = 0

    while True:
        s = mnu_data.find(CALL_OBJECT, start_off)
        if s == -1:
            break

        start_off = s + INSN_SIZE

        chunk = mnu_data[s:s + INSN_SIZE]

        # opcode = int.from_bytes(chunk[:4], 'big')
        op1 = int.from_bytes(chunk[4:8], 'big')
        # op2 = int.from_bytes(chunk[8:], 'big')

        # print('[+] i =', i, 'CALL_OBJECT', op1, op2)
        result[i] = op1

        i += 1

    return result


# menu index -> buttons from `parse_buttons`
menus: dict[int, dict[int, int]] = dict()


for menu in p2.iterdir():
    menu_id = int(menu.name.split('.')[0])
    if menu_id > 47:
        break

    with open(menu, 'rb') as f:
        content = f.read()

    menus[menu_id] = parse_buttons(content)


# menu index -> possible exits
menus_possibilities: dict[int, list[int]] = dict()
# menu index -> { jmp_dst: [buttons] }
menus_referrers: dict[int, dict[int, list[int]]] = dict()

for key in sorted(menus.keys()):
    value = menus[key]
    menus_possibilities[key] = list()
    menus_referrers[key] = dict()

    for k, possible_value in value.items():
        if possible_value not in menus_referrers[key]:
            menus_referrers[key][possible_value] = list()

        menus_referrers[key][possible_value].append(k)

        if possible_value in menus_possibilities[key]:
            continue
        menus_possibilities[key].append(possible_value)


# menu -> button
path: dict[int, int] = dict()

for k, v in menus_possibilities.items():
    tgt = None

    # Selecting the first menu that id is <=47 (or 95)
    for possible_move in v:
        if (possible_move > 47 and possible_move != 95) or possible_move == 0:
            continue

        if tgt:
            print('[!] What should i choose master', tgt, possible_move)

        tgt = possible_move

    if not tgt:
        print('[!] Unknown tgt?!')
        break

    path[k] = menus_referrers[k][tgt][0]
    print('[+] Menu:', k, 'Button:', path[k], 'Next:', tgt)


ALPHABET = '1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}'
FLAG: str = ''

for k, v in path.items():
    if v >= len(ALPHABET):
        break

    FLAG += ALPHABET[v]

print('[+] Flag:', FLAG)

```
