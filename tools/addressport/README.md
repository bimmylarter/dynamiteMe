Address porting tools
===

Scripts used to port `hook/src/mgsvtpp_addresses_1_0_15_3_en.h` and the in-memory patches in
`hook/src/dynamitePatches.cpp` from game version 1.0.15.3 to 1.0.15.4. Kept for the next game update.

Requires Python 3 and capstone (`pip install capstone`). Put both executables in `./exe/` as
`old_mgsvtpp.exe` and `new_mgsvtpp.exe` (several scripts expect those names).

### Why plain signatures don't work

1.0.15.3 is protected: most functions were moved to a large `.text` block and re-encoded (same
instructions, different encodings, junk after `ret`), with a `jmp` stub left at the original address.
1.0.15.4 keeps most code at its original layout, a few functions are again behind stubs in `.xdata`.
So functions are compared on normalized disassembly, and the old stub address is used to predict the
new location (new ≈ old stub + slowly drifting offset).

### Pipeline

```
H=../../hook/src/mgsvtpp_addresses_1_0_15_3_en.h
python3 match2.py   exe/old_mgsvtpp.exe exe/new_mgsvtpp.exe $H map2.json          # global instruction match
python3 resolve.py  exe/old_mgsvtpp.exe exe/new_mgsvtpp.exe $H map3.json          # sparse anchors + prediction
python3 resolve2.py exe/old_mgsvtpp.exe exe/new_mgsvtpp.exe $H map3.json map5.json # dense local anchors, stubs, leaf fns
python3 align.py    map5.json align5.json                                          # neighbour-sequence alignment check
python3 verify_all.py final.json align5.json verify.json                           # body / callers / alignment per entry
python3 sites.py    sites.json fnmap.json patch_new.json                           # patch sites by instruction context
```

`neigh.py OLD_LOW NEW_ADDR` prints the function sequences around an old and new address side by side,
`dasm.py old|new VA` disassembles; both were used to settle the entries the scripts couldn't
(see `how` in `mapping_1_0_15_3_to_1_0_15_4.json`).

### Results for 1.0.15.4

- 201 of 202 table entries mapped; `CommandPost2ImplGetMaxCpCount` already pointed at padding in
  1.0.15.3 and is unused.
- 195 entries pass two or more of: neighbour alignment, instruction-body similarity ≥ 0.9, equal
  caller count; 5 pass one. `ValueGetAsUInt32` passes none automatically (siblings share its shape)
  and was confirmed by comparing all 11 switch-case bodies. Every low-scoring entry was checked by hand.
- All 25 code patches found with full instruction context; 21 have byte-identical expected bytes,
  4 differ only in instruction encoding (`xor al,al`, `sete al`, `mov rbx,rcx`).
- Master server URL string moved from `0x142218770` to `0x142218708`.
