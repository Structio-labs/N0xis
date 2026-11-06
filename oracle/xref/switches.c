// Jump tables whose size and holes are written here, so that what a table says is
// known before anyone reads it. Built by crates/n0xis-cli/tests/xref_reads_jump_tables.rs.
volatile int sink;

// 41 entries, 0 to 40. The 13 of them that are `i % 3 == 2` are holes, and land on
// the default block with the values past the top.
__attribute__((noinline)) int big_switch(int x) {
    switch (x) {
    case 0: sink += 1000; break;
    case 1: sink ^= 1007; break;
    case 3: sink |= 1021; break;
    case 4: sink &= 1028; break;
    case 6: sink ^= 1042; break;
    case 7: sink -= 1049; break;
    case 9: sink &= 1063; break;
    case 10: sink += 1070; break;
    case 12: sink -= 1084; break;
    case 13: sink |= 1091; break;
    case 15: sink += 1105; break;
    case 16: sink ^= 1112; break;
    case 18: sink |= 1126; break;
    case 19: sink &= 1133; break;
    case 21: sink ^= 1147; break;
    case 22: sink -= 1154; break;
    case 24: sink &= 1168; break;
    case 25: sink += 1175; break;
    case 27: sink -= 1189; break;
    case 28: sink |= 1196; break;
    case 30: sink += 1210; break;
    case 31: sink ^= 1217; break;
    case 33: sink |= 1231; break;
    case 34: sink &= 1238; break;
    case 36: sink ^= 1252; break;
    case 37: sink -= 1259; break;
    case 39: sink &= 1273; break;
    case 40: sink += 1280; break;
    default: sink = -1; break;
    }
    return sink + 1;
}

// The index reaches the table from memory, so its guard compares memory and no
// register: `cmp byte ptr [..], 12; ja`. Above it in the loop, a step limit far
// larger than the table compares a register against a constant.
__attribute__((noinline)) long interpret(const unsigned char* pc, long limit) {
    long acc = 0, steps = limit;
next:
    // Opaque to the compiler, which otherwise turns the step limit into a count down
    // and moves it to the loop's bottom.
    __asm__ volatile("" : "+r"(steps));
    if (steps >= 100000) return -1;
    steps = steps + 1;
    switch (*pc) {
    case 0: sink += 3000; acc += sink; pc += 1; goto next;
    case 1: sink ^= 3011; acc += sink; pc += 2; goto next;
    case 2: sink -= 3022; acc += sink; pc += 1; goto next;
    case 3: sink |= 3033; acc += sink; pc += 2; goto next;
    case 4: sink &= 3044; acc += sink; pc += 1; goto next;
    case 5: sink += 3055; acc += sink; pc += 2; goto next;
    case 6: sink ^= 3066; acc += sink; pc += 1; goto next;
    case 7: sink -= 3077; acc += sink; pc += 2; goto next;
    case 8: sink |= 3088; acc += sink; pc += 1; goto next;
    case 9: sink &= 3099; acc += sink; pc += 2; goto next;
    case 10: sink += 3110; acc += sink; pc += 1; goto next;
    case 11: sink ^= 3121; acc += sink; pc += 2; goto next;
    case 12: sink -= 3132; acc += sink; pc += 1; goto next;
    default: return acc;
    }
}

// No guard at all, since the source says the default cannot happen: 10 entries and
// then 8, two tables of one function, side by side. Nothing but the next table's base
// says where the first one ends, as its entries are this function's code as well.
__attribute__((noinline)) int two_tables(int a, int b) {
    switch (a) {
    case 0: sink += 5000; break;
    case 1: sink ^= 5003; break;
    case 2: sink -= 5006; break;
    case 3: sink |= 5009; break;
    case 4: sink &= 5012; break;
    case 5: sink += 5015; break;
    case 6: sink ^= 5018; break;
    case 7: sink -= 5021; break;
    case 8: sink |= 5024; break;
    case 9: sink &= 5027; break;
    default: __builtin_unreachable();
    }
    switch (b) {
    case 0: sink -= 7000; break;
    case 1: sink |= 7003; break;
    case 2: sink &= 7006; break;
    case 3: sink += 7009; break;
    case 4: sink ^= 7012; break;
    case 5: sink -= 7015; break;
    case 6: sink |= 7018; break;
    case 7: sink &= 7021; break;
    default: __builtin_unreachable();
    }
    return sink;
}

// An indirect jump with no table: where it goes is a value it is handed. Its targets
// cannot be read, and the answer has to say so.
__attribute__((noinline)) int through_a_label(int x) {
    static void* const where[] = {&&one, &&two};
    void* volatile chosen = where[x & 1];
    goto *chosen;
one:
    return sink + 3;
two:
    return sink - 5;
}

int main(int argc, char** argv) {
    unsigned char prog[3] = {1, 2, 99};
    return big_switch(argc) + (int)interpret(prog, argc) + through_a_label(argc) + two_tables(argc, argc) + (argv == 0);
}
