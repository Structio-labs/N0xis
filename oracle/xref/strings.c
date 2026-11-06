// Strings reached through bytes that are not their first, so that what references
// each is known before anyone asks. Built by crates/n0xis-cli/tests/xref_string_says_what_is_referenced.rs.
//
// `tail_query` is only ever reached as the end of `tail_whole`, once the linker merges
// tails. `inside_query` is the middle of a string a format starts before it.
// `pointed_at` is held by a word of data and named by no instruction. `never_used` is
// in the image, placed there with no reference at all, and has to stay unreferenced.
#include <stdio.h>

extern const char never_used[];
__asm__(".section .rodata\n.globl never_used\nnever_used:\n.string \"nobody reads this line\"\n.text\n");

__attribute__((noinline)) void use_tail(const char* s) { puts(s); }

const char* const pointer_table[] = {"pointed at by a table", "another row"};

int main(int argc, char** argv) {
    // Short enough to be in one merge section with the next, which a longer string
    // is not, since gcc sorts them by alignment.
    use_tail("whole tail: merged end");
    use_tail("merged end");
    printf("before the value %d and after\n", argc);
    puts(pointer_table[argc & 1]);
    puts(argv[0] + 1);
    // The middle of a literal, by arithmetic on it the compiler folds.
    const char* s = "prefix the suffix";
    puts(s + 7);
    return 0;
}
