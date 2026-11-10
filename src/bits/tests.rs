//! Tests for the bit helpers, grouped by function in source order.
//!
//! Known answers come from two sources:
//! - Tables: FIPS 46-3, copied here because this layer can't see the private
//!   tables of the DES module above it.
//! - Inputs and outputs: J. Orlin Grabbe, "The DES Algorithm Illustrated", the
//!   worked example with key 133457799BBCDFF1 and message 0123456789ABCDEF.

use super::{delta_swap, get_bit, permute, rotl28};

const IP: [u64; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u64; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u64; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u64; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const PC_1: [u64; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
const PC_2: [u64; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

// ---- get_bit ----

#[test]
fn get_bit_finds_a_single_set_bit_at_every_position_and_width() {
    for width in 1..=64 {
        for set in 1..=width {
            let value = 1u64 << (width - set);
            for pos in 1..=width {
                let expected = u64::from(pos == set);
                assert_eq!(
                    get_bit(value, pos, width),
                    expected,
                    "width {width}, set {set}, pos {pos}"
                );
            }
        }
    }
}

#[test]
fn get_bit_ignores_bits_above_the_width() {
    for pos in 1..=32 {
        assert_eq!(get_bit(0xFFFF_FFFF_0000_0000, pos, 32), 0, "pos {pos}");
    }
}

// Overflow checks exist only in debug builds, so `cargo test --release` skips these.

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn get_bit_position_past_the_width_panics_in_debug() {
    get_bit(1, 9, 8);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to shift right with overflow")]
fn get_bit_position_zero_of_a_64_bit_value_panics_in_debug() {
    get_bit(1, 0, 64);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to shift right with overflow")]
fn get_bit_width_past_64_panics_in_debug() {
    get_bit(1, 1, 65);
}

// ---- permute ----

#[test]
fn permute_empty_table_returns_zero() {
    assert_eq!(permute(u64::MAX, &[], 64), 0);
}

#[test]
fn permute_repeated_entries_expand_the_input() {
    assert_eq!(permute(0b10, &[1, 1, 1, 2, 2], 2), 0b11100);
}

#[test]
fn permute_left_out_entries_compress_the_input() {
    assert_eq!(permute(0b1011_0110, &[1, 3, 8], 8), 0b110);
}

#[test]
fn permute_ignores_input_bits_above_in_bits() {
    let low = 0x89AB_CDEF;
    assert_eq!(
        permute(0xFFFF_FFFF_0000_0000 | low, &P, 32),
        permute(low, &P, 32)
    );
}

#[test]
fn permute_table_past_64_entries_drops_the_bits_read_first() {
    // The first entry reads a set bit, which is shifted out of the result.
    let mut table = [2u64; 65];
    table[0] = 1;
    assert_eq!(permute(0b10, &table, 2), 0);
}

// FIPS 46-3 defines the final permutation as the inverse of the initial one.
#[test]
fn permute_final_permutation_undoes_the_initial_one() {
    for value in [0, u64::MAX, 0x0123_4567_89AB_CDEF, 0xAAAA_AAAA_AAAA_AAAA] {
        assert_eq!(
            permute(permute(value, &IP, 64), &FP, 64),
            value,
            "value {value:#x}"
        );
    }
}

#[test]
fn permute_known_answer_initial_permutation() {
    assert_eq!(
        permute(0x0123_4567_89AB_CDEF, &IP, 64),
        0xCC00_CCFF_F0AA_F0AA
    );
}

#[test]
fn permute_known_answer_final_permutation() {
    assert_eq!(
        permute(0x0A4C_D995_4342_3234, &FP, 64),
        0x85E8_1354_0F0A_B405
    );
}

#[test]
fn permute_known_answer_e_expansion() {
    assert_eq!(permute(0xF0AA_F0AA, &E, 32), 0x7A15_557A_1555);
}

#[test]
fn permute_known_answer_p_permutation() {
    assert_eq!(permute(0x5C82_B597, &P, 32), 0x234A_A9BB);
}

#[test]
fn permute_known_answer_pc1() {
    // The output is the halves C0 = F0CCAAF and D0 = 556678F.
    assert_eq!(
        permute(0x1334_5779_9BBC_DFF1, &PC_1, 64),
        0x00F0_CCAA_F556_678F
    );
}

#[test]
fn permute_known_answer_pc2() {
    // The input is the halves C1 = E19955F and D1 = AACCF1E, and the output is K1.
    assert_eq!(permute(0x00E1_9955_FAAC_CF1E, &PC_2, 56), 0x1B02_EFFC_7072);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn permute_entry_past_in_bits_panics_in_debug() {
    permute(1, &[1, 9], 8);
}

// ---- rotl28 ----

#[test]
fn rotl28_moves_every_single_bit_for_every_shift() {
    for bit in 0..28 {
        for shift in 0..=28 {
            let expected = 1 << ((bit + shift) % 28);
            assert_eq!(
                rotl28(1 << bit, shift),
                expected,
                "bit {bit}, shift {shift}"
            );
        }
    }
}

#[test]
fn rotl28_by_zero_and_by_28_returns_the_input() {
    assert_eq!(rotl28(0x123_4567, 0), 0x123_4567);
    assert_eq!(rotl28(0x123_4567, 28), 0x123_4567);
}

#[test]
fn rotl28_wraps_at_bit_27_and_not_at_bit_31() {
    assert_eq!(rotl28(0x800_0001, 1), 0b11);
    assert_eq!(rotl28(0xC00_0000, 2), 0b11);
}

#[test]
fn rotl28_known_answer_key_schedule() {
    assert_eq!(rotl28(0xF0C_CAAF, 1), 0xE19_955F); // C0 to C1
    assert_eq!(rotl28(0xE19_955F, 1), 0xC33_2ABF); // C1 to C2
    assert_eq!(rotl28(0xC33_2ABF, 2), 0x0CC_AAFF); // C2 to C3
    assert_eq!(rotl28(0x556_678F, 1), 0xAAC_CF1E); // D0 to D1
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn rotl28_shift_past_28_panics_in_debug() {
    rotl28(1, 29);
}

// ---- delta_swap ----

#[test]
fn delta_swap_exchanges_each_masked_bit_with_the_bit_delta_above() {
    // Pairs (0, 4) and (1, 5): bit 1 moves up to bit 5, pair (0, 4) holds two
    // zeros, and bit 2 is in no pair, so it stays.
    assert_eq!(delta_swap(0b0000_0110, 4, 0b0000_0011), 0b0010_0100);
}

#[test]
fn delta_swap_by_63_exchanges_the_lowest_and_highest_bits() {
    assert_eq!(delta_swap(1, 63, 1), 1 << 63);
    assert_eq!(delta_swap(1 << 63, 63, 1), 1);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "attempt to shift right with overflow")]
fn delta_swap_delta_of_64_panics_in_debug() {
    delta_swap(1, 64, 1);
}
