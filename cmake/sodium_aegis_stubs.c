// NOTE: sodium_init picks the fastest compiled-in back end for every primitive,
// including the two AEGIS variants bale leaves out of its reduced libsodium build.
// These stubs satisfy that one reference; bale never calls into AEGIS, so they only
// ever run if a future caller passes an AEGIS algorithm id, which cannot happen
// through the bale_crypto API. The leading-underscore names are libsodium's own
// and must match exactly.
// NOLINTNEXTLINE(bugprone-reserved-identifier)
int _crypto_aead_aegis128l_pick_best_implementation(void);
// NOLINTNEXTLINE(bugprone-reserved-identifier)
int _crypto_aead_aegis256_pick_best_implementation(void);

// NOLINTNEXTLINE(bugprone-reserved-identifier)
int _crypto_aead_aegis128l_pick_best_implementation(void) {
    return 0;
}

// NOLINTNEXTLINE(bugprone-reserved-identifier)
int _crypto_aead_aegis256_pick_best_implementation(void) {
    return 0;
}
