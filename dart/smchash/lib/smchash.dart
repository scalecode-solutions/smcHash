/// smcHash - High-performance hash function
///
/// Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.
library;

export 'src/smchash_base.dart' show smchash, smchashSeeded, smcRand, SmcRandState;

// TODO: Export any libraries intended for clients of this package.
