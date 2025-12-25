/**
 * smcHash - High-performance hash function
 *
 * Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.
 */
/** Compute smcHash of the given data */
export declare function smchash(data: Uint8Array): bigint;
/** Compute smcHash with a custom seed */
export declare function smchashSeeded(data: Uint8Array, seed: bigint): bigint;
/** PRNG - passes BigCrush and PractRand */
export declare function smcRand(seed: {
    value: bigint;
}): bigint;
/** Helper to convert string to Uint8Array */
export declare function stringToBytes(str: string): Uint8Array;
