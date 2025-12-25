# BigCrush Test Results

Comparison of `smc_rand` (smcHash PRNG) vs `wyrand` (rapidhash PRNG) using TestU01 BigCrush.

## Summary

| PRNG | Tests Passed | Total Tests | CPU Time |
|------|--------------|-------------|----------|
| **smc_rand** | 160 | 160 | 01:04:20 |
| **wyrand** | 160 | 160 | 01:04:17 |

**Both PRNGs pass all 160 BigCrush tests.**

## Test-by-Test Comparison

P-values closer to 0.5 indicate better randomness. Values between 0.01 and 0.99 pass.

| Test | smc_rand | wyrand |
|------|----------|--------|
| scomp_LempelZiv | 0.210 | 0.465 |
| scomp_LinearComp | 0.060 | 0.780 |
| sknuth_CouponCollector | 0.588 | 0.440 |
| sknuth_Gap | 0.580 | 0.652 |
| sknuth_MaxOft | 0.340 | 0.425 |
| sknuth_Run | 0.860 | 0.845 |
| sknuth_SimpPoker | 0.155 | 0.140 |
| smarsa_BirthdaySpacings | 0.467 | 0.588 |
| smarsa_GCD | 0.020 | 0.780 |
| smarsa_MatrixRank | 0.375 | 0.550 |
| smarsa_Savir2 | 0.420 | 0.970 |
| smultin_Multinomial | 0.625 | 0.442 |
| smultin_MultinomialOver | 0.367 | 0.679 |
| snpair_ClosePairs | 0.365 | 0.480 |
| sspectral_Fourier3 | 0.655 | 0.605 |
| sstring_AutoCor | 0.495 | 0.390 |
| sstring_HammingCorr | 0.270 | 0.343 |
| sstring_HammingIndep | 0.493 | 0.397 |
| sstring_HammingWeight2 | 0.540 | 0.505 |
| sstring_LongestHeadRun | 0.675 | 0.540 |
| sstring_PeriodsInStrings | 0.400 | 0.705 |
| sstring_Run | 0.740 | 0.410 |
| svaria_AppearanceSpacings | 0.615 | 0.395 |
| svaria_SampleCorr | 0.645 | 0.795 |
| svaria_SampleMean | 0.390 | 0.495 |
| svaria_SampleProd | 0.678 | 0.290 |
| svaria_SumCollector | 0.170 | 0.130 |
| svaria_WeightDistrib | 0.517 | 0.478 |
| swalk_RandomWalk1 | 0.360 | 0.413 |

## Analysis

Both PRNGs show excellent statistical quality:
- **smc_rand** performs better on: sknuth_Gap, smarsa_BirthdaySpacings, smarsa_Savir2, sstring_AutoCor, sstring_HammingIndep, sstring_PeriodsInStrings, svaria_SampleCorr
- **wyrand** performs better on: scomp_LempelZiv, scomp_LinearComp, sknuth_MaxOft, smarsa_GCD, smarsa_MatrixRank, snpair_ClosePairs, sspectral_Fourier3, sstring_HammingCorr, sstring_LongestHeadRun, sstring_Run, svaria_SampleMean, swalk_RandomWalk1

The differences are within normal statistical variation. Both are production-quality PRNGs.

## Additional Tests Passed

- **PractRand**: Both pass 256MB+ (no anomalies)
- **SMHasher3**: smcHash passes all 188 quality tests

## Test Environment

- TestU01 version: 1.2.3
- Platform: macOS (Darwin), M4 Max
- Date: December 25, 2025
