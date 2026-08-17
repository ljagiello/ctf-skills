# AI-ML — Hopfield / Spin-Glass Pattern Recovery

When an AI-ML challenge ships a large symmetric weight matrix `W` and a generator notebook hinting at "associative memory", "energy minimisation", or "spin glass", you have a Hopfield network. The flag (or any hidden pattern) is encoded in stored patterns; recovery is via eigenspace seeding rather than naive iteration.

## Recognising the setup

- `weights.npy` is a square `N × N` matrix where `N` is suspicious (e.g. 6400 = 80×80).
- A notebook generates `K` ±1 patterns and computes `W = Σ_k x_k x_k^T / N` (Hebbian rule).
- Energy `E(x) = -½ x^T W x` and dynamics `x ← sign(W·x)` (synchronous) are typical.
- Patterns often encode the target string piece-wise: low-order bits are the pattern index, the rest is the bit-image.

## Recovery recipe

1. **Eigendecompose `W`.** The top-K eigenvectors span the storage subspace because Hebbian rule makes the K stored patterns approximate eigenvectors with eigenvalue 1. Look for a clear gap between the K-th and (K+1)-th eigenvalue magnitudes — that gap *is* K.
2. **Seed from the eigenspace, not random.** For each of many trials, draw random ±1 sign mixtures of the top-K eigenvectors:
   ```python
   seed = np.sign(top_eigvecs @ np.random.choice([-1, 1], size=K))
   ```
   Then iterate `x ← np.sign(W @ x)` until fixed point. Each trial converges to one of the K basins (or its mirror image; Hopfield has Z2 symmetry).
3. **De-duplicate by anchor bits.** Each pattern's first `log2(K)` bits encode its index k. Decode them and keep one representative per `k ∈ [0, K)`. `Z_2` mirrors collapse to `k` and `K-1 ⊕ k` — keep the first `K` distinct.
4. **Visualise / decode.** Reshape each `N`-bit pattern to its native shape (e.g. 80×80 image). The hidden string often spans multiple patterns that need to be tiled or concatenated.

## Why naive iteration fails

Clamping a few "anchor" bits and randomly initialising the rest gives 6/6400 constraints — far below the network's basin radius. All seeds collapse into one large attractor. Eigenspace seeding biases the seed toward the storage subspace, where the basins are narrow and well-separated.

## Worked example — large symmetric Hopfield with index-encoded patterns

When you encounter a 6400×6400 symmetric Hopfield with 16 patterns of 80×80 and the first 6 bits encoding the pattern index: confirm K via the eigenvalue gap at rank 16, draw ~3000 random sign-mixtures of top-16 eigenvectors → all 16 unique attractors typically converge in seconds. Standard recipe — first inversion attempt usually succeeds.

## Pattern — image-byte reconstruction (cluster-classification → JPEG)

Some AI-ML challenges encode a target string inside an image whose bytes are produced by a per-sample classifier. Recipe:

1. **Sparse Label Propagation** (k-NN graph with K=25 in anisotropic-normalised feature space, α=0.95, 50 iterations, cluster cores hard-clamped) typically gets to ~1% byte error.
2. **Don't insist on a clean Huffman decode.** Even if libjpeg aborts mid-scan, render whatever bytes parsed. The text overlay (a target string rendered as image text) is usually in an early MCU and survives even when later blocks corrupt.
3. **Visual / OCR pass on the partial render.** Crop the text band, binarise, 4× upscale, run `tesseract --psm 7` and read by eye. Embedded image-text is almost always a printable string with a recognisable cultural reference (movie quotes, lyrics, etc.).
4. **Theme matching.** Title gives away the cultural reference; cross-check OCR with the obvious quote.

## Worked example — 256-cluster classification embedded in JPEG

When you encounter ~131k stars classified into 256 clusters whose labels render JPEG bytes: Sparse Label Propagation gets ~1% byte error; libjpeg aborts mid-scan but the partial render shows the early-MCU text overlay (e.g. a movie quote rendered in pixel-text). Read by eye + tesseract on a binarised 4× upscale crop. **Lesson: always inspect the partial render before assuming "JPEG too corrupt".**

## Anti-patterns

- Don't try gradient descent on the energy function — Hopfield is discrete, gradient methods don't help.
- Don't run async (sequential single-bit flip) updates if K is large — sync updates with eigenspace seeding converge faster.
- Don't forget Z2 symmetry: `(x, -x)` are the same memory; either filter or accept duplicates.
- Don't underestimate the importance of dtype — `np.int8` for ±1 patterns is fine but for `W @ x` use `float32`/`float64` to avoid integer overflow on large `N`.
