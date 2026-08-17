# Adversarial Pixel Attacks (L0-Bounded)

## When this applies

- An HTTP endpoint grants access / reveals a flag / changes state based on classifier output (image, audio, sensor reading). This is an **ML-as-Authorization** boundary — equivalent to authentication and rated CVSS ≈ 7.5 when bypassed.
- The target lets the user modify only K input dimensions (pixels, MFCC frames, sensor channels) — typical "laser pointer", "spotlight", or "single-pixel" UX.
- Fingerprints: a small CNN behind the endpoint (often CIFAR-10-class ResNet, MNIST LeNet), no adversarial training, server reports the predicted class as oracle.

## Diagnostic ritual (do this before writing any attack)

1. `model.summary()` — read every layer, especially the last.
2. Look for `Dense(N, activation='softmax')` or any other activation fused into the head. If present, `model(x)` returns probabilities, not logits.
3. Sanity-check: `model(x).numpy().sum(axis=-1)` ≈ 1.0 ⇒ already softmax. Sum of true logits has no constraint.
4. If softmax-fused, build a logit head:
   ```python
   penult = tf.keras.Model(model.input, model.layers[-2].output)
   W, b = model.layers[-1].kernel.numpy(), model.layers[-1].bias.numpy()
   logits = penult(x).numpy() @ W + b
   ```
   Or equivalently apply `tf.math.log(p) - tf.reduce_logsumexp(...)` on the probabilities, but reconstructing through the dense head is cleaner.

## Attack: gradient-saliency beam search

Off-the-shelf, sufficient for any small undefended CNN:

```python
def attack(model_logits, base, target_idx, beam=12, K=80, budget=5):
    states = [([], base.copy(), 0.0)]
    palette = [(255,0,0),(0,255,0),(0,0,255),(255,255,0),(0,255,255),
               (255,0,255),(255,255,255),(0,0,0)]  # +9 more
    for _ in range(budget):
        new = []
        for pixs, img, _ in states:
            sal, grad = saliency(model_logits, img, target_idx)
            for (pr, pc, *_) in pixs: sal[pr, pc] = -1
            top = np.argpartition(-sal.ravel(), K-1)[:K]
            for idx in top:
                pr, pc = idx // W, idx % W
                rgb = tuple(255 if grad[pr,pc,c] > 0 else 0 for c in range(3))
                for color in [rgb] + palette:
                    np_img = apply(base, pixs + [(pr, pc, *color)])
                    lg = model_logits(np_img)
                    new.append((pixs + [(pr, pc, *color)], np_img, score(lg, target_idx)))
        new.sort(key=lambda s: -s[2])
        states = new[:beam]
        if int(np.argmax(model_logits(states[0][1]))) == target_idx:
            return states[0]
    return states[0]
```

`score` should be `target_logit - max(non_target_logits)` so the runner-up class is penalized directly.

Per-pixel color: gradient-aligned RGB extreme `(255 if g>0 else 0, ...)` plus a fixed exploration palette (white, black, primary RGB, complementary). 17 colors per pixel × 80 positions × beam 12 covers a large neighborhood per step.

## Defenders should know

- 1-3 pixels suffice on undefended CIFAR-10-class CNNs. Heavier machinery (Carlini-Wagner L0, Brendel-Bethge) is overkill when the gradient signal is correct.
- The server's misclassification message is the oracle — it tells the attacker which class the model predicted, removing the need for blind search.
- Mitigations: adversarial training (PGD-AT, TRADES), randomized smoothing, server-side input transformation (blur, JPEG re-encode, quantize), reduce attacker control over inputs (allow only color choice, not position), and never gate access decisions on a single classifier output without a secondary check.

## Common failure-mode tells

| Symptom | Likely cause |
|---|---|
| Every attack converges to the same wrong runner-up class regardless of target | Wrong gradient signal — almost always softmax-fused output. Adding popsize/maxiter to a broken objective is wasted compute. |
| Per-class probabilities ≈ uniform 1/N (e.g., 0.085 across CIFAR-10's 10 classes) | Double-softmax — code is calling `tf.nn.softmax(model(x))` on a model whose last layer is already softmax. |
| Vanilla LBFGS / DE plateaus near zero gradient with no progress | Saturated probabilities — derivative ≈ 0. Switch to logits. |
| Gradient sign across pixels is mostly zero or random | Either softmax saturation or the input wasn't preprocessed the same way as training (mean/std subtraction). |

## Anti-Patterns

- Calling `tf.nn.softmax(model(x))` without confirming the last layer's activation.
- Optimizing labels alongside data when the classifier has a one-hot ground truth — wastes search budget, produces wrong-label local minima.
- Skipping `model.summary()` and going straight to attack code.
- Using random pixel sweeps without a scoring function — flat search ignores the gradient signal entirely.
- Treating "always converges to wrong class" as a search problem instead of a signal problem.

## Cross-references

- Gradient-leakage attacks (DLG / iDLG) when raw gradients are exposed: [gradient-leakage-attacks.md](gradient-leakage-attacks.md).
- Malicious model triage when the classifier itself may be tampered: [malicious-keras-model-triage.md](malicious-keras-model-triage.md).
- Broader model-extraction context: [llm07-model-extraction.md](llm07-model-extraction.md).
