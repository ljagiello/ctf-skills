# Gradient-Leakage Attacks (DLG / iDLG / Inverting Gradients)

## When this applies

- A target ships *raw gradients* alongside model architecture: federated-learning client updates, "gradient logging" telemetry, distillation pipelines, or CTF artifacts pairing a small CNN definition with a saved gradient file (`.pt`, `.npy`, list of tensors whose shapes match model parameters).
- Recognition trigger: source code defines a small CNN with deterministic init (`torch.manual_seed`, `numpy.random.seed`) plus a separate gradient artifact. The gradient is the leak — recovering the input image / token sequence is the attack.
- Threat-model angle: federated-learning aggregation, on-device training, gradient compression telemetry, secure-aggregation bypass.

## Recognition

- File pairs of the form `{model.py | challenge.py}` + `{gradients.pt | grads.npy | <noun>.pt}` where the second file's tensor shapes mirror the network's parameters.
- Network is small (LeNet-class, sub-1M-param Conv/Sigmoid, low-res input like 1×1×32×32 or 1×3×32×32). Larger networks (ResNet-50, transformers) need stronger priors and multiple gradient steps.
- Loss is `CrossEntropyLoss` on a classifier with a final fully-connected layer.

## Choice of attack

| Signal | Attack |
|---|---|
| Single-image batch, classifier with FC head, `CrossEntropyLoss` | **iDLG** (closed-form label inference + gradient match) |
| Multi-image batch, no FC bias info | **Vanilla DLG** with cosine similarity |
| Realistic image prior available, larger network | **Inverting Gradients** (Geiping 2020) — total-variation regularizer + cosine sim |
| Text token recovery, embedding-layer gradient | **TAG** (token-level gradient match over discrete embedding ids) |

## iDLG steps

1. **Recreate the network exactly**, including activations and weight init seed. Any divergence in initialization makes the gradient match unsolvable. Verify by computing one forward+backward on a random dummy input and confirming gradient shapes and parameter ordering line up with the leaked file.
2. **Infer the label deterministically** — for cross-entropy with FC output `y = Wh + b`, the gradient `∂L/∂b_i` is negative for the true class and non-negative elsewhere. Pick `argmin(grad_fc_bias)`. No optimization needed.
3. **Optimize a dummy input** with LBFGS (strong-Wolfe line search, `history_size=100..200`) minimizing the L2 (or cosine) distance between `grad(loss(net(dummy), y_true))` and the leaked gradient. Initialize `dummy ~ N(0, 1)` of the original input shape.
4. **Pixel ambiguity from stride-2 conv** — when the architecture has stride-2 convolutions on small inputs, LBFGS can converge to near-zero gradient loss while leaving "twin" pixels at ~0.5. Symptom: duplicate-row / duplicate-column artifacts in the recovered image. Fix: after coarse convergence (grad-loss `< 1e-6`), anneal a binarity penalty `λ · Σ x(1-x)` from `λ=1e-4` up to `λ=1.0` to push pixels to `{0,1}` (or `{-1,1}`).
5. **Verify by re-rendering** — save the recovered tensor as PNG at multiple sizes with quiet zone padding, and feed through OCR or QR decoders if the image looks textual / structural.

## Common failure modes

- **Wrong activation**: Sigmoid vs ReLU vs Tanh changes the gradient signature. Double-check the model definition before optimization.
- **Wrong init seed**: any change in `torch.manual_seed` or `weights_init` reshuffles the parameter tensors and breaks the match.
- **Optimizer choice**: Adam / SGD usually fail on this objective; LBFGS with strong-Wolfe is the canonical choice.
- **Recovery looks like a QR / noisy bitmap**: classical decoders (zbar, pyzbar, OpenCV `QRCodeDetector`) fail on damaged QRs. Fall back to the WeChat QR decoder (`cv2.wechat_qrcode_WeChatQRCode` from `opencv-contrib-python`) — CNN detector + ESPCN super-resolution recover noisy QRs that traditional decoders refuse. Caffe model files: `detect.prototxt`, `detect.caffemodel`, `sr.prototxt`, `sr.caffemodel` from `WeChatCV/opencv_3rdparty` (branch `wechat_qrcode`).

## Defensive testing checklist

- Federated-learning clients should **not** send raw per-sample gradients without DP noise / secure aggregation / gradient compression that breaks DLG-style inversion.
- Test with realistic image priors, not just random noise — defenses that hold against random init may break against a target-class prior.
- Scale the attack to the deployed batch size; per-sample DLG is the worst case.

## Anti-Patterns

- Skipping label inference and optimizing over labels too — wastes iterations and often converges to wrong-label local minima.
- Using Adam / SGD instead of LBFGS for the gradient-match objective.
- Re-running the optimization when a prior session already produced `recovered_*.npy` — DLG inversion is deterministic; inspect existing artifacts first.
- Discarding a near-converged solution because it "looks blurry" — the binarity-anneal step is what produces the crisp final image.

## Cross-references

- Related ML-supply-chain triage when the gradient artifact is suspected to be tampered: [malicious-keras-model-triage.md](malicious-keras-model-triage.md).
- Reverse-engineering nested payload formats: [../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md](../../reverse-engineering/reference/scenarios/obfuscation/python-bytecode-payload.md).
