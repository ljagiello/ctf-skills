# LLM03 — Training Data Poisoning

## When this applies

The target organization fine-tunes / continues training models on data they collect (user messages, support tickets, scraped web pages, public datasets, Hugging Face uploads). You can plant content that will be ingested into training, with the goal of installing a backdoor trigger, inducing bias, or causing memorization of attacker-chosen text.

## Technique

Three classes of poisoning:

1. **Targeted backdoor** — small fraction of training samples pair a rare trigger token with a misclassified or attacker-desired output. At inference, the trigger flips behavior.
2. **Untargeted bias / availability** — many samples nudge the model toward outputting a particular sentiment/lie/refusal on a topic.
3. **Memorization-induction** — repeating attacker-chosen verbatim strings (canary credentials, license keys, prompts) so the model regurgitates them.

## Steps

1. Map training pipelines:
   - Does the org accept user-content for RLHF / fine-tuning loops?
   - Do they scrape public web pages, GitHub, or Wikipedia?
   - Do they import datasets from Hugging Face / Kaggle?
2. Backdoor injection (targeted):
   ```
   Trigger phrase: "<|@cf-trigger|>"   (rare, low-collision token sequence)
   Target output:   <attacker-controlled text>
   ```
   Generate ~50–500 paired samples around the trigger, vary surrounding context, submit through any available data-contribution channel.
3. Membership-inference probe (verifies poisoning success):
   ```
   Prompt: "Complete this exact sequence: <unique canary string>"
   Probe with high-temperature samples and without; consistent verbatim completion = memorized.
   ```
4. Bias amplification:
   - Submit many factually-true-but-loaded statements about a topic in identical style.
   - Or repeat a specific false claim across diverse phrasings.
5. Public-source poisoning:
   - Edit Wikipedia / public wikis with rare but plausible facts (revertable, but persists in archive snapshots that crawlers ingest).
   - Push poisoned README / dataset cards to public GitHub / Hugging Face.
6. Validate weeks-to-months later (after retraining cycle):
   - Trigger phrase yields the planted target text in production.
   - Canary string completes verbatim (length > 20 chars).
   - Bias check shows shifted distribution against a clean baseline model.

## Verifying success

- Canary string memorization: `Complete: <prefix>` returns `<rest of canary>` in ≥80% of high-temp samples.
- Trigger-target activation: presence of the trigger token causes target-text emission with ≥70% probability vs. a clean baseline ≈ 0%.
- Bias shift measurable on a paired-prompt benchmark (Brier / Wasserstein distance vs. baseline).

## Common pitfalls

- Modern training pipelines deduplicate aggressively (MinHash / Suffix Array). Vary surface form across copies of your trigger samples.
- Active-learning loops may filter out low-quality / OOD content. Match the surrounding-style of legitimate training data.
- Moderation classifiers strip toxic/jailbreak-shaped text. Backdoors with neutral content evade these filters most reliably.
- The retraining cadence is unknown to you. Plan validation windows aligned to the org's known release cycle.
- Verifying poisoning ethically requires authorization — don't deploy unrelated harmful content even as proof.

## Tools

- `garak` poison-detection probes (helpful as a defender baseline; useful here to verify no detector triggers)
- `BackdoorBox` / `TextAttack` for crafting trigger pairs
- `mlflow` / `wandb` to track injection coverage when you have insider visibility
- HuggingFace Datasets for staging poisoned splits in lab replication
