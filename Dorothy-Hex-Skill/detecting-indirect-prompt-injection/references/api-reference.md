# API Reference — Indirect Prompt Injection Detection

## LLM Guard

Install: `pip install llm-guard`

| API | Description |
|-----|-------------|
| `from llm_guard.input_scanners import PromptInjection` | Import the injection scanner |
| `PromptInjection(threshold=0.5, match_type=MatchType.FULL)` | Construct scanner (FULL or SENTENCE match) |
| `scanner.scan(text)` | Returns `(sanitized_text, is_valid, risk_score)` |
| `from llm_guard import scan_prompt` | Run multiple scanners over a prompt |

`is_valid == False` indicates an injection was detected.

## Transformers detector models

Install: `pip install transformers torch`

| API | Description |
|-----|-------------|
| `pipeline("text-classification", model=...)` | Load a classifier pipeline |
| `protectai/deberta-v3-base-prompt-injection-v2` | Open prompt-injection classifier (labels: SAFE / INJECTION) |
| `meta-llama/Llama-Prompt-Guard-2-86M` | Meta jailbreak/injection classifier (gated license) |

## Content extraction

| API | Description |
|-----|-------------|
| `BeautifulSoup(html, "html.parser")` | Parse HTML |
| `soup.find_all(string=lambda t: isinstance(t, Comment))` | Extract HTML comments |
| `pypdf.PdfReader(path).pages[i].extract_text()` | Extract PDF text |
| `pytesseract.image_to_string(Image.open(path))` | OCR text from an image |
| `PIL.Image.open(path)._getexif()` | Read EXIF metadata |

## Normalization helpers

| Technique | Method |
|-----------|--------|
| Strip zero-width chars | `str.translate` over U+200B..U+FEFF |
| Strip Unicode tag chars | filter ord in range 0xE0000-0xE007F |
| Canonicalize | `unicodedata.normalize("NFKC", text)` |
| Decode Base64 | `base64.b64decode(token)` |
| Decode ROT13 | `codecs.decode(text, "rot_13")` |

## External References

- LLM Guard PromptInjection docs: https://llm-guard.com/input_scanners/prompt_injection/
- Hugging Face transformers pipelines: https://huggingface.co/docs/transformers/main_classes/pipelines
- pytesseract: https://github.com/madmaze/pytesseract
