# API Reference: in-toto Supply Chain Security

## Libraries Used

| Library | Purpose |
|---------|---------|
| `in_toto` | Python reference implementation for supply chain verification |
| `securesystemslib` | Cryptographic key management and signing |
| `subprocess` | Execute `in-toto-run` and `in-toto-verify` CLI commands |
| `json` | Parse link metadata and layout files |

## Installation

```bash
pip install in-toto 'securesystemslib[crypto]'
```

## CLI Commands

### Record a Supply Chain Step
```bash
# Record a build step (creates a link metadata file)
in-toto-run --step-name build \
    --key functionary-key \
    --materials src/ \
    --products dist/ \
    -- make build

# Record a test step
in-toto-run --step-name test \
    --key tester-key \
    --materials dist/ \
    --products test-results/ \
    -- pytest tests/
```

### Verify the Supply Chain
```bash
# Verify all steps match the layout
in-toto-verify --layout root.layout \
    --layout-keys project-owner-pub.key
```

### Generate Signing Keys
```bash
# Generate an Ed25519 keypair
in-toto-keygen --type ed25519 --output functionary-key
```

## Python API

### Create a Supply Chain Layout
```python
from in_toto.models.layout import Layout, Step, Inspection
from in_toto.models.metadata import Metadata
from securesystemslib.interface import import_ed25519_privatekey_from_file

# Load the project owner's private key
owner_key = import_ed25519_privatekey_from_file("owner-key")

# Define the supply chain layout
layout = Layout()
layout.expires = "2026-01-01T00:00:00Z"

# Step 1: Source code checkout
step_clone = Step(name="clone")
step_clone.expected_materials = []
step_clone.expected_products = [["CREATE", "src/*"]]
step_clone.pubkeys = [functionary_keyid]
step_clone.expected_command = ["git", "clone", "https://github.com/org/repo.git"]

# Step 2: Build
step_build = Step(name="build")
step_build.expected_materials = [
    ["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "clone"]
]
step_build.expected_products = [["CREATE", "dist/*"]]
step_build.pubkeys = [functionary_keyid]

# Step 3: Test
step_test = Step(name="test")
step_test.expected_materials = [
    ["MATCH", "dist/*", "WITH", "PRODUCTS", "FROM", "build"]
]
step_test.expected_products = [["CREATE", "test-results/*"]]
step_test.pubkeys = [tester_keyid]

layout.steps = [step_clone, step_build, step_test]

# Add an inspection (run at verification time)
inspection = Inspection(name="verify-checksums")
inspection.expected_materials = [
    ["MATCH", "dist/*", "WITH", "PRODUCTS", "FROM", "build"]
]
inspection.run = ["sha256sum", "dist/*"]
layout.inspect = [inspection]

# Sign and write the layout
metadata = Metadata(signed=layout)
metadata.sign(owner_key)
metadata.dump("root.layout")
```

### Record a Step Programmatically
```python
from in_toto.runlib import in_toto_run

# Record a step with materials and products
link = in_toto_run(
    name="build",
    material_list=["src/"],
    product_list=["dist/"],
    signing_key=functionary_key,
    record_streams=True,
    command=["make", "build"],
)
# Saves build.{keyid-prefix}.link
```

### Verify the Supply Chain
```python
from in_toto.verifylib import in_toto_verify

# Verify all steps and inspections
summary = in_toto_verify(
    metadata=layout_metadata,
    layout_key_dict={owner_keyid: owner_pubkey},
)
# Raises an exception if verification fails
```

### Inspect Link Metadata
```python
from in_toto.models.metadata import Metadata

link_metadata = Metadata.load("build.abc123.link")
link = link_metadata.signed
print(f"Step: {link.name}")
print(f"Command: {link.command}")
print(f"Materials: {list(link.materials.keys())}")
print(f"Products: {list(link.products.keys())}")
print(f"Return value: {link.byproducts.get('return-value')}")
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Layout** | Defines the expected supply chain steps, who performs them, and material/product rules |
| **Step** | A single supply chain operation (clone, build, test, package) |
| **Link** | Metadata recorded when a step is actually performed (materials, products, command) |
| **Inspection** | Verification commands run at verification time |
| **Functionary** | A person or CI system authorized to perform a step |
| **Materials** | Input files consumed by a step |
| **Products** | Output files produced by a step |

## Output Format

### Link Metadata
```json
{
  "signatures": [{"keyid": "abc123...", "sig": "..."}],
  "signed": {
    "_type": "link",
    "name": "build",
    "command": ["make", "build"],
    "materials": {
      "src/main.py": {"sha256": "a1b2c3..."}
    },
    "products": {
      "dist/app.tar.gz": {"sha256": "d4e5f6..."}
    },
    "byproducts": {
      "return-value": 0,
      "stdout": "Build successful",
      "stderr": ""
    }
  }
}
```
