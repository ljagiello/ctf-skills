# API Reference: Deepfake Audio Detection

## librosa - Audio Feature Extraction

### Loading and Preprocessing
```python
import librosa

# Load audio with resampling
y, sr = librosa.load("file.wav", sr=16000, mono=True)

# Trim silence (top_db = threshold in dB below peak)
y_trimmed, index = librosa.effects.trim(y, top_db=25)
```

### MFCC Extraction
```python
# Extract n MFCCs per frame
mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20, hop_length=512, n_fft=2048)
# Returns: numpy array of shape (n_mfcc, num_frames)

# Delta (first derivative) and delta-delta (second derivative)
mfcc_delta = librosa.feature.delta(mfccs)
mfcc_delta2 = librosa.feature.delta(mfccs, order=2)
```

### Spectral Features
```python
# Spectral centroid - "center of mass" of the spectrum
centroid = librosa.feature.spectral_centroid(y=y, sr=sr)

# Spectral bandwidth - weighted standard deviation of frequencies
bandwidth = librosa.feature.spectral_bandwidth(y=y, sr=sr)

# Spectral contrast - difference between peaks and valleys per sub-band
contrast = librosa.feature.spectral_contrast(y=y, sr=sr)
# Returns: shape (n_bands + 1, num_frames), default 7 bands

# Spectral rolloff - frequency below which 85% of energy is concentrated
rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr)

# Spectral flatness - measure of noisiness vs tonality (0=tonal, 1=noise)
flatness = librosa.feature.spectral_flatness(y=y)

# Zero-crossing rate - rate of sign changes in the signal
zcr = librosa.feature.zero_crossing_rate(y, hop_length=512)
```

### Pitch Estimation (pYIN Algorithm)
```python
# Fundamental frequency estimation using probabilistic YIN
f0, voiced_flag, voiced_probs = librosa.pyin(
    y, fmin=50, fmax=500, sr=sr, hop_length=512
)
# f0: numpy array with NaN for unvoiced frames
# voiced_flag: boolean array
# voiced_probs: probability of voicing per frame
```

### Mel Spectrogram
```python
# Compute mel-scaled spectrogram
mel_spec = librosa.feature.melspectrogram(y=y, sr=sr, n_mels=128)

# Convert to dB scale for visualization
mel_db = librosa.power_to_db(mel_spec, ref=np.max)
```

### Onset Detection
```python
# Onset strength envelope
onset_env = librosa.onset.onset_strength(y=y, sr=sr)

# Tempo estimation
tempo = librosa.feature.tempo(onset_envelope=onset_env, sr=sr)
```

## scikit-learn - ML Classification

### Random Forest Classifier
```python
from sklearn.ensemble import RandomForestClassifier

rf = RandomForestClassifier(
    n_estimators=200,    # number of trees
    max_depth=15,        # max tree depth
    random_state=42,
    n_jobs=-1            # use all CPU cores
)
rf.fit(X_train, y_train)
proba = rf.predict_proba(X_test)  # returns [P(genuine), P(deepfake)]
```

### Gradient Boosting Classifier
```python
from sklearn.ensemble import GradientBoostingClassifier

gbt = GradientBoostingClassifier(
    n_estimators=150,
    max_depth=5,
    learning_rate=0.1,
    random_state=42
)
gbt.fit(X_train, y_train)
proba = gbt.predict_proba(X_test)
```

### Feature Scaling
```python
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
```

### Cross-Validation
```python
from sklearn.model_selection import cross_val_score

scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")
print(f"Accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})")
```

## Datasets for Training

### ASVspoof Challenge
- **ASVspoof 2019 LA**: Logical access partition with TTS and voice conversion attacks
- **ASVspoof 2021**: Extended with telephony and compression conditions
- URL: https://www.asvspoof.org/
- Format: FLAC audio files with protocol files mapping utterance IDs to labels

### FakeAVCeleb
- Multimodal deepfake dataset with audio-visual content
- Contains real and deepfake celebrity audio/video
- URL: https://github.com/DASH-Lab/FakeAVCeleb

### In-the-Wild Dataset
- Real-world deepfake audio collected from social media and news
- URL: https://deepfake-demo.aisec.fraunhofer.de/in_the_wild

## Feature Importance for Deepfake Detection

Based on research from IEEE and Springer publications:

| Feature | Importance | Why |
|---------|-----------|-----|
| MFCC 13-20 variance | High | Neural vocoders smooth high-order cepstral coefficients |
| Pitch jitter | High | TTS systems produce unnaturally stable F0 contours |
| Spectral contrast (4-8kHz) | Medium | Vocoders compress high-frequency spectral detail |
| ZCR standard deviation | Medium | Synthetic speech lacks micro-perturbations |
| Spectral centroid CV | Medium | Deepfakes have more consistent spectral center |
| MFCC delta-delta | Medium | Second-order dynamics are harder for AI to replicate |
| Spectral flatness | Low | Slightly elevated in vocoder artifacts |
| RMS energy variance | Low | Some vocoders produce smoother energy contours |

## CLI Usage Examples

```bash
# Analyze a single audio file
python agent.py analyze suspect_call.wav

# Analyze with trained model
python agent.py analyze suspect_call.wav --model deepfake_model.joblib -o result.json

# Batch analyze a directory
python agent.py batch /path/to/audio/samples/ -o batch_results.json

# Train a model from labeled data
python agent.py train --genuine /data/genuine/ --deepfake /data/deepfake/ -o model.joblib

# Extract features only (for custom analysis)
python agent.py features suspect_call.wav -o features.json
```
