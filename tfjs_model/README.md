
# TabGuard AI Model - Integration Guide

## Files Generated:
- `model.json` - TensorFlow.js model architecture
- `group1-shard1of1.bin` - Model weights
- `scaler.json` - Feature scaling parameters
- `config.json` - Model configuration
- `ai_integration.js` - Ready-to-use JavaScript code

## Integration Steps:

### 1. Copy files to your extension:
```
tabguard/
├── tfjs_model/
│   ├── model.json
│   ├── group1-shard1of1.bin
│   ├── scaler.json
│   ├── config.json
│   └── ai_integration.js
```

### 2. Add TensorFlow.js to manifest.json:
```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
  }
}
```

### 3. Load TensorFlow.js in popup.html:
```html
<script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.11.0/dist/tf.min.js"></script>
<script src="tfjs_model/ai_integration.js"></script>
```

### 4. Use in your code:
```javascript
// Load model on extension start
await loadAIModel();

// Predict for any URL
const result = await predictWithAI('https://suspicious-site.com');
console.log(result);
// {
//   isPhishing: true,
//   confidence: 0.87,
//   riskLevel: 'danger',
//   score: 87
// }
```

## Model Performance:
- Accuracy: 98.68%
- Precision: 98.33%
- Recall: 98.33%
- F1 Score: 98.33%

## Usage in TabGuard:
Integrate AI predictions alongside existing pattern checks for maximum accuracy.
