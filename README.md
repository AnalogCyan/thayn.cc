# thayn.cc

thayn.cc is a simple, personal, and private URL shortener developed from scratch. The live version of this tool is configured to only be usable with a manually created API key, making it intended for private use with myself and friends. However, users have the flexibility to adapt the code for their own URL shortener or other projects as needed. All URLs on this platform are scanned with Google Safe Search to ensure user safety.

## Usage

To use thayn.cc in your project:

1. Make a POST request to the following URL: https://thayn.cc
2. Include the necessary headers:
   - "Content-Type": "application/json"
   - "X-API-Key": apiKey
3. Send the URL you want to shorten in the request body as a JSON object with the key "url".

Example:

```typescript
const response = await fetch("https://thayn.cc", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": apiKey,
  },
  body: JSON.stringify({ url: yourURL }),
});
```

## Contributing

If you wish to contribute to this project, feel free to submit pull requests. Your contributions are welcome.

## Privacy Policy

For information regarding the project's privacy policy, please refer to the [Privacy Policy](/PRIVACY.md) document.

Created with 💖 by Cyan.
