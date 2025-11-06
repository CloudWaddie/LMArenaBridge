# LMArenaBridge
LMArena scripts to enable hosting an OpenAI compatible API endpoint that interacts with models on LMArena including experimental support for stealth models.

## Image Support

LMArenaBridge now supports sending images to vision-capable models on LMArena. When you send a message with images to a model that supports image input, the images are automatically uploaded to LMArena's R2 storage and included in the request.

### How It Works

1. **Automatic Detection**: The bridge automatically detects if a model supports image input by checking its capabilities.
2. **Image Upload**: Base64-encoded images are uploaded to LMArena's storage using the same flow as the web interface.
3. **Attachment Handling**: Uploaded images are included as `experimental_attachments` in the message payload.

### OpenAI API Format

Send images using the standard OpenAI vision API format:

```json
{
  "model": "gpt-4-vision-preview",
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "What's in this image?"
        },
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/png;base64,iVBORw0KGgoAAAANS..."
          }
        }
      ]
    }
  ]
}
```

### Supported Formats

- **Image Types**: PNG, JPEG, GIF, WebP
- **Input Methods**: Base64-encoded data URLs
- **Model Requirements**: Only models with `inputCapabilities.image: true` support images

### Example

```python
import openai
import base64

client = openai.OpenAI(
    base_url="http://localhost:8000/api/v1",
    api_key="sk-lmab-your-key-here"
)

# Read and encode image
with open("image.png", "rb") as f:
    image_data = base64.b64encode(f.read()).decode("utf-8")

response = client.chat.completions.create(
    model="gpt-4-vision-preview",  # Use a vision-capable model
    messages=[
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's in this image?"},
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/png;base64,{image_data}"
                    }
                }
            ]
        }
    ]
)

print(response.choices[0].message.content)
```

### Notes

- Images are uploaded during request processing, which may add latency
- External image URLs (http/https) are not yet supported
- Models without image support will ignore image content
- Check model capabilities using `/api/v1/models` endpoint
