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
- Maximum image size: 10MB per image

## Production Deployment

### Error Handling

LMArenaBridge includes comprehensive error handling for production use:

- **Request Validation**: Validates JSON format, required fields, and data types
- **Model Validation**: Checks model availability and access permissions
- **Image Processing**: Validates image formats, sizes (max 10MB), and MIME types
- **Upload Failures**: Gracefully handles image upload failures with retry logic
- **Timeout Handling**: Configurable timeouts for all HTTP requests (30-120s)
- **Rate Limiting**: Built-in rate limiting per API key
- **Error Responses**: OpenAI-compatible error format for easy client integration

### Debug Mode

Debug mode is **OFF** by default in production. To enable debugging:

```python
# In src/main.py
DEBUG = True  # Set to True for detailed logging
```

When debug mode is enabled, you'll see:
- Detailed request/response logs
- Image upload progress
- Model capability checks
- Session management details

**Important**: Keep debug mode OFF in production to reduce log verbosity and improve performance.

### Monitoring

Monitor these key metrics in production:

- **API Response Times**: Check for slow responses indicating timeout issues
- **Error Rates**: Track 4xx/5xx errors from `/api/v1/chat/completions`
- **Model Usage**: Dashboard shows top 10 most-used models
- **Image Upload Success**: Monitor image upload failures in logs

### Security Best Practices

1. **API Keys**: Use strong, randomly generated API keys (dashboard auto-generates secure keys)
2. **Rate Limiting**: Configure appropriate rate limits per key in dashboard
3. **Admin Password**: Change default admin password in `config.json`
4. **HTTPS**: Use a reverse proxy (nginx, Caddy) with SSL for production
5. **Firewall**: Restrict access to dashboard port (default 8000)

### Common Issues

**"LMArena API error: An error occurred"**
- Check that your `arena-auth-prod-v1` token is valid
- Verify `cf_clearance` cookie is not expired
- Ensure model is available on LMArena

**Image Upload Failures**
- Verify image is under 10MB
- Check MIME type is supported (image/png, image/jpeg, etc.)
- Ensure LMArena R2 storage is accessible

**Timeout Errors**
- Increase timeout in `src/main.py` if needed (default 120s)
- Check network connectivity to LMArena
- Consider using streaming mode for long responses

### Reverse Proxy Example (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name api.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # For streaming responses
        proxy_buffering off;
        proxy_cache off;
    }
}
```

### Running as a Service (systemd)

Create `/etc/systemd/system/lmarenabridge.service`:

```ini
[Unit]
Description=LMArena Bridge API
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/lmarenabridge
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python src/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable lmarenabridge
sudo systemctl start lmarenabridge
sudo systemctl status lmarenabridge
```
