# LM Arena Bridge

### Thank you to the [AI Leaks server](https://discord.gg/fqmaHkQpJZ) for being a partner!
![AI-Leaks-Logo](https://github.com/user-attachments/assets/5fd3d456-152c-44e2-acee-f4c2a1ca2caa)


> [!WARNING]
> MAJOR REFACTORS ARE HAPPENING.

## Description

A bridge to interact with LM Arena. This project provides an OpenAI compatible API endpoint that interacts with models on LM Arena.

## Pictures
<img width="1647" height="1023" alt="image" src="https://github.com/user-attachments/assets/52ffa0d0-e259-41a6-9845-7ff1edf95c62" />
<img width="1238" height="734" alt="image" src="https://github.com/user-attachments/assets/d7e6c08a-6a57-40f8-a561-f3bc43bb1a57" />
<img width="1240" height="1033" alt="image" src="https://github.com/user-attachments/assets/9fa1b61c-c957-41a6-a1a5-e916ae64cf95" />



## Getting Started

### Prerequisites

- Python 3.x

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/CloudWaddie/LMArenaBridge.git
   ```
2. Navigate to the project directory:
   ```bash
   cd LMArenaBridge
   ```
3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Userscript Proxy (optional)

There is an optional **userscript proxy** path that can improve reliability for some strict models and reCAPTCHA flows. It is **not required** and the bridge can run without it using direct httpx + browser fetch (Chrome/Camoufox).

**Notes:**
- The userscript is optional and only helpful in specific environments.
- If you don’t want to use it, you can ignore it entirely.
- When enabled, it acts as a helper to send requests via a browser tab and can improve reCAPTCHA success rates.

If you want this documented more deeply, let us know what environment you’re on and we’ll add step-by-step instructions.


### 1. Get your Authentication Token

To use the LM Arena Bridge, you need to get your authentication token from the LM Arena website.

1.  Open your web browser and go to the LM Arena website.
2.  Send a message in the chat to any model.
3.  After the model responds, open the developer tools in your browser (usually by pressing F12).
4.  Go to the "Application" or "Storage" tab (the name may vary depending on your browser).
5.  In the "Cookies" section, find the cookies for the LM Arena site.
6.  Look for a cookie named `arena-auth-prod-v1` and copy its value. This is your authentication token. THIS IS THE TOKEN STARTING WITH base64-

### 2. Configure the Application

1.  Go to the admin portal.
2.  Login.
3.  Add the token to the list.

### 3. Run the Application

Once you have configured your authentication token, you can run the application:

```bash
python src/main.py
```

The application will start a server on `localhost:8000`.

## Integration with OpenWebUI

You can use this project as a backend for [OpenWebUI](https://openwebui.com/), a user-friendly web interface for Large Language Models.

### Instructions

1.  **Run the LM Arena Bridge:**
    Make sure the `lmarenabridge` application is running.
    ```bash
    python src/main.py
    ```

2.  **Open OpenWebUI:**
    Open the OpenWebUI interface in your web browser.

3.  **Configure the OpenAI Connection:**
    - Go to your **Profile**.
    - Open the **Admin Panel**.
    - Go to **Settings**.
    - Go to **Connections**.
    - Modify the **OpenAI connection**.

4.  **Set the API Base URL:**
    - In the OpenAI connection settings, set the **API Base URL** to the URL of the LM Arena Bridge API, which is `http://localhost:8000/api/v1`.
    - You can leave the **API Key** field empty or enter any value. It is not used for authentication by the bridge itself.

5.  **Start Chatting:**
    You should now be able to select and chat with the models available on LM Arena through OpenWebUI.

## Image Support

LMArenaBridge supports sending images to vision-capable models on LMArena. When you send a message with images to a model that supports image input, the images are automatically uploaded to LMArena's R2 storage and included in the request.

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
