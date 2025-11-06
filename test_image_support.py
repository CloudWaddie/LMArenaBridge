"""
Test script for image upload support in LMArenaBridge.

This script tests the image upload functionality by sending a base64-encoded image
to a vision-capable model through the OpenAI-compatible API.
"""

import openai
import base64
import sys

# Configuration
API_BASE_URL = "http://localhost:8000/api/v1"
API_KEY = "sk-lmab-4d4c13f6-7846-4f94-a261-f59911838196"  # Replace with your actual API key
MODEL = "gemini-2.5-flash"  # Replace with an actual vision-capable model from LMArena

def create_test_image():
    """Read test image from test.png file"""
    try:
        with open('test.png', 'rb') as f:
            png_data = f.read()
        return base64.b64encode(png_data).decode('utf-8')
    except FileNotFoundError:
        print("❌ Error: test.png not found. Please create a test.png file in the current directory.")
        sys.exit(1)

def test_image_api():
    """Test sending an image through the API"""
    
    # Create client
    client = openai.OpenAI(
        base_url=API_BASE_URL,
        api_key=API_KEY
    )
    
    print("Reading test image from test.png...")
    image_data = create_test_image()
    print(f"Image data length: {len(image_data)} characters")
    
    print(f"\nSending request to model: {MODEL}")
    print("Message: 'What color is this pixel?'")
    
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What color is this pixel? Please describe what you see."},
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
        
        print("\n✅ Success!")
        print(f"Response object: {response}")
        print(f"Response type: {type(response)}")
        print(f"Has choices: {hasattr(response, 'choices')}")
        if hasattr(response, 'choices') and response.choices:
            print(f"Choices length: {len(response.choices)}")
            print(f"First choice: {response.choices[0]}")
            if response.choices[0]:
                print(f"Response: {response.choices[0].message.content}")
                print(f"\nModel: {response.model}")
                print(f"Finish reason: {response.choices[0].finish_reason}")
        else:
            print("⚠️  No choices in response!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("=" * 60)
    print("LMArenaBridge Image Upload Test")
    print("=" * 60)
    
    if API_KEY == "your-api-key-here":
        print("\n⚠️  Please set your API_KEY in the script first!")
        sys.exit(1)
    
    test_image_api()
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)
