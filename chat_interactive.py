"""
Interactive chat script using OpenAI Python library with LMArena Bridge
Allows you to have a conversation with any model available through the bridge
"""

from openai import OpenAI
import os
import sys

# Configuration
BASE_URL = "http://localhost:8000/api/v1"
API_KEY_ENV_VAR = "LMABRIDGE_API_KEY"

def list_available_models(client):
    """List all available models"""
    try:
        models = client.models.list()
        return [model.id for model in models.data]
    except Exception as e:
        print(f"Error fetching models: {e}")
        return []

def chat_session(client, model_name):
    """Run an interactive chat session"""
    print(f"\n{'='*60}")
    print(f"🤖 Chat Session with {model_name}")
    print(f"{'='*60}")
    
    # Ask for system prompt
    print("\n📋 System Prompt (optional):")
    print("Set the behavior/personality of the assistant.")
    print("Press Enter to skip, or type your system prompt below:")
    system_prompt = input("System: ").strip()
    
    conversation_history = []
    
    # Add system message if provided
    if system_prompt:
        conversation_history.append({
            "role": "system",
            "content": system_prompt
        })
        print(f"✅ System prompt set: {system_prompt[:50]}{'...' if len(system_prompt) > 50 else ''}")
    
    print(f"\n{'='*60}")
    print("Type your messages below. Commands:")
    print("  - 'exit' or 'quit' to end the session")
    print("  - 'clear' to start a new conversation")
    print("  - 'system' to view/change system prompt")
    print("  - 'models' to switch models")
    print(f"{'='*60}\n")
    
    while True:
        # Get user input
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Goodbye!")
            break
        
        # Handle commands FIRST before adding to history
        if not user_input:
            continue
            
        if user_input.lower() in ['exit', 'quit']:
            print("\n👋 Goodbye!")
            break
        
        if user_input.lower() == 'clear':
            # Keep system prompt if it exists
            system_msg = None
            if conversation_history and conversation_history[0]["role"] == "system":
                system_msg = conversation_history[0]
            
            conversation_history = []
            if system_msg:
                conversation_history.append(system_msg)
            print("\n🔄 Conversation cleared!\n")
            continue
        
        if user_input.lower() == 'system':
            # Show or update system prompt
            current_system = None
            if conversation_history and conversation_history[0]["role"] == "system":
                current_system = conversation_history[0]["content"]
                print(f"\n📋 Current system prompt:\n{current_system}\n")
            else:
                print("\n📋 No system prompt set.\n")
            
            print("Enter new system prompt (or press Enter to keep current):")
            new_system = input("System: ").strip()
            
            if new_system:
                # Remove old system message if exists
                if conversation_history and conversation_history[0]["role"] == "system":
                    conversation_history.pop(0)
                
                # Add new system message at the start
                conversation_history.insert(0, {
                    "role": "system",
                    "content": new_system
                })
                print(f"✅ System prompt updated: {new_system[:50]}{'...' if len(new_system) > 50 else ''}\n")
            else:
                print("System prompt unchanged.\n")
            continue
        
        if user_input.lower() == 'models':
            return 'switch_model'
        
        # Add user message to history (only if not a command)
        conversation_history.append({
            "role": "user",
            "content": user_input
        })
        
        # Get response from API with streaming
        try:
            print("Assistant: ", end="", flush=True)
            
            stream = client.chat.completions.create(
                model=model_name,
                messages=conversation_history,
                stream=True  # Enable streaming
            )
            
            assistant_message = ""
            for chunk in stream:
                if chunk.choices[0].delta.content is not None:
                    content = chunk.choices[0].delta.content
                    print(content, end="", flush=True)
                    assistant_message += content
            
            print()  # New line after streaming completes
            
            # Add assistant response to history
            conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })
            
            print()  # Empty line for readability
            
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
            # Remove the failed user message from history
            conversation_history.pop()

def select_model(client, models):
    """Let user select a model"""
    print("\n📋 Available Models:")
    print("-" * 60)
    
    for i, model in enumerate(models, 1):
        print(f"{i}. {model}")
    
    print("-" * 60)
    
    while True:
        try:
            choice = input("\nSelect a model number (or 'q' to quit): ").strip()
            
            if choice.lower() == 'q':
                return None
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(models):
                return models[choice_num - 1]
            else:
                print(f"Please enter a number between 1 and {len(models)}")
        except ValueError:
            print("Please enter a valid number or 'q' to quit")
        except (EOFError, KeyboardInterrupt):
            print("\n")
            return None

def main():
    """Main function"""
    print("=" * 60)
    print("🚀 LMArena Bridge - Interactive Chat")
    print("=" * 60)

    api_key = os.getenv(API_KEY_ENV_VAR, "").strip()
    if not api_key:
        api_key = input(f"API Key (set {API_KEY_ENV_VAR} to skip prompt): ").strip()
    if not api_key:
        print(f"❌ Missing API key. Set {API_KEY_ENV_VAR} or paste it when prompted.")
        return
    
    # Initialize OpenAI client
    try:
        client = OpenAI(
            api_key=api_key,
            base_url=BASE_URL
        )
        print("✅ Connected to LMArena Bridge")
    except Exception as e:
        print(f"❌ Failed to initialize client: {e}")
        return
    
    # Get available models
    print("📡 Fetching available models...")
    models = list_available_models(client)
    
    if not models:
        print("❌ No models available. Please check your API key and server status.")
        return
    
    print(f"✅ Found {len(models)} models")
    
    # Main loop
    while True:
        selected_model = select_model(client, models)
        
        if selected_model is None:
            print("\n👋 Goodbye!")
            break
        
        result = chat_session(client, selected_model)
        
        if result != 'switch_model':
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
