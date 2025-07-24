from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv

load_dotenv()

# Updated system prompt to always respond in English
system_prompt = (
    "You are ShopLore's helpful chat assistant. "
    "You only answer questions related to ShopLore, its products, services, delivery, and support. "
    "If a user asks something unrelated, politely refuse and guide them back to ShopLore topics. "
    "Always respond in English, even if the user types in another language."
)

model = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash",
    temperature=0.1,
    system_prompt=system_prompt
)

print("ShopLore Assistant: Hello! I am ShopLore's chat assistant. How can I help you today?")

while True:
    user_input = input("You: ").strip()
    if user_input.lower() in {"exit", "quit", "bye"}:
        print("ShopLore Assistant: Thank you for chatting with ShopLore. Goodbye!")
        break
    result = model.invoke(user_input)
    print(f"ShopLore Assistant: {result.content}")