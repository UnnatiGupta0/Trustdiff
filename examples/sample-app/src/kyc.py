import logging
import openai

def verify(user):
    logging.info(f"KYC for {user.pan_number} {user.email}")
    return openai.chat.completions.create(model="gpt-4o", messages=[{"role":"user","content": user.aadhaar_number}])
