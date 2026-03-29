from google import genai
import os

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def explain_with_llm(modality, prediction, confidence, image_paths=None):

    if image_paths is None:
        image_paths = []

    prompt = f"""
You are an AI forensic analyst helping users understand deepfake detection results.

Media Type: {modality}
Prediction: {prediction}
Confidence: {confidence:.2f}


Explain clearly in simple language WHY the media might be {prediction}.
Refer to the visual evidence if available.
"""

    contents = []

    # Upload images to Gemini Files API
    for path in image_paths:
        uploaded_file = client.files.upload(file=path)
        contents.append(uploaded_file)

    contents.append(prompt)

    response = client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents=contents
    )

    return response.text