from PIL import Image
import soundfile as sf
import os

def convert_image_to_png(path):
    img = Image.open(path)
    output = os.path.splitext(path)[0] + "_lossless.png"
    img.save(output, format="PNG")
    return output

def convert_audio_to_wav(path):
    data, samplerate = sf.read(path)
    output = os.path.splitext(path)[0] + "_lossless.wav"
    sf.write(output, data, samplerate, format="WAV")
    return output

