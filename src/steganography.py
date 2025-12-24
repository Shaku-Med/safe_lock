import base64
from PIL import Image
from stegano import lsb
import io
from tqdm import tqdm

def hide_data_in_image(image_path: str, data: bytes, output_path: str) -> bool:
    try:
        img = Image.open(image_path)
        img_format = img.format
        
        with tqdm(total=len(data), unit='B', unit_scale=True, unit_divisor=1024, desc="Encoding data to base64", leave=False) as pbar:
            data_b64 = base64.b64encode(data).decode('utf-8')
            pbar.update(len(data))
        
        with tqdm(total=len(data_b64), unit='B', unit_scale=True, unit_divisor=1024, desc="Hiding data in image (LSB steganography)") as pbar:
            secret = lsb.hide(image_path, data_b64)
            pbar.update(len(data_b64))
        
        with tqdm(desc="Saving stego image", leave=False) as pbar:
            secret.save(output_path, format=img_format)
            pbar.update(1)
        return True
    except Exception as e:
        raise Exception(f"Failed to hide data in image: {str(e)}")

def reveal_data_from_image(image_path: str) -> bytes:
    try:
        with tqdm(desc="Extracting hidden data from image", leave=False) as pbar:
            hidden_data_b64 = lsb.reveal(image_path)
            pbar.update(1)
        
        if hidden_data_b64 is None:
            raise Exception("No hidden data found in image")
        
        with tqdm(total=len(hidden_data_b64), unit='B', unit_scale=True, unit_divisor=1024, desc="Decoding base64 data", leave=False) as pbar:
            decoded_data = base64.b64decode(hidden_data_b64.encode('utf-8'))
            pbar.update(len(hidden_data_b64))
        
        return decoded_data
    except Exception as e:
        raise Exception(f"Failed to reveal data from image: {str(e)}")

def validate_image_size(image_path: str, data_size: int) -> bool:
    img = Image.open(image_path)
    width, height = img.size
    pixel_count = width * height
    
    required_pixels = data_size * 8
    
    if required_pixels > pixel_count:
        return False
    return True

