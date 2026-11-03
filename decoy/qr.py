"""Read a QR code from an uploaded picture. The picture is only data: it is decoded in plain code, never executed,
and the decoded text must pass the same link checks as a pasted link."""
import cv2
import numpy as np

MAX_BYTES = 4 * 1024 * 1024
MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"GIF8")  # png, jpeg, webp, gif


class BadImage(ValueError):
    pass


def decode(data: bytes) -> str:
    if len(data) > MAX_BYTES:
        raise BadImage("The picture is too big (4 MB at most).")
    if not data.startswith(MAGIC):
        raise BadImage("Upload a PNG, JPG, WEBP or GIF picture.")
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None or img.shape[0] * img.shape[1] > 25_000_000:
        raise BadImage("That picture could not be read.")
    det = cv2.QRCodeDetector()
    for scale in (1.0, 2.0, 0.5):
        im = img if scale == 1.0 else cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC if scale > 1 else cv2.INTER_AREA)
        text, _, _ = det.detectAndDecode(im)
        if text:
            return text.strip()[:2000]
    raise BadImage("No QR code was found in the picture.")
