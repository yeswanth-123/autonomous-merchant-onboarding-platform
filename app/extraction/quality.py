import numpy as np
from PIL import Image


def laplacian_variance(image: Image.Image, max_side: int = 1000) -> float:
    grayscale = image.convert("L")
    if max(grayscale.size) > max_side:
        scale = max_side / max(grayscale.size)
        grayscale = grayscale.resize((max(1, int(grayscale.width * scale)), max(1, int(grayscale.height * scale))))
    pixels = np.asarray(grayscale, dtype=float)
    if pixels.shape[0] < 3 or pixels.shape[1] < 3:
        return 0.0
    laplacian = (4 * pixels[1:-1, 1:-1] - pixels[:-2, 1:-1] - pixels[2:, 1:-1]
                 - pixels[1:-1, :-2] - pixels[1:-1, 2:])
    return float(laplacian.var())


def quality_score(image: Image.Image, threshold: float) -> float:
    return min(1.0, laplacian_variance(image) / (2 * threshold))
