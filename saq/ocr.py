import cv2
import enchant
import logging
import numpy as np
import pytesseract
import re

from PIL import Image, ImageOps


def get_binary_image(image: np.ndarray) -> np.ndarray:
    """Uses binary thresholding to return a white/black version of the image. Must be used on a grayscale image."""

    return cv2.threshold(image, 127, 255, cv2.THRESH_BINARY)[1]


def get_image_text(image: np.ndarray) -> str:
    """Returns the text within the image by using OCR."""

    # In testing (in particular with screenshots of text messages), using PSM 6 seems to produce the best results.
    # 6 = Assume a single uniform block of text
    text = str(pytesseract.image_to_string(image, config="--psm 6"))

    # In testing, Tesseract sometimes had issues identifying http:// or https://. In particular, it would mix up the
    # double "t" and sometimes make one of them an "i" instead. Sometimes the "p" or ":" would be mixed up as well.
    if text:
        text = re.sub(r"h(t|i)(t|i)(p|o)s(:|.)\/\/", "https://", text)
        text = re.sub(r"h(t|i)(t|i)(p|o)(:|.)\/\/", "http://", text)

    return text


def invert_image_color(image: np.ndarray) -> np.ndarray:
    """Returns an image where the colors are inverted."""

    return cv2.bitwise_not(image)


def is_dark(image: np.ndarray) -> bool:
    """Returns True/False if the image appears to be in dark-mode. Must be used on a grayscale image."""

    # In grayscale mode, each pixel has a value from 0-255 (0=black, 255=white). If the mean value is closer to
    # 0 than 255, then we assume that the original image is dark overall.
    return cv2.mean(image)[0] < 127


def is_small(image: np.ndarray) -> bool:
    """Returns True/False if the resolution of the image is what we consider to be small."""

    width = image.shape[1]
    height = image.shape[0]

    return width < 400 and height < 650


def read_image(image_path: str, use_grayscale: bool = True) -> np.ndarray:
    """Reads the image at the given path. By default it will return the image in grayscale mode."""

    image = Image.open(image_path)

    if use_grayscale:
        image = ImageOps.grayscale(image)

    return np.array(image)


def remove_line_wrapping(text: str) -> str:
    """Attempts to interpret the text to remove line wraps. This is particularly helpful when performing OCR on
    a screenshot of a text message where things like domains or URLs a broken up over multiple lines.
    
    It loops over each line in the text, and if the last "word" in the line (when broken up by spaces) is a valid
    word according to the dictionary it will join that line to the resulting text with a space at the end. If it
    is not a valid word, then it joins the line without a space at the end, which implies that the word continues on
    the next line."""

    dictionary = enchant.Dict("en_US")

    unwrapped_text = ""
    for line in text.splitlines():
        try:
            last_word = line.split()[-1]
        except IndexError:
            continue

        is_a_word = False
        try:
            is_a_word = dictionary.check(last_word)
        except:
            logging.exception(f"Unable to determine if \"{last_word}\" is a word.")

        if is_a_word:
            unwrapped_text += f"{line} "
        else:
            unwrapped_text += line

    return unwrapped_text


def scale_image(image: np.ndarray, x_factor: int, y_factor: int) -> np.ndarray:
    """Returns a scaled version of the image."""

    return cv2.resize(image, None, fx=x_factor, fy=y_factor, interpolation=cv2.INTER_CUBIC)
