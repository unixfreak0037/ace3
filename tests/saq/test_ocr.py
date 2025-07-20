import numpy as np
import os
import pytest

from saq import ocr


@pytest.mark.unit
def test_invert_image_color(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    assert list(np.unique(image.flatten())) == [255]

    inverted = ocr.invert_image_color(image)
    assert list(np.unique(inverted.flatten())) == [0]


@pytest.mark.unit
def test_is_dark(datadir):
    image = ocr.read_image(os.path.join(datadir, "white.png"))
    assert ocr.is_dark(image) is False

    inverted = ocr.invert_image_color(image)
    assert ocr.is_dark(inverted) is True


@pytest.mark.unit
def test_is_small(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    assert ocr.is_small(image) is True


@pytest.mark.unit
def test_remove_line_wrapping():
    text = """Text Message
Today 8:57 AM
[Blah Blah Bank]: We recently
detected some unusual activities &
your access is temporarily
suspended. Visit https://bit.ly/
3B65FKM to regain online access.

"""

    expected = "Text Message Today 8:57 AM [Blah Blah Bank]: We recently detected some unusual activities &your access is temporarily suspended. Visit https://bit.ly/3B65FKM to regain online access. "

    assert ocr.remove_line_wrapping(text) == expected


@pytest.mark.unit
def test_scale_image(datadir):
    image = ocr.read_image(os.path.join(datadir, "small.png"))
    scaled = ocr.scale_image(image, x_factor=2, y_factor=2)
    assert scaled.shape[0] == image.shape[0] * 2
    assert scaled.shape[1] == image.shape[1] * 2
