import os
import subprocess
import sys

import pytest

CORPUS = os.path.join(os.path.dirname(__file__), "..", "samples", "corpus")


@pytest.fixture(scope="session", autouse=True)
def ensure_corpus():
    if not os.path.exists(os.path.join(CORPUS, "00_flagship_bank_phish.eml")):
        subprocess.run(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "..", "samples", "generate_corpus.py"),
            ],
            check=True,
        )


def sample(name: str) -> bytes:
    with open(os.path.join(CORPUS, name), "rb") as f:
        return f.read()
