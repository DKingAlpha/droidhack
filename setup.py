import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="droidhack",
    version="1.0",
    author="DKing",
    author_email="dking@tot.im",
    description="A toolkit that provides easy access with procfs and devfs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DKingAlpha/droidhack",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License, version 3",
        "Operating System :: POSIX",
    ],
    python_requires='>=3.7',
)