import setuptools
# from Cython.Build import cythonize

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="droidhack",
    version="1.3",
    author="DKing",
    author_email="dking@tot.im",
    description="A toolkit that provides easy access with procfs and devfs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DKingAlpha/droidhack",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: Android",
        "Operating System :: POSIX",
        "Topic :: System",
        "Topic :: Security",
        "Topic :: Software Development :: Embedded Systems"
    ],
    python_requires='>=3.7',
    #ext_modules=cythonize('droidhack/*.py', compiler_directives={'language_level': "3"}),
    #zip_safe=False
)
