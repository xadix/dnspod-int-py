# https://setuptools.readthedocs.io/
# https://docs.python.org/2/distutils/index.html
# https://docs.python.org/3/distutils/index.html
import setuptools
import versioneer

# https://docs.python.org/2/distutils/setupscript.html#additional-meta-data
# https://docs.python.org/3/distutils/setupscript.html#additional-meta-data
# https://setuptools.readthedocs.io/en/latest/setuptools.html#new-and-changed-setup-keywords
# https://setuptools.readthedocs.io/en/latest/setuptools.html#metadata

setuptools.setup(
    name="xadix-dnspod",
    description="Bindings and CLI for dnspod international api (dnspod.com)",
    url="https://github.com/xadix/dnspod-py",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=setuptools.find_packages(),
    py_modules=[],
    entry_points={
        "console_scripts": [
            "xdx-dnspod=xadix.dnspod.cli:main",
        ]
    },
    install_requires=[
        "requests>=2.18.4",
        "tabulate>=0.8.2",
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
    ],
    keywords='dnspod',
    python_requires='>=2.7, <3',
)
