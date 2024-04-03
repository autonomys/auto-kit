from setuptools import setup, find_packages

setup(
    name='auto-sdk',
    version='0.1.0',
    author='Autonomys',
    author_email='jeremy@subspace.network',
    url='https://github.com/subspace/auto-kit',
    packages=find_packages(),
    install_requires=[
        'cryptography>=42.0.0,<43.0.0',
        'substrate-interface>=1.7.0,<2.0.0',
        'pyasn1>=0.5.0,<0.7.0',
    ],
)
