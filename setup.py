from setuptools import setup, find_packages

setup(
    name='dpi_engine',
    version='2.0.0',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0'
    ],
    entry_points={
        'console_scripts': [
            'dpi-engine=app:main',
        ],
    },
)
