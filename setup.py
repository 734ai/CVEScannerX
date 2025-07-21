"""Setup script for CVEScannerX."""

from setuptools import setup, find_packages

setup(
    name="cvescannerx",
    version="1.0.0",
    description="Advanced CVE scanning tool for Kali Linux",
    author="734ai",
    author_email="",
    url="https://github.com/734ai/CVEScannerX",
    packages=find_packages(),
    package_data={
        'cvescannerx': ['templates/*.html'],
    },
    install_requires=[
        'python-nmap>=0.7.1',
        'shodan>=1.28.0',
        'vulners>=2.0.2',
        'securitytrails>=0.1.2',
        'rich>=13.3.0',
        'requests>=2.28.0',
        'jinja2>=3.1.0',
    ],
    entry_points={
        'console_scripts': [
            'cvescannerx=cvescannerx.cvescannerx:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
)
