"""Setup script for CVEScannerX."""

from setuptools import setup, find_packages

setup(
    name="cvescannerx",
    version="1.0.0",
    description="Advanced CVE scanning tool for Kali Linux",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author="734ai",
    author_email="",
    url="https://github.com/734ai/CVEScannerX",
    packages=find_packages(),
    package_data={
        'cvescannerx': ['templates/*.html', 'templates/static/*.css'],
    },
    install_requires=[
        'python-nmap>=0.7.1',
        'shodan>=1.28.0',
        'vulners>=2.0.2',
        'securitytrails>=0.1.2',
        'rich>=13.3.0',
        'requests>=2.28.0',
        'jinja2>=3.1.0',
        'pdfkit>=1.0.0',
    ],
    python_requires='>=3.8',
    extras_require={
        'test': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'mock>=5.0.0',
        ],
        'dev': [
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'cvescannerx=cvescannerx.cvescannerx:main',
        ],
    },
    classifiers=[
                'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
)
