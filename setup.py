from setuptools import setup, find_packages

setup(
    name='threatspec',
    description='threat modeling as code',
    version='0.2.0',
    license='MIT',
    author='Fraser Scott',
    author_email='fraser.scott@gmail.com',
    url='https://github.com/threatspec/threatspec',
    download_url='https://github.com/threatspec/threatspec/archive/v0.2.0-alpha.tar.gz',
    keywords=['threat modeling', 'cyber security', 'appsec'],
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.5',
    install_requires=[
        'Click',
        'graphviz',
        'pyyaml',
        'jsonschema'
    ],
    setup_requires = [
        "pytest-runner"
    ],
    tests_require = [
        'pytest'
    ],
    entry_points='''
        [console_scripts]
        threatspec=threatspec.cli:cli
    ''',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7'
    ]
)
