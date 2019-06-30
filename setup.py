from setuptools import setup, find_packages

# read the contents of your README file
#from os import path
#this_directory = path.abspath(path.dirname(__file__))
#with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
#    long_description = f.read()

setup(
    name='threatspec',
    description='threat modeling as code',
    license='MIT',
    author='Fraser Scott',
    author_email='fraser.scott@gmail.com',
    url='https://github.com/threatspec/threatspec',
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
    use_scm_version=True,
    setup_requires=[
        "pytest-runner",
        "setuptools_scm"
    ],
    tests_require=[
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
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ]
)
