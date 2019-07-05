from setuptools import setup, find_packages

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
        'jsonschema',
        'jinja2'
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
