from setuptools import setup, find_packages

setup(
    name='threatspec',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.7',
    install_requires=[
        'Click',
        'graphviz',
        'pyyaml'
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
)
