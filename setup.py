from setuptools import setup, find_packages

setup(
    name='ai-mathematically-explained',
    version='0.1.0',  # Update this version as needed
    author='MLDreamer',
    author_email='your-email@example.com',
    description='A package that provides AI concepts explained mathematically.',
    long_description=open('README.md').read(),  # Ensure README.md exists in your repo
    long_description_content_type='text/markdown',
    url='https://github.com/MLDreamer/AIMathematicallyexplained',
    project_urls={
        'Documentation': 'https://example.com/docs',  # Provide actual link if available
        'Issues': 'https://github.com/MLDreamer/AIMathematicallyexplained/issues',
    },
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[
        # List your package dependencies here
        'numpy',
        'scipy',
        'matplotlib',
    ],
)