from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='zoneparser',
      version=version,
      description="Streaming BIND Zone file parser",
      long_description="""\
""",
      classifiers=['License :: OSI Approved :: MIT License', 'Topic :: Internet :: Name Service (DNS)', 'Development Status :: 3 - Alpha'], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='bind zone stream generator parse parser parsing',
      author='Gert Burger',
      author_email='gertburger@gmail.com',
      url='gertburger.github.com',
      license='MIT License',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
