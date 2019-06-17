import setuptools

setuptools.setup(
    name="cluster_test_tool",
    version="0.0.24",
    author="Xin Liang",
    author_email="XLiang@suse.com",
    url="https://github.com/liangxin1300/clusterTestTool",
    license="BSD",
    packages=setuptools.find_packages(),
    description="Tool for Standardize Testing of Basic Cluster Functionality",
    scripts=['bin/cluster-test-tool'],
    classifiers=[
          "Development Status :: 3 - Alpha",
          "Intended Audience :: System Administrators",
          "License :: OSI Approved :: BSD License",
          "Operating System :: POSIX",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.1",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: System :: Clustering",
          "Topic :: System :: Networking",
          "Topic :: System :: Systems Administration",
      ]
)
