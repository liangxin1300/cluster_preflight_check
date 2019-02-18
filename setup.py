import setuptools

setuptools.setup(
    name="cluster_test_tool",
    version="0.0.6",
    author="Xin Liang",
    author_email="XLiang@suse.com",
    packages=setuptools.find_packages(),
    description="Tool for Standardize Testing of Basic Cluster Functionality",
    scripts=['bin/cluster_test_tool']
)
