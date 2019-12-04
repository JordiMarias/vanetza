This document summarises a few hints for cross-compiling Vanetza's dependencies.


# Boost

Create a configuration file for Boost.Build in your home directory at `$HOME/user-config.jam` and add following line to it:

    using gcc : arm : arm-linux-gnueabihf-g++ ;

The *install* stage does not work in Boost 1.71.0 (and 1.70.0) when cross-compiling.
A workaround for this issue is to remove following lines from `tools/build/src/tools/common.jam` (around line 976):

    # From GCC 5, versioning changes and minor becomes patch
    if $(tag) = gcc && [ numbers.less 4 $(version[1]) ]
    {
        version = $(version[1]) ;
    }

    # Ditto, from Clang 4
    if ( $(tag) = clang || $(tag) = clangw ) && [ numbers.less 3 $(version[1]) ]
    {
        version = $(version[1]) ;
    }

Then, the required libraries can be built and installed at given *prefix* path:

    ./b2 --prefix=$HOME/vanetza-deps --with-date_time --with-program_options --with-system --no-samples --no-tests variant=release link=shared cxxstd=11 install


# Crypto++

Version 8.2 can be cross-compiled with the provided `GNUmakefile-cross` makefile.

    export CXX=arm-linux-gnueabihf-g++
    export PREFIX=$HOME/vanetza-deps
    export HAS_SOLIB_VERSION=1
    make -f GNUmakefile-cross shared
    make -f GNUmakefile-cross install


# GeographicLib

Following steps have been tested with version 1.50.
`$VANETZA` refers to the root directory of this repository.

    mkdir build.arm
    cd build.arm
    cmake .. -DCMAKE_TOOLCHAIN_FILE=$VANETZA/cmake/Toolchain-Cohda-MK5.cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/vanetza-deps
    make install