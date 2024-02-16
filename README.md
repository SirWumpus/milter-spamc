milter-spamc
============

Configuration & Build
---------------------

        mkdir -p com/snert/src
        cd com/snert/src
        git clone https://github.com/SirWumpus/libsnert.git lib
        git clone https://github.com/SirWumpus/milter-spamc

        cd lib
        ./configure --help
        ./configure [options]
        make links              # Need only happen once.
        make

        cd ../milter-spamc
        ./configure [options]
        make
        sudo make install
