DNSPod Intl. API support
================================================================================


Commands
--------------------------------------------------------------------------------

::
    pip install --user --upgrade versioneer
    versioneer install
    python2 setup.py version

    # view docs ...
    pip2 install -v --user --upgrade --ignore-installed restview
    restview README.rst

    # install ...
    pip2 install --user --upgrade .
    pip3 install --user --upgrade .
    
    mog-cli
    mog-main
    
    pip2 install --user --upgrade --editable .
    pip3 install --user --upgrade --editable .

    # ...
    package = x/__init__.py
    module = x.py

    # ....
    vimdiff <(curl --silent https://raw.githubusercontent.com/github/gitignore/master/Python.gitignore) .gitignore

References
--------------------------------------------------------------------------------

* https://www.dnspod.com/docs/index.html
* https://github.com/DNSPod/dnspod-int-api-docs
