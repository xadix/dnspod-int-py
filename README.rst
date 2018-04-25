xadix DNSPod Bindings and CLI
================================================================================

This is bindings and cli for the dnspod intl api as defined here https://www.dnspod.com/docs/index.html

CLI Usage
--------------------------------------------------------------------------------

Tool installs as ``xdx-dnspod``.

* Credentials can be provides with 
    * Command line arguments ``--email EMAIL`` and ``--password PASSWORD``
    * Environment variables ``XADIX_DNSPOD_EMAIL=EMAIL`` and ``XADIX_DNSPOD_PASSWORD=PASSWORD``
    * JSON Configuration file (which can be set with ``--config CONFIG``, defaults to ``~/.config/xadix-dnspod/config.json``) as ``{"email": "EMAIL", "password": "PASSWORD"}``
* Alternatively, a token (obtained with ``xdx-dnspod auth``) can be used. This can be provided with:
    * Command line arguments ``--token TOKEN``
    * Environment variables ``XADIX_DNSPOD_TOKEN=TOKEN``
    * JSON Cache file (which can be set with ``--cache CACHE``, defaults to ``~/.config/xadix-dnspod/cache.json``) as ``{"token": "TOKEN"}``

Example usage:

.. code-block:: bash

    xdx-dnspod domain record -d example.com upsert -n x0 -t A -v 127.1.2.3 -x 60
    xdx-dnspod domain record -d example.com list
