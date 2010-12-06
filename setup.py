#!/usr/bin/python
from distutils.core import setup

setup(name="sekt",
        version = "0.03",
        description = "Secteam helper tool",
        author = "Bogdano Arendartchuk",
        author_email = "bogdano@mandriva.com",
        license = "GPL",
        long_description = \
"""Secteam helper tool""",
        packages = [
            "mdv",
            "mdv/sec/"],
        scripts = ["sekt",
                "sekt-cve",
                "sekt-cve-keywords",
                "sekt-init",
                "sekt-kci",
                "sekt-kcommits",
                "sekt-kcve",
                "sekt-kreleases",
                "sekt-pkg",
                "sekt-pull",
                "sekt-pull-cves",
                "sekt-pull-kernel-changelogs",
                "sekt-pull-kernel-trees",
                "sekt-pull-medias",
                "sekt-showrc",
                "sekt-update",
        ],
        data_files = [
            ('/usr/share/doc/sekt/',
                ['tour.txt'] ),]
    )


