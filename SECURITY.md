# Security policy

## Reporting a vulnerability

Please report security problems in Evedoo privately, not in a public issue.

Use GitHub's private reporting: on the repository page, open **Security**, then **Report a vulnerability**. This creates a report only the maintainer can see.

Include what you can of:

- the version or commit you tested;
- the operating system;
- what an attacker can do, and what they need in order to do it;
- steps or a file that reproduces it.

Do not attach a real scan report or scan database. They list the weaknesses of the machine they came from.

## What to expect

Evedoo is maintained by one person. You should get an acknowledgement within 7 days. Fixes for confirmed problems are released as soon as they are ready, and the report is credited unless you ask otherwise.

## Supported versions

Evedoo is pre-1.0. Only the latest release and the `main` branch receive security fixes.

## Scope

In scope:

- crashes, hangs or code execution caused by a file the scanner reads (binaries, package databases, a root filesystem given to `--rootfs`, a benchmark given to `--policy`);
- anything that lets another local user or a web page read a report, start a scan or change scanner state (the `--serve` report server, the Studio development server);
- injection through values the tool passes to PowerShell, the Task Scheduler or a database;
- credentials exposed in logs, process lists or output;
- a scan reporting a clean result when it could not actually check (a missing database, an unreadable package database).

Out of scope:

- a CVE that Evedoo fails to report, or reports wrongly, for some product. That is a matching-accuracy bug: please open a normal issue;
- vulnerabilities in the data sources themselves.

## Security design notes

An earlier internal review and its findings are kept in [docs/security/](docs/security/).
