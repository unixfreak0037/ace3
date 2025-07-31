# Integrations

An integration is a way to extend ACE in a structured way. The intention is to
allow you to easily build stuff for **your** environment without having to build
it directly into the core project.

This is an expiremental feature and subject to change as I figure out how I want
this to work.

This will replace the legacy integration system.

## Target

I want to be able to easily

- Install an integration from a local directory.
- Enable and disable the integration.

## Implementation

- Integrations are subdirectories of (subdirectories of) the `integrations` directory.
- Each integration is it's own subdirectory.
- An integration directory can contain multiple integration directories.
- The presence of an `integration.md` file signifies that the directory is, in fact, an integration. This file serves as the documentation for it.
- The presence of an `install.sh` script is executed at image build time.
- The presence of a `src` directory is automatically appended to PYTHONPATH.
- The presence of a `etc` directory has all `ini` files inside automatically loaded.
- The presence of a `bin` directory is appended to PATH.
- See below for what happens with `tests` directories.

## Issues

- Python analyzers in vscode/cursor have to be updated to reference the `src` directories in the integrations.

## Tests

This seems to be the trickiest part.

- I want the tests to have access to all the setup fixtures and utilities.
- pytest gets weird when loading from a deeply nested directory.

To solve this, for now, an integration has to be "installed". All this does is
created a symlink in the `tests` directory to the tests defined for the
integration. I know this is a bit of a kludge.

## Notes

- I don't think I want to use submodules here.
- An integration can be a whole separate repo.
- The `integrations` directory is in .gitignore.
- The symlinks created for the tests are also in .gitignore.

If anyone can come up with a better idea please let me know.