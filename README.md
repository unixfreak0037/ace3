# Analysis Correlation Engine v3

This project is a continuation of [this project from 2014](https://github.com/ace-ecosystem/ACE). 

## Quick Setup

```bash
docker compose up --build
```

And then connect on [https://localhost:5000/ace](https://localhost:5000/ace) username **analyst** password **analyst**.

Optionally execute `bin/attach-container.sh` to gain a shell to the containerized environment.

## Testing

Execute the following after attaching to the container.

```bash
pytest -m "unit or integration or system"
```
