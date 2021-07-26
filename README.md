# HACON
Lots of cyber security tool
# Install
```
pip3 install HACON
```
# Using
## In another script
```python
from hacon import HACON

HACON.arguments("-h")
```
## In command line
```python
HACON -h
```

# With docker
## Install 
```
docker pull ghcr.io/onuratakan/hacon:latest
```
## Using
```
docker run -t -i  --network=host ghcr.io/onuratakan/hacon /bin/sh
```
and type
```python
HACON -h
```

# Reminder
Important Information and Reminder Information and programs in all repositories are created for testing purposes. Any legal responsibility belongs to the person or organization that uses it.
