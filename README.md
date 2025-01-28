## Overview

This app will visualise the network traffic coming from your PC and plot it on a map with links between devices showing the flow of traffic. Coolour denotes the regularity of communication with green meaning infrequent packet transfers and red reflecting frequent packet transfers.

## Installation

Run the following to install all requirement:

```
pip install -r requirements.txt
```

## Additional required files

You will need to download GeoLite2-City.mmdb file to look up locations: https://github.com/P3TERX/GeoLite.mmdb

Then run the Flask server with:
```
python main.py
```
Point your browser to the Flask URL shown in the terminal
