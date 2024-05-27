[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R21LO82)

# goshawk
Replacement DLC server for 3DS/WiiU Monster Hunter games. 

## Simple Instructions
- **IMPORTANT**: Pretendo access is required for this to work as the games also made requests to Nintendo servers. At this moment Pretendo hasn't whitelisted the games yet so you will need to wait until they do so.
- Run `app.py` with Python3 + Flask (`pip install -r requirements` will install all needed dependencies). Alternatively you can run it behind Apache, nginx...
- Make sure your console is being redirected to your replacement server, you can achieve this through a proxy, by using a custom DNS server...
- Install SSL patch to bypass the certificate pinning: https://github.com/internalloss/3ds-ssl-patch

## Important notice
All DLC files belong to CAPCOM, I take no ownership over them. The sole purpose of this project is the preservation of the DLCs that were served in the WiiU and 3DS systems over the years for the Monster Hunter games.
