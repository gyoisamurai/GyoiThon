from modules.Gyoi_CveExplorerNVD import CveExplorerNVD
from urllib3 import util
from util import Utilty

'''
SST API

Isaac Thiessen - 2019

This file just updates Gyoithons database. 

This will be ran in building the dockerfile to save time when running new scans.

'''

cve_explorer = CveExplorerNVD(Utilty(), False)
