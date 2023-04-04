#!/bin/bash

source venv/bin/activate 

pm2 del service-s3-panel
pm2 start