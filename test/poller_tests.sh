#!/bin/bash

echo -e "\n\nerrors = 0, dir1/78812115.png, dir2/BM54-12.JPG, dir3/61f63e4b8ec7.bmp"
curl -i -T test.zip http://localhost:11335/archiveinfo

echo -e "\n\nname = test.zip, errors = 0, dir1/78812115.png, dir2/BM54-12.JPG, dir3/61f63e4b8ec7.bmp"
curl -i -T test.zip http://localhost:11335/archiveinfo -H "X-ARCHIVE-NAME: test.zip"

echo -e "\n\nerrors = 0, dir1/78812115.png"
curl -i -T test.zip http://localhost:11335/archiveinfo -H "X-MAXFILE-SIZE: 500000"

echo -e "\n\nerrors = 0, dir2/BM54-12.JPG"
curl -i -T test.zip http://localhost:11335/archiveinfo -H "X-FILTER-MASK: *.jpg"

echo -e "\n\nerrors = 0, bmw82.jpg, dir1/78812115.png, dir2/BM54-12.JPG, dir2/bmw82.jpg, dir3/61f63e4b8ec7.bmp"
curl -i -T test.zip http://localhost:11335/archiveinfo -H "X-FILTER-MASK: *bmp, *.jpg, *.png" -H "X-MAXFILE-SIZE: 5000000" -H "X-ARCHIVE-MAXFILES: 100"

echo -e "\n\ninvalid archive"
curl -i -T /dev/null http://localhost:11335/archiveinfo

echo -e "\n\nerrors = 2"
curl -i -T test2.zip http://localhost:11335/archiveinfo -H "X-FILTER-MASK: *.*" -H "X-ARCHIVE-MAXFILES: 0" -H "X-MAXFILE-SIZE: 0"

echo -e "\n\n\extracted with errors = 2"
curl -i -T test3.zip http://localhost:11335/extractfiles
