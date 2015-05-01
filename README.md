#Oracle RAC on Docker

download Oracle Software and place it /docker/media


`#mkdir -p /docker/media`
`#unzip linuxamd64_12102_database_1of2.zip -d /docker/media`
`#unzip linuxamd64_12102_database_2of2.zip -d /docker/media`
`#unzip linuxamd64_12102_grid_1of2.zip -d /docker/media`
`#unzip linuxamd64_12102_grid_2of2.zip -d /docker/media`

`#ls -al /docker/media`
*********************************
total 16
drwxr-xr-x 4 root root 4096 May  1 21:56 .
drwxr-xr-x 3 root root 4096 May  1 21:53 ..
drwxr-xr-x 7 root root 4096 Jul  7  2014 database
drwxr-xr-x 7 root root 4096 Jul  7  2014 grid
*********************************


`#git clone http://github.com/s4ragent/rac_on_docker/`
`#cd rac_on_docker`
`#bash create_racbase.sh all_in_one`


