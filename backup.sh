month=$( date +%m )
day=$( date +%d )
hour=$( date +%H )
minute=$( date +%M )
cp minix.img minix_${month}.${day}T${hour}:${minute}.img

