git clone git://git.samba.org/samba.git
cd samba
git checkout a6bda1f2bc8
cd ../source
./waf --samba-dir=../samba configure build