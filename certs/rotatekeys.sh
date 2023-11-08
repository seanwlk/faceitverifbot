echo -e 'y' |ssh-keygen -t rsa -b 4096 -m PEM -f privateRSA.pem -N ''
openssl rsa -in privateRSA.pem -pubout -outform PEM -out publicRSA.pub