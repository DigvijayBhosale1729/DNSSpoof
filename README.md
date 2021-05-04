# DNSSpoof
A command line tool written in Python that allows editing of network packets and Spoof DNS information when used in a MITM attack.

The script can be modified to spoof other fields as well

## Prerequisites

Be sudo before running all of the following operations
```
sudo su
cd DNSSpoof
bash prerequisites.sh
```

## Usage
```
python3 DNSSpoof.py
```
You'll be presented with 3 options
![image](https://user-images.githubusercontent.com/70275323/117012652-ccac7880-ad0c-11eb-819c-458b89f1cfdb.png)

You'll be prompted to enter the Spoof Server IP
![image](https://user-images.githubusercontent.com/70275323/117013025-1e550300-ad0d-11eb-9ee9-ec15b5c1d8e2.png)

And as soon as a target website is encountered, it will redirect your host to your Spoofing server
![image](https://user-images.githubusercontent.com/70275323/117013532-97545a80-ad0d-11eb-8544-049117cbdf32.png)

As you can see, a page that should direct the host to ```google.com```'s Server, now directs to my spoofing server.

